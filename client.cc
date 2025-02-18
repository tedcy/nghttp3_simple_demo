#include <cstdlib>
#include <cassert>
#include <cerrno>
#include <iostream>
#include <algorithm>
#include <memory>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/mman.h>

#include "client.h"
#include "network.h"
#include "debug.h"
#include "util.h"
#include "shared.h"

using namespace ngtcp2;
using namespace std::literals;

namespace {
auto randgen = util::make_mt19937();

constexpr size_t max_preferred_versionslen = 4;

} // namespace

Config config{};

namespace TC_Socket {
static int tc_safe_gethostbyname_r(vector<char> &buf, const string &sAddr,
                                   struct hostent *stHostent,
                                   struct hostent **pstHostent) {
    static constexpr int initSize = 2048;
    int iError = 0;
    if (buf.size() < initSize) {
        buf.resize(initSize);
    }

    while ((gethostbyname_r(sAddr.c_str(), stHostent, buf.data(), buf.size(),
                            pstHostent, &iError)) == ERANGE) {
        buf.resize(buf.size() * 2);
    }
    return iError;
}

static void parseAddr(const string &sAddr, struct in_addr &stSinAddr) {
    int iRet = inet_pton(AF_INET, sAddr.c_str(), &stSinAddr);
    if (iRet < 0) {
        throw string("[TC_Socket::parseAddr] inet_pton error", errno);
    } else if (iRet == 0) {
        struct hostent stHostent;
        struct hostent *pstHostent;
        vector<char> buf;
        int iError =
            tc_safe_gethostbyname_r(buf, sAddr, &stHostent, &pstHostent);

        if (pstHostent == NULL) {
            throw string(
                "[TC_Socket::parseAddr] tc_safe_gethostbyname_r error! :" +
                string(hstrerror(iError)));
        } else {
            stSinAddr = *(struct in_addr *)pstHostent->h_addr;
        }
    }
}

static int get_local_addr(sockaddr_in &local_addr, int fd) {
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr =
        htonl(INADDR_ANY);           // 绑定到 0.0.0.0（任意地址）
    local_addr.sin_port = htons(0);  // 绑定到随机系统端口

    if (bind(fd, reinterpret_cast<sockaddr *>(&local_addr),
             sizeof(local_addr)) == -1) {
        std::cerr << "bind: " << strerror(errno) << std::endl;
        return -1;
    }

    // 获取绑定后的地址信息
    socklen_t len = sizeof(local_addr);
    if (getsockname(fd, reinterpret_cast<sockaddr *>(&local_addr), &len) ==
        -1) {
        std::cerr << "getsockname: " << strerror(errno) << std::endl;
        return -1;
    }

    return 0;
}
}

Stream::Stream(shared_ptr<taf::TC_HttpRequest> &req, int64_t stream_id)
    : req(req), stream_id(stream_id) {}

namespace {
void writecb(Client *c) {
  c->on_write();
}

void readcb(Client *c) {
  if (c->on_read() != 0) {
    return;
  }

  c->on_write();
}

void timeoutcb(Client *c) {

  int rv = c->handle_expiry();
  if (rv != 0) {
    return;
  }

  c->on_write();
}
} // namespace

void Client::Timer::onTimeout() {
  timeoutcb(client_);
}

Client::Client(TC_Epoller &epoller,
               TC_TimeoutQueueSimple<shared_ptr<EventLoopTimer>> &data,
               uint32_t client_chosen_version, uint32_t original_version)
    : _epoller(epoller),
      _data(data),
      remote_addr_{},
      httpconn_(nullptr),
      addr_(nullptr),
      port_(nullptr),
      client_chosen_version_(client_chosen_version),
      original_version_(original_version),
      handshake_confirmed_(false),
      tx_{},
      timer_(make_shared<Timer>(this)) {
    tls_ctx_.init(nullptr, nullptr);
}

Client::~Client() {
  if (httpconn_) {
    nghttp3_conn_del(httpconn_);
    httpconn_ = nullptr;
  }
}

void Client::disconnect() {
  tx_.send_blocked = false;

  handle_error();

  _data.erase(timer_->getId());

  removeConnFunc_(getId());
}

namespace {
int recv_crypto_data(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data) {
  if (!config.quiet && !config.no_quic_dump) {
    debug::print_crypto_data(crypto_level, data, datalen);
  }

  return ngtcp2_crypto_recv_crypto_data_cb(conn, crypto_level, offset, data,
                                           datalen, user_data);
}

int recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data, void *stream_user_data) {
  if (!config.quiet && !config.no_quic_dump) {
    debug::print_stream_data(stream_id, data, datalen);
  }

  auto c = static_cast<Client *>(user_data);

  if (c->recv_stream_data(flags, stream_id, data, datalen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

int acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                             uint64_t offset, uint64_t datalen, void *user_data,
                             void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);
  if (c->acked_stream_data_offset(stream_id, datalen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int handshake_completed(ngtcp2_conn *conn, void *user_data) {
  auto c = static_cast<Client *>(user_data);

  if (!config.quiet) {
    debug::handshake_completed(conn, user_data);
  }

  if (c->handshake_completed() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

int Client::handshake_completed() {
  if (!config.quiet) {
    std::cerr << "Negotiated cipher suite is " << tls_session_.get_cipher_name()
              << std::endl;
    std::cerr << "Negotiated ALPN is " << tls_session_.get_selected_alpn()
              << std::endl;
  }

  return 0;
}

namespace {
int handshake_confirmed(ngtcp2_conn *conn, void *user_data) {
  auto c = static_cast<Client *>(user_data);

  if (!config.quiet) {
    debug::handshake_confirmed(conn, user_data);
  }

  if (c->handshake_confirmed() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

int Client::handshake_confirmed() {
  handshake_confirmed_ = true;

  return 0;
}

namespace {
int recv_version_negotiation(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                             const uint32_t *sv, size_t nsv, void *user_data) {
  auto c = static_cast<Client *>(user_data);

  c->recv_version_negotiation(sv, nsv);

  return 0;
}
} // namespace

void Client::recv_version_negotiation(const uint32_t *sv, size_t nsv) {
  offered_versions_.resize(nsv);
  std::copy_n(sv, nsv, std::begin(offered_versions_));
}

namespace {
int stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                 uint64_t app_error_code, void *user_data,
                 void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);

  if (!(flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)) {
    app_error_code = NGHTTP3_H3_NO_ERROR;
  }

  if (c->on_stream_close(stream_id, app_error_code) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

int stream_reset(ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
                 uint64_t app_error_code, void *user_data,
                 void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);

  if (c->on_stream_reset(stream_id) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

int stream_stop_sending(ngtcp2_conn *conn, int64_t stream_id,
                        uint64_t app_error_code, void *user_data,
                        void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);

  if (c->on_stream_stop_sending(stream_id) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

int extend_max_streams_bidi(ngtcp2_conn *conn, uint64_t max_streams,
                            void *user_data) {
  auto c = static_cast<Client *>(user_data);

  if (c->on_extend_max_streams() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

void rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) {
  auto dis = std::uniform_int_distribution<uint8_t>();
  std::generate(dest, dest + destlen, [&dis]() { return dis(randgen); });
}

int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                          size_t cidlen, void *user_data) {
  if (util::generate_secure_random(cid->data, cidlen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  cid->datalen = cidlen;
  if (ngtcp2_crypto_generate_stateless_reset_token(
          token, config.static_secret.data(), config.static_secret.size(),
          cid) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

int do_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
               const ngtcp2_crypto_cipher_ctx *hp_ctx, const uint8_t *sample) {
  if (ngtcp2_crypto_hp_mask(dest, hp, hp_ctx, sample) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

int update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
               ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
               ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
               const uint8_t *current_rx_secret,
               const uint8_t *current_tx_secret, size_t secretlen,
               void *user_data) {
  auto c = static_cast<Client *>(user_data);
  return 0;
//return NGTCP2_ERR_CALLBACK_FAILURE;
}

int path_validation(ngtcp2_conn *conn, uint32_t flags, const ngtcp2_path *path,
                    const ngtcp2_path *old_path,
                    ngtcp2_path_validation_result res, void *user_data) {
  if (!config.quiet) {
    debug::path_validation(path, res);
  }

  if (flags & NGTCP2_PATH_VALIDATION_FLAG_PREFERRED_ADDR) {
    auto c = static_cast<Client *>(user_data);

    c->set_remote_addr(path->remote);
  }

  return 0;
}
} // namespace

void Client::set_remote_addr(const ngtcp2_addr &remote_addr) {
  memcpy(&remote_addr_, remote_addr.addr, sizeof(sockaddr_in));
}

namespace {
int select_preferred_address(ngtcp2_conn *conn, ngtcp2_path *dest,
                             const ngtcp2_preferred_addr *paddr,
                             void *user_data) {
  auto c = static_cast<Client *>(user_data);
  return 0;
}

int extend_max_stream_data(ngtcp2_conn *conn, int64_t stream_id,
                           uint64_t max_data, void *user_data,
                           void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);
  if (c->extend_max_stream_data(stream_id, max_data) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

int Client::extend_max_stream_data(int64_t stream_id, uint64_t max_data) {
  if (auto rv = nghttp3_conn_unblock_stream(httpconn_, stream_id); rv != 0) {
    std::cerr << "nghttp3_conn_unblock_stream: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }
  return 0;
}

int recv_new_token(ngtcp2_conn *conn, const uint8_t *token, size_t tokenlen,
                   void *user_data) {
  return 0;
}

namespace {
int recv_rx_key(ngtcp2_conn *conn, ngtcp2_crypto_level level, void *user_data) {
  if (level != NGTCP2_CRYPTO_LEVEL_APPLICATION) {
    return 0;
  }

  auto c = static_cast<Client *>(user_data);
  if (c->setup_httpconn() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

int early_data_rejected(ngtcp2_conn *conn, void *user_data) {
  abort();
  auto c = static_cast<Client *>(user_data);

  return 0;
}
} // namespace

int Client::init(int fd, const sockaddr_in &local_addr,
                 const sockaddr_in &remote_addr, const char *addr,
                 const char *port) {
  endpoint_ = std::make_unique<Endpoint>();
  endpoint_->addr = local_addr;
  endpoint_->fd = fd;

  remote_addr_ = remote_addr;
  addr_ = addr;
  port_ = port;

  auto callbacks = ngtcp2_callbacks{
      ngtcp2_crypto_client_initial_cb,
      nullptr, // recv_client_initial
      ::recv_crypto_data,
      ::handshake_completed,
      ::recv_version_negotiation,
      ngtcp2_crypto_encrypt_cb,
      ngtcp2_crypto_decrypt_cb,
      ::do_hp_mask,
      ::recv_stream_data,
      ::acked_stream_data_offset,
      nullptr, // stream_open
      ::stream_close,
      nullptr, // recv_stateless_reset
      ngtcp2_crypto_recv_retry_cb,
      ::extend_max_streams_bidi,
      nullptr, // extend_max_streams_uni
      rand,
      ::get_new_connection_id,
      nullptr, // remove_connection_id
      ::update_key,
      ::path_validation,
      ::select_preferred_address,
      ::stream_reset,
      nullptr, // extend_max_remote_streams_bidi,
      nullptr, // extend_max_remote_streams_uni,
      ::extend_max_stream_data,
      nullptr, // dcid_status
      ::handshake_confirmed,
      ::recv_new_token,
      ngtcp2_crypto_delete_crypto_aead_ctx_cb,
      ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
      nullptr, // recv_datagram
      nullptr, // ack_datagram
      nullptr, // lost_datagram
      ngtcp2_crypto_get_path_challenge_data_cb,
      ::stream_stop_sending,
      ngtcp2_crypto_version_negotiation_cb,
      ::recv_rx_key,
      nullptr, // recv_tx_key
      ::early_data_rejected,
  };

  ngtcp2_cid scid, dcid;
  scid.datalen = 17;
  if (util::generate_secure_random(scid.data, scid.datalen) != 0) {
      std::cerr << "Could not generate source connection ID" << std::endl;
      return -1;
  }
  dcid.datalen = 18;
  if (util::generate_secure_random(dcid.data, dcid.datalen) != 0) {
      std::cerr << "Could not generate destination connection ID" << std::endl;
      return -1;
  }

  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);
  settings.log_printf = config.quiet ? nullptr : debug::log_printf;

  settings.cc_algo = config.cc_algo;
  settings.initial_ts = util::timestamp();
  settings.initial_rtt = config.initial_rtt;
  settings.max_window = config.max_window;
  settings.max_stream_window = config.max_stream_window;
  if (config.max_udp_payload_size) {
    settings.max_tx_udp_payload_size = config.max_udp_payload_size;
    settings.no_tx_udp_payload_size_shaping = 1;
  }
  settings.handshake_timeout = config.handshake_timeout;
  settings.no_pmtud = config.no_pmtud;
  settings.ack_thresh = config.ack_thresh;

  settings.original_version = original_version_;

  ngtcp2_transport_params params;
  ngtcp2_transport_params_default(&params);
  params.initial_max_stream_data_bidi_local = config.max_stream_data_bidi_local;
  params.initial_max_stream_data_bidi_remote =
      config.max_stream_data_bidi_remote;
  params.initial_max_stream_data_uni = config.max_stream_data_uni;
  params.initial_max_data = config.max_data;
  params.initial_max_streams_bidi = config.max_streams_bidi;
  params.initial_max_streams_uni = config.max_streams_uni;
  params.max_idle_timeout = config.timeout;
  params.active_connection_id_limit = 7;

  auto path = ngtcp2_path{
      {
          reinterpret_cast<sockaddr *>(&endpoint_->addr),
          sizeof(sockaddr_in),
      },
      {
          reinterpret_cast<sockaddr *>(&remote_addr_),
          sizeof(sockaddr_in),
      },
      endpoint_.get(),
  };
  auto rv = ngtcp2_conn_client_new(&conn_, &dcid, &scid, &path,
                                   client_chosen_version_, &callbacks,
                                   &settings, &params, nullptr, this);

  if (rv != 0) {
    std::cerr << "ngtcp2_conn_client_new: " << ngtcp2_strerror(rv)
                << std::endl;
    return -1;
  }

  if (tls_session_.init(tls_ctx_, addr_, this, client_chosen_version_,
                        AppProtocol::H3) != 0) {
    return -1;
  }

  ngtcp2_conn_set_tls_native_handle(conn_, tls_session_.get_native_handle());

  return 0;
}

int Client::feed_data(const Endpoint &ep, const sockaddr *sa, socklen_t salen,
                      const ngtcp2_pkt_info *pi, uint8_t *data,
                      size_t datalen) {
  auto path = ngtcp2_path{
      {
          const_cast<sockaddr *>(
                reinterpret_cast<const sockaddr *>(&ep.addr)),
          sizeof(sockaddr_in),
      },
      {
          const_cast<sockaddr *>(sa),
          salen,
      },
      const_cast<Endpoint *>(&ep),
  };
  if (auto rv = ngtcp2_conn_read_pkt(conn_, &path, pi, data, datalen,
                                     util::timestamp());
      rv != 0) {
    std::cerr << "ngtcp2_conn_read_pkt: " << ngtcp2_strerror(rv) << std::endl;
    if (!last_error_.error_code) {
      if (rv == NGTCP2_ERR_CRYPTO) {
        ngtcp2_ccerr_set_tls_alert(
            &last_error_, ngtcp2_conn_get_tls_alert(conn_), nullptr, 0);
      } else {
        ngtcp2_ccerr_set_liberr(&last_error_, rv, nullptr, 0);
      }
    }
    disconnect();
    return -1;
  }
  return 0;
}

int Client::on_read() {
  const Endpoint &ep = *endpoint_;
  std::array<uint8_t, 64_k> buf;
  sockaddr_storage ss;
  sockaddr* sa = reinterpret_cast<sockaddr*>(&ss);
  size_t pktcnt = 0;
  ngtcp2_pkt_info pi;

  iovec msg_iov;
  msg_iov.iov_base = buf.data();
  msg_iov.iov_len = buf.size();

  msghdr msg{};
  msg.msg_name = &ss;
  msg.msg_iov = &msg_iov;
  msg.msg_iovlen = 1;

  uint8_t msg_ctrl[CMSG_SPACE(sizeof(uint8_t))];
  msg.msg_control = msg_ctrl;

  for (;;) {
    msg.msg_namelen = sizeof(ss);
    msg.msg_controllen = sizeof(msg_ctrl);

    auto nread = recvmsg(ep.fd, &msg, 0);

    if (nread == -1) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        std::cerr << "recvmsg: " << strerror(errno) << std::endl;
      }
      break;
    }

    pi.ecn = msghdr_get_ecn(&msg, ss.ss_family);

    if (!config.quiet) {
      std::cerr << "Received packet: local="
                << util::straddr((const sockaddr *)&ep.addr, sizeof(sockaddr_in))
                << " remote=" << util::straddr(sa, msg.msg_namelen)
                << " ecn=0x" << std::hex << pi.ecn << std::dec << " " << nread
                << " bytes" << std::endl;
    }

    if (feed_data(ep, sa, msg.msg_namelen, &pi, buf.data(), nread) != 0) {
      return -1;
    }

    if (++pktcnt >= 10) {
      break;
    }
  }

  update_timer();

  return 0;
}

int Client::handle_expiry() {
  auto now = util::timestamp();
  if (auto rv = ngtcp2_conn_handle_expiry(conn_, now); rv != 0) {
    std::cerr << "ngtcp2_conn_handle_expiry: " << ngtcp2_strerror(rv)
              << std::endl;
    ngtcp2_ccerr_set_liberr(&last_error_, rv, nullptr, 0);
    disconnect();
    return -1;
  }

  return 0;
}

int Client::on_write() {
  if (tx_.send_blocked) {
    if (auto rv = send_blocked_packet(); rv != 0) {
      return rv;
    }

    if (tx_.send_blocked) {
      return 0;
    }

    setEvent(getFd(), getId(), EPOLLIN);
  }

  if (auto rv = write_streams(); rv != 0) {
    return rv;
  }

  update_timer();
  return 0;
}

int Client::write_streams() {
  std::array<nghttp3_vec, 16> vec;
  ngtcp2_path_storage ps;
  size_t pktcnt = 0;
  auto max_udp_payload_size = ngtcp2_conn_get_max_tx_udp_payload_size(conn_);
  auto max_pktcnt = ngtcp2_conn_get_send_quantum(conn_) / max_udp_payload_size;
  auto ts = util::timestamp();

  ngtcp2_path_storage_zero(&ps);

  for (;;) {
    int64_t stream_id = -1;
    int fin = 0;
    nghttp3_ssize sveccnt = 0;

    if (httpconn_ && ngtcp2_conn_get_max_data_left(conn_)) {
      sveccnt = nghttp3_conn_writev_stream(httpconn_, &stream_id, &fin,
                                           vec.data(), vec.size());
      if (sveccnt < 0) {
        std::cerr << "nghttp3_conn_writev_stream: " << nghttp3_strerror(sveccnt)
                  << std::endl;
        ngtcp2_ccerr_set_application_error(
            &last_error_, nghttp3_err_infer_quic_app_error_code(sveccnt),
            nullptr, 0);
        disconnect();
        return -1;
      }
    }

    ngtcp2_ssize ndatalen;
    auto v = vec.data();
    auto vcnt = static_cast<size_t>(sveccnt);

    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (fin) {
      flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }

    ngtcp2_pkt_info pi;

    auto nwrite = ngtcp2_conn_writev_stream(
        conn_, &ps.path, &pi, tx_.data.data(), max_udp_payload_size, &ndatalen,
        flags, stream_id, reinterpret_cast<const ngtcp2_vec *>(v), vcnt, ts);
    if (nwrite < 0) {
      switch (nwrite) {
      case NGTCP2_ERR_STREAM_DATA_BLOCKED:
        assert(ndatalen == -1);
        nghttp3_conn_block_stream(httpconn_, stream_id);
        continue;
      case NGTCP2_ERR_STREAM_SHUT_WR:
        assert(ndatalen == -1);
        nghttp3_conn_shutdown_stream_write(httpconn_, stream_id);
        continue;
      case NGTCP2_ERR_WRITE_MORE:
        assert(ndatalen >= 0);
        if (auto rv =
                nghttp3_conn_add_write_offset(httpconn_, stream_id, ndatalen);
            rv != 0) {
          std::cerr << "nghttp3_conn_add_write_offset: " << nghttp3_strerror(rv)
                    << std::endl;
          ngtcp2_ccerr_set_application_error(
              &last_error_, nghttp3_err_infer_quic_app_error_code(rv), nullptr,
              0);
          disconnect();
          return -1;
        }
        continue;
      }

      assert(ndatalen == -1);

      std::cerr << "ngtcp2_conn_write_stream: " << ngtcp2_strerror(nwrite)
                << std::endl;
      ngtcp2_ccerr_set_liberr(&last_error_, nwrite, nullptr, 0);
      disconnect();
      return -1;
    } else if (ndatalen >= 0) {
      if (auto rv =
              nghttp3_conn_add_write_offset(httpconn_, stream_id, ndatalen);
          rv != 0) {
        std::cerr << "nghttp3_conn_add_write_offset: " << nghttp3_strerror(rv)
                  << std::endl;
        ngtcp2_ccerr_set_application_error(
            &last_error_, nghttp3_err_infer_quic_app_error_code(rv), nullptr,
            0);
        disconnect();
        return -1;
      }
    }

    if (nwrite == 0) {
      // We are congestion limited.
      ngtcp2_conn_update_pkt_tx_time(conn_, ts);
      return 0;
    }

    auto &ep = *static_cast<Endpoint *>(ps.path.user_data);

    if (auto rv =
            send_packet(ep, ps.path.remote, pi.ecn, tx_.data.data(), nwrite);
        rv != NETWORK_ERR_OK) {
      if (rv != NETWORK_ERR_SEND_BLOCKED) {
        ngtcp2_ccerr_set_liberr(&last_error_, NGTCP2_ERR_INTERNAL, nullptr, 0);
        disconnect();

        return rv;
      }

      ngtcp2_conn_update_pkt_tx_time(conn_, ts);
      on_send_blocked(ep, ps.path.remote, pi.ecn, nwrite);

      return 0;
    }

    if (++pktcnt == max_pktcnt) {
      ngtcp2_conn_update_pkt_tx_time(conn_, ts);
      return 0;
    }
  }
}

void Client::update_timer() {
  auto expiry = ngtcp2_conn_get_expiry(conn_);
  auto now = util::timestamp();

  if (expiry <= now) {
    if (!config.quiet) {
      auto t = static_cast<double>(now - expiry) / NGTCP2_SECONDS;
      std::cerr << "Timer has already expired: " << std::fixed << t << "s"
                << std::defaultfloat << std::endl;
    }

    timeoutcb(this);

    return;
  }

  auto t = static_cast<double>(expiry - now) / NGTCP2_MILLISECONDS;
//   if (!config.quiet) {
//     std::cerr << "Set timer=" << std::fixed << t << "ms" << std::defaultfloat
//               << std::endl;
//   }
  t = max(t, 1.0);
  _data.push(timer_, timer_->getId(), t);
}

namespace {
int udp_sock(int family) {
  auto fd = util::create_nonblock_socket(family, SOCK_DGRAM, IPPROTO_UDP);
  if (fd == -1) {
    return -1;
  }

  fd_set_recv_ecn(fd, family);
  fd_set_ip_mtu_discover(fd, family);
  fd_set_ip_dontfrag(fd, family);

  return fd;
}

int get_remote_addr(sockaddr_in &remote_addr, const char *addr, const char *port) {
    // Step 1: 使用 parseAddr 解析 IP 地址
    struct in_addr sin_addr;
    try {
        TC_Socket::parseAddr(addr,
                             sin_addr);  // 替代 getaddrinfo 的 IP 解析部分
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        return -1;
    }

    // Step 2: 构造 sockaddr_in
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr = sin_addr;
    remote_addr.sin_port = htons(std::stoi(port));  // 将端口转为网络字节序

    return 0;
}
} // namespace

int Client::send_packet(const Endpoint &ep, const ngtcp2_addr &remote_addr,
                        unsigned int ecn, const uint8_t *data, size_t datalen) {
  iovec msg_iov;
  msg_iov.iov_base = const_cast<uint8_t *>(data);
  msg_iov.iov_len = datalen;

  msghdr msg{};
  msg.msg_name = const_cast<sockaddr *>(remote_addr.addr);
  msg.msg_namelen = remote_addr.addrlen;
  msg.msg_iov = &msg_iov;
  msg.msg_iovlen = 1;

  fd_set_ecn(ep.fd, remote_addr.addr->sa_family, ecn);

  ssize_t nwrite = 0;

  do {
    nwrite = sendmsg(ep.fd, &msg, 0);
  } while (nwrite == -1 && errno == EINTR);

  if (nwrite == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return NETWORK_ERR_SEND_BLOCKED;
    }
    std::cerr << "sendmsg: " << strerror(errno) << std::endl;
    if (errno == EMSGSIZE) {
      return 0;
    }
    return NETWORK_ERR_FATAL;
  }

  assert(static_cast<size_t>(nwrite) == datalen);

  if (!config.quiet) {
      std::cerr << "Sent packet: local="
                << util::straddr((const sockaddr *)&ep.addr,
                                 sizeof(sockaddr_in))
                << " remote="
                << util::straddr(remote_addr.addr, remote_addr.addrlen)
                << " ecn=0x" << std::hex << ecn << std::dec << " " << nwrite
                << " bytes" << std::endl;
  }

  return NETWORK_ERR_OK;
}

void Client::on_send_blocked(const Endpoint &ep, const ngtcp2_addr &remote_addr,
                             unsigned int ecn, size_t datalen) {
  assert(!tx_.send_blocked);

  tx_.send_blocked = true;

  memcpy(&tx_.blocked.remote_addr, remote_addr.addr, remote_addr.addrlen);
  tx_.blocked.ecn = ecn;
  tx_.blocked.datalen = datalen;
  tx_.blocked.endpoint = &ep;

  start_wev_endpoint(ep);
}

void Client::start_wev_endpoint(const Endpoint &ep) {
  setEvent(getFd(), getId(), EPOLLIN | EPOLLOUT);
}

int Client::send_blocked_packet() {
  assert(tx_.send_blocked);

  ngtcp2_addr remote_addr{
      .addr = reinterpret_cast<sockaddr *>(&tx_.blocked.remote_addr),
      .addrlen = sizeof(sockaddr_in),
  };

  auto rv = send_packet(*tx_.blocked.endpoint, remote_addr, tx_.blocked.ecn,
                        tx_.data.data(), tx_.blocked.datalen);
  if (rv != 0) {
    if (rv == NETWORK_ERR_SEND_BLOCKED) {
      assert(endpoint_->fd == tx_.blocked.endpoint->fd);

      return 0;
    }

    ngtcp2_ccerr_set_liberr(&last_error_, NGTCP2_ERR_INTERNAL, nullptr, 0);
    disconnect();

    return rv;
  }

  tx_.send_blocked = false;

  return 0;
}

int Client::handle_error() {
  if (!conn_ || ngtcp2_conn_is_in_closing_period(conn_) ||
      ngtcp2_conn_is_in_draining_period(conn_)) {
    return 0;
  }

  std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> buf;

  ngtcp2_path_storage ps;

  ngtcp2_path_storage_zero(&ps);

  ngtcp2_pkt_info pi;

  auto nwrite = ngtcp2_conn_write_connection_close(
      conn_, &ps.path, &pi, buf.data(), buf.size(), &last_error_,
      util::timestamp());
  if (nwrite < 0) {
    std::cerr << "ngtcp2_conn_write_connection_close: "
              << ngtcp2_strerror(nwrite) << std::endl;
    return -1;
  }

  if (nwrite == 0) {
    return 0;
  }

  return send_packet(*static_cast<Endpoint *>(ps.path.user_data),
                     ps.path.remote, pi.ecn, buf.data(), nwrite);
}

int Client::on_stream_close(int64_t stream_id, uint64_t app_error_code) {
  if (httpconn_) {
    if (app_error_code == 0) {
      app_error_code = NGHTTP3_H3_NO_ERROR;
    }
    auto rv = nghttp3_conn_close_stream(httpconn_, stream_id, app_error_code);
    switch (rv) {
    case 0:
      break;
    case NGHTTP3_ERR_STREAM_NOT_FOUND:
      // We have to handle the case when stream opened but no data is
      // transferred.  In this case, nghttp3_conn_close_stream might
      // return error.
      if (!ngtcp2_is_bidi_stream(stream_id)) {
        assert(!ngtcp2_conn_is_local_stream(conn_, stream_id));
        ngtcp2_conn_extend_max_streams_uni(conn_, 1);
      }
      break;
    default:
      std::cerr << "nghttp3_conn_close_stream: " << nghttp3_strerror(rv)
                << std::endl;
      ngtcp2_ccerr_set_application_error(
          &last_error_, nghttp3_err_infer_quic_app_error_code(rv), nullptr, 0);
      return -1;
    }
  }

  return 0;
}

int Client::on_stream_reset(int64_t stream_id) {
  if (httpconn_) {
    if (auto rv = nghttp3_conn_shutdown_stream_read(httpconn_, stream_id);
        rv != 0) {
      std::cerr << "nghttp3_conn_shutdown_stream_read: " << nghttp3_strerror(rv)
                << std::endl;
      return -1;
    }
  }
  return 0;
}

int Client::on_stream_stop_sending(int64_t stream_id) {
  if (!httpconn_) {
    return 0;
  }

  if (auto rv = nghttp3_conn_shutdown_stream_read(httpconn_, stream_id);
      rv != 0) {
    std::cerr << "nghttp3_conn_shutdown_stream_read: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  return 0;
}

int Client::on_extend_max_streams() {
  int64_t stream_id;

  for (auto iter = requests_.begin(); iter != requests_.end();) {
    auto &req = *iter;
    if (auto rv = ngtcp2_conn_open_bidi_stream(conn_, &stream_id, nullptr);
        rv != 0) {
      assert(NGTCP2_ERR_STREAM_ID_BLOCKED == rv);
      break;
    }

    auto stream = std::make_unique<Stream>(req, stream_id);

    if (submit_http_request(stream.get()) != 0) {
      break;
    }

    streams_.emplace(stream_id, std::move(stream));
    iter = requests_.erase(iter);
  }
  return 0;
}

namespace {
nghttp3_ssize read_data(nghttp3_conn *conn, int64_t stream_id, nghttp3_vec *vec,
                        size_t veccnt, uint32_t *pflags, void *user_data,
                        void *stream_user_data) {
  //TODO 记得改tc_http的getContent实现，必须返回非临时变量
  const Stream *stream = static_cast<Stream *>(stream_user_data);
  vec[0].base = (uint8_t *)stream->req->getContent().c_str();
  vec[0].len = stream->req->getContentLength();
  *pflags |= NGHTTP3_DATA_FLAG_EOF;

  return 1;
}
} // namespace

int Client::submit_http_request(Stream *stream) {
  std::string content_length_str;

  const auto &req = *stream->req;

  stream->method = req.requestType2str(req.getRequestType());
  stream->authority = req.getURL().getDomain();
  stream->path = req.getRequest();

  std::vector<nghttp3_nv> nva{
      util::make_nv_nn(":method", stream->method),
      util::make_nv_nn(":authority", stream->authority),
      util::make_nv_nn(":scheme", "https"),
      util::make_nv_nn(":path", stream->path),
  };

  for (auto &[key, value] : req.getHeaders()) {
    auto lowerKey = key;
    std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    stream->keys.push_back(lowerKey);
    nva.push_back(util::make_nv_nn(stream->keys.back(), value));
  }
  
  if (!config.quiet) {
    debug::print_http_request_headers(stream->stream_id, nva.data(), nva.size());
  }

  nghttp3_data_reader dr{};
  dr.read_data = read_data;

  if (auto rv = nghttp3_conn_submit_request(
          httpconn_, stream->stream_id, nva.data(), nva.size(),
          req.getContent().empty() ? nullptr : &dr, (void*)stream);
      rv != 0) {
    std::cerr << "nghttp3_conn_submit_request: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  return 0;
}

int Client::recv_stream_data(uint32_t flags, int64_t stream_id,
                             const uint8_t *data, size_t datalen) {
  auto nconsumed = nghttp3_conn_read_stream(
      httpconn_, stream_id, data, datalen, flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  if (nconsumed < 0) {
    std::cerr << "nghttp3_conn_read_stream: " << nghttp3_strerror(nconsumed)
              << std::endl;
    ngtcp2_ccerr_set_application_error(
        &last_error_, nghttp3_err_infer_quic_app_error_code(nconsumed), nullptr,
        0);
    return -1;
  }

  ngtcp2_conn_extend_max_stream_offset(conn_, stream_id, nconsumed);
  ngtcp2_conn_extend_max_offset(conn_, nconsumed);

  return 0;
}

int Client::acked_stream_data_offset(int64_t stream_id, uint64_t datalen) {
  if (auto rv = nghttp3_conn_add_ack_offset(httpconn_, stream_id, datalen);
      rv != 0) {
    std::cerr << "nghttp3_conn_add_ack_offset: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  return 0;
}

namespace {
int http_recv_data(nghttp3_conn *conn, int64_t stream_id, const uint8_t *data,
                   size_t datalen, void *user_data, void *stream_user_data) {
  if (!config.quiet && !config.no_http_dump) {
    debug::print_http_data(stream_id, data, datalen);
  }
  auto c = static_cast<Client *>(user_data);
  c->http_consume(stream_id, datalen);
  c->http_write_data(stream_id, data, datalen);
  return 0;
}

int http_deferred_consume(nghttp3_conn *conn, int64_t stream_id,
                          size_t nconsumed, void *user_data,
                          void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);
  c->http_consume(stream_id, nconsumed);
  return 0;
}
} // namespace

void Client::http_consume(int64_t stream_id, size_t nconsumed) {
  ngtcp2_conn_extend_max_stream_offset(conn_, stream_id, nconsumed);
  ngtcp2_conn_extend_max_offset(conn_, nconsumed);
}

void Client::http_write_data(int64_t stream_id, const uint8_t *data,
                             size_t datalen) {
  auto it = streams_.find(stream_id);
  if (it == std::end(streams_)) {
    return;
  }

  auto &stream = (*it).second;

  stream->data += std::string((char *)data, datalen);
}

namespace {
int http_begin_headers(nghttp3_conn *conn, int64_t stream_id, void *user_data,
                       void *stream_user_data) {
  if (!config.quiet) {
    debug::print_http_begin_response_headers(stream_id);
  }
  return 0;
}

int http_recv_header(nghttp3_conn *conn, int64_t stream_id, int32_t token,
                     nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                     void *user_data, void *stream_user_data) {
  if (!config.quiet) {
    debug::print_http_header(stream_id, name, value, flags);
  }
  const Stream *stream = static_cast<Stream *>(stream_user_data);
  nghttp3_vec nameBuf = nghttp3_rcbuf_get_buf(name);
  nghttp3_vec valueBuf = nghttp3_rcbuf_get_buf(value);
  auto &rsp = const_cast<Stream *>(stream)->rsp;
  if (nameBuf.len == 0) {
      return 0;
  }
  if (nameBuf.base[0] == ':') {
      if (memcmp(nameBuf.base, ":status", nameBuf.len) == 0) {
          int status =
              atoi(std::string((char *)valueBuf.base, valueBuf.len).c_str());
          rsp.setStatus(status);
          return 0;
      }
      return 0;
  }
  rsp.setHeader(std::string((char *)nameBuf.base, nameBuf.len),
                std::string((char *)valueBuf.base, valueBuf.len));
  return 0;
}
} // namespace

namespace {
int http_end_headers(nghttp3_conn *conn, int64_t stream_id, int fin,
                     void *user_data, void *stream_user_data) {
  if (!config.quiet) {
    debug::print_http_end_headers(stream_id);
  }
  return 0;
}

int http_begin_trailers(nghttp3_conn *conn, int64_t stream_id, void *user_data,
                        void *stream_user_data) {
  if (!config.quiet) {
    debug::print_http_begin_trailers(stream_id);
  }
  return 0;
}

int http_recv_trailer(nghttp3_conn *conn, int64_t stream_id, int32_t token,
                      nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                      void *user_data, void *stream_user_data) {
  if (!config.quiet) {
    debug::print_http_header(stream_id, name, value, flags);
  }
  return 0;
}

int http_end_trailers(nghttp3_conn *conn, int64_t stream_id, int fin,
                      void *user_data, void *stream_user_data) {
  if (!config.quiet) {
    debug::print_http_end_trailers(stream_id);
  }
  return 0;
}

int http_stop_sending(nghttp3_conn *conn, int64_t stream_id,
                      uint64_t app_error_code, void *user_data,
                      void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);
  if (c->stop_sending(stream_id, app_error_code) != 0) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

int Client::stop_sending(int64_t stream_id, uint64_t app_error_code) {
  if (auto rv =
          ngtcp2_conn_shutdown_stream_read(conn_, stream_id, app_error_code);
      rv != 0) {
    std::cerr << "ngtcp2_conn_shutdown_stream_read: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }
  return 0;
}

namespace {
int http_reset_stream(nghttp3_conn *conn, int64_t stream_id,
                      uint64_t app_error_code, void *user_data,
                      void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);
  if (c->reset_stream(stream_id, app_error_code) != 0) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

int Client::reset_stream(int64_t stream_id, uint64_t app_error_code) {
  if (auto rv =
          ngtcp2_conn_shutdown_stream_write(conn_, stream_id, app_error_code);
      rv != 0) {
    std::cerr << "ngtcp2_conn_shutdown_stream_write: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }
  return 0;
}

namespace {
int http_end_stream(nghttp3_conn *conn, int64_t stream_id, void *user_data,
                    void *stream_user_data) {
    auto *c = static_cast<Client *>(user_data);
    if (c->http_end_stream(stream_id) != 0) {
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }

    return 0; // 正常处理
}
}
int Client::http_end_stream(int64_t stream_id) {
    auto it = streams_.find(stream_id); 
    if (it != streams_.end()) {
        auto &stream = (*it).second;
        stream->rsp.setContent(stream->data);
        if (!config.quiet) {
            std::cout << "stream " << stream_id << " ended" << std::endl;
        }
    }
    return 0;
}

namespace {
int http_stream_close(nghttp3_conn *conn, int64_t stream_id,
                      uint64_t app_error_code, void *conn_user_data,
                      void *stream_user_data) {
  auto c = static_cast<Client *>(conn_user_data);
  if (c->http_stream_close(stream_id, app_error_code) != 0) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

int Client::http_stream_close(int64_t stream_id, uint64_t app_error_code) {
  if (ngtcp2_is_bidi_stream(stream_id)) {
    //双向流判断流id是不是对的上
    assert(ngtcp2_conn_is_local_stream(conn_, stream_id));

  } else {
    //单向流判断是否远程控制，是的话就扩展一个配额（本地流不应该触发这个close，所以要assert掉）
    assert(!ngtcp2_conn_is_local_stream(conn_, stream_id));
    ngtcp2_conn_extend_max_streams_uni(conn_, 1);
  }

  if (auto it = streams_.find(stream_id); it != std::end(streams_)) {
    if (!config.quiet) {
      std::cerr << "HTTP stream " << stream_id << " closed with error code "
                << app_error_code << std::endl;
    }
    streams_.erase(it);
  }

  return 0;
}

int Client::setup_httpconn() {
  if (httpconn_) {
    return 0;
  }

  if (ngtcp2_conn_get_streams_uni_left(conn_) < 3) {
    std::cerr << "peer does not allow at least 3 unidirectional streams."
              << std::endl;
    return -1;
  }

  nghttp3_callbacks callbacks{
      nullptr, // acked_stream_data
      ::http_stream_close,
      ::http_recv_data,
      ::http_deferred_consume,
      ::http_begin_headers,
      ::http_recv_header,
      ::http_end_headers,
      ::http_begin_trailers,
      ::http_recv_trailer,
      ::http_end_trailers,
      ::http_stop_sending,
      ::http_end_stream,
      ::http_reset_stream,
      nullptr, // shutdown
  };
  nghttp3_settings settings;
  nghttp3_settings_default(&settings);
  settings.qpack_max_dtable_capacity = 4_k;
  settings.qpack_blocked_streams = 100;

  auto mem = nghttp3_mem_default();

  if (auto rv =
          nghttp3_conn_client_new(&httpconn_, &callbacks, &settings, mem, this);
      rv != 0) {
    std::cerr << "nghttp3_conn_client_new: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  int64_t ctrl_stream_id;

  if (auto rv = ngtcp2_conn_open_uni_stream(conn_, &ctrl_stream_id, nullptr);
      rv != 0) {
    std::cerr << "ngtcp2_conn_open_uni_stream: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }

  if (auto rv = nghttp3_conn_bind_control_stream(httpconn_, ctrl_stream_id);
      rv != 0) {
    std::cerr << "nghttp3_conn_bind_control_stream: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  if (!config.quiet) {
    fprintf(stderr, "http: control stream=%" PRIx64 "\n", ctrl_stream_id);
  }

  int64_t qpack_enc_stream_id, qpack_dec_stream_id;

  if (auto rv =
          ngtcp2_conn_open_uni_stream(conn_, &qpack_enc_stream_id, nullptr);
      rv != 0) {
    std::cerr << "ngtcp2_conn_open_uni_stream: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }

  if (auto rv =
          ngtcp2_conn_open_uni_stream(conn_, &qpack_dec_stream_id, nullptr);
      rv != 0) {
    std::cerr << "ngtcp2_conn_open_uni_stream: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }

  if (auto rv = nghttp3_conn_bind_qpack_streams(httpconn_, qpack_enc_stream_id,
                                                qpack_dec_stream_id);
      rv != 0) {
    std::cerr << "nghttp3_conn_bind_qpack_streams: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  if (!config.quiet) {
    fprintf(stderr,
            "http: QPACK streams encoder=%" PRIx64 " decoder=%" PRIx64 "\n",
            qpack_enc_stream_id, qpack_dec_stream_id);
  }

  return 0;
}

void Client::process(int events) {
    if (events & (EPOLLERR | EPOLLHUP)) {
    //   onException(string("process events:") +
    //     ((events & EPOLLERR) ? "EPOLLERR" : " ") +
    //     ((events & EPOLLHUP) ? "EPOLLHUP" : ""));
      return;
    }
    if (events & EPOLLIN) readcb(this);
    if (events & EPOLLOUT) writecb(this);
}

EXTERN void *createHttp3Conn(
    TC_Epoller &epoller,
    TC_TimeoutQueueSimple<shared_ptr<EventLoopTimer>> &data,
    const string &targetAddr, uint32_t targetPort) {
    Client *c = nullptr;
    sockaddr_in remote_addr, local_addr;

    if (get_remote_addr(remote_addr, targetAddr.c_str(),
                        to_string(targetPort).c_str()) != 0) {
        return c;
    }

    int fd = udp_sock(AF_INET);
    if (fd == -1) {
        std::cerr << "Could not create socket" << std::endl;
        return c;
    }

    if (TC_Socket::get_local_addr(local_addr, fd) != 0) {
        std::cerr << "Could not get local address" << std::endl;
        close(fd);
        return c;
    }

    c = new Client(epoller, data, NGTCP2_PROTO_VER_V1, NGTCP2_PROTO_VER_V1);
    if (c->init(fd, local_addr, remote_addr, targetAddr.c_str(),
                to_string(targetPort).c_str()) != 0) {
        c = nullptr;
        return c;
    }
    if (auto rv = c->on_write(); rv != 0) {
        c = nullptr;
        return c;
    }
    c->setEvent(c->getFd(), c->getId(), EPOLLIN | EPOLLOUT);

    return c;
}

EXTERN void destroyHttp3Conn(void *conn) {
    if (conn) {
        delete static_cast<Client *>(conn);
    }
}

EXTERN void initConfig() {
  if (util::generate_secret(config.static_secret.data(),
                            config.static_secret.size()) != 0) {
    std::cerr << "Unable to generate static secret" << std::endl;
    abort();
  }
}

EXTERN uint64_t getId(void *conn) {
    return static_cast<Client *>(conn)->getId();
}
EXTERN void check_pushed_requests(void *conn) {
    static_cast<Client *>(conn)->check_pushed_requests();
}
EXTERN void push_request(void *conn, shared_ptr<taf::TC_HttpRequest> &req) {
    static_cast<Client *>(conn)->push_request(req);
}
EXTERN void process(void *conn, int events) {
    static_cast<Client *>(conn)->process(events);
}
EXTERN void setRemoveConnFunc(void *conn, const function<void(uint64_t)> &func) {
    static_cast<Client *>(conn)->setRemoveConnFunc(func);
}