/*
 * ngtcp2
 *
 * Copyright (c) 2017 ngtcp2 contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef CLIENT_H
#define CLIENT_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // HAVE_CONFIG_H

#include <vector>
#include <deque>
#include <map>
#include <string_view>
#include <memory>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <nghttp3/nghttp3.h>

#include <ev.h>

#include "client_base.h"
#include "tls_client_context.h"
#include "tls_client_session.h"
#include "network.h"
#include "shared.h"
#include "template.h"

using namespace ngtcp2;

struct Stream {
  Stream(const Request &req, int64_t stream_id);
  ~Stream();

  int open_file(const std::string_view &path);

  Request req;
  int64_t stream_id;
  int fd;
};

class Client;

struct Endpoint {
  Address addr;
  ev_io rev;
  Client *client;
  int fd;
};

class Client : public ClientBase {
public:
  Client(struct ev_loop *loop, uint32_t client_chosen_version,
         uint32_t original_version);
  ~Client();

  int init(int fd, const Address &local_addr, const Address &remote_addr,
           const char *addr, const char *port, TLSClientContext &tls_ctx);
  void disconnect();

  int on_read(const Endpoint &ep);
  int on_write();
  int write_streams();
  int feed_data(const Endpoint &ep, const sockaddr *sa, socklen_t salen,
                const ngtcp2_pkt_info *pi, uint8_t *data, size_t datalen);
  int handle_expiry();
  void update_timer();
  int handshake_completed();
  int handshake_confirmed();
  void recv_version_negotiation(const uint32_t *sv, size_t nsv);

  int send_packet(const Endpoint &ep, const ngtcp2_addr &remote_addr,
                  unsigned int ecn, const uint8_t *data, size_t datalen);
  int on_stream_close(int64_t stream_id, uint64_t app_error_code);
  int on_extend_max_streams();
  int handle_error();

  int select_preferred_address(Address &selected_addr,
                               const ngtcp2_preferred_addr *paddr);

  void set_remote_addr(const ngtcp2_addr &remote_addr);

  int setup_httpconn();
  int submit_http_request(const Stream *stream);
  int recv_stream_data(uint32_t flags, int64_t stream_id, const uint8_t *data,
                       size_t datalen);
  int acked_stream_data_offset(int64_t stream_id, uint64_t datalen);
  void http_consume(int64_t stream_id, size_t nconsumed);
  void http_write_data(int64_t stream_id, const uint8_t *data, size_t datalen);
  int on_stream_reset(int64_t stream_id);
  int on_stream_stop_sending(int64_t stream_id);
  int extend_max_stream_data(int64_t stream_id, uint64_t max_data);
  int stop_sending(int64_t stream_id, uint64_t app_error_code);
  int reset_stream(int64_t stream_id, uint64_t app_error_code);
  int http_stream_close(int64_t stream_id, uint64_t app_error_code);

  void on_send_blocked(const Endpoint &ep, const ngtcp2_addr &remote_addr,
                       unsigned int ecn, size_t datalen);
  void start_wev_endpoint(const Endpoint &ep);
  int send_blocked_packet();

private:
  std::vector<Endpoint> endpoints_;
  Address remote_addr_;
  ev_io wev_;
  ev_timer timer_;
  ev_signal sigintev_;
  struct ev_loop *loop_;
  std::map<int64_t, std::unique_ptr<Stream>> streams_;
  std::vector<uint32_t> offered_versions_;
  nghttp3_conn *httpconn_;
  // addr_ is the server host address.
  const char *addr_;
  // port_ is the server port.
  const char *port_;
  // nstreams_done_ is the number of streams opened.
  size_t nstreams_done_;
  uint32_t client_chosen_version_;
  uint32_t original_version_;
  // handshake_confirmed_ gets true after handshake has been
  // confirmed.
  bool handshake_confirmed_;

  struct {
    bool send_blocked;
    // blocked field is effective only when send_blocked is true.
    struct {
      const Endpoint *endpoint;
      Address remote_addr;
      unsigned int ecn;
      size_t datalen;
    } blocked;
    std::array<uint8_t, 64_k> data;
  } tx_;
};

#endif // CLIENT_H
