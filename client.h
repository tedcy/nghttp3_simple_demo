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

#include "client_base.h"
#include "tls_client_context.h"
#include "tls_client_session.h"
#include "network.h"
#include "shared.h"
#include "template.h"

#include <iostream>
#include <sstream>
#include <atomic>
#include <list>
#include <set>
#include "tc_http/tc_http.h"
#include "tc_eventloop_timer.h"

using namespace ngtcp2;

struct Stream {
  Stream(shared_ptr<taf::TC_HttpRequest> &req, int64_t stream_id);
  ~Stream() {
    cout << "stream_id: " << stream_id << " data: " << data
         << " status: " << rsp.getStatus() << " content: " << rsp.getContent()
         << endl;
    for (auto &kv : rsp.getHeaders()) {
        cout << "stream_id: " << stream_id << " " << kv.first << ": "
             << kv.second << endl;
    }
  }

  int64_t stream_id;
  //for rsp
  taf::TC_HttpResponse rsp;
  string data;

  //for req
  shared_ptr<taf::TC_HttpRequest> req;
  string method;
  string authority;
  string path;
  string content_length;
  list<string> keys;
};

class Client;

struct Endpoint {
  sockaddr_in addr;
  int fd;
};

class EventLoop;
class Client : public ClientBase {
public:
  Client(uint32_t client_chosen_version,
         uint32_t original_version);
  ~Client();

  int init(int fd, const sockaddr_in &local_addr,
           const sockaddr_in &remote_addr, const char *addr, const char *port);
  void disconnect();

  int on_read();
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

  void set_remote_addr(const ngtcp2_addr &remote_addr);

  int setup_httpconn();
  int submit_http_request(Stream *stream);
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
  int http_end_stream(int64_t stream_id);
  int http_stream_close(int64_t stream_id, uint64_t app_error_code);

  void on_send_blocked(const Endpoint &ep, const ngtcp2_addr &remote_addr,
                       unsigned int ecn, size_t datalen);
  void start_wev_endpoint(const Endpoint &ep);
  int send_blocked_packet();
  uint64_t getId() const {
    return id_;
  }
  int getFd() const {
    return endpoint_->fd;
  }
  using Ptr = std::shared_ptr<Client>;
  void process(int events);
  void push_request(shared_ptr<taf::TC_HttpRequest> &req) {
    requests_.push_back(req);
  }
  void check_pushed_requests() {
    on_extend_max_streams();
    on_write();
  }
  void setRemoveConnFunc(const function<void(uint64_t)> &func) {
      removeConnFunc_ = func;
  }
  void setCancelTimerFunc(const function<void(const EventLoopTimer *)> &func) {
      cancelTimerFunc_ = func;
  }
  void setEventFunc(const function<void(int, int, uint32_t)> &func) {
      setEventFunc_ = func;
  }
  void initEvent() {
      setEventFunc_(getFd(), getId(), EPOLLIN | EPOLLOUT);
  }
  void setTimerFunc(const function<void(const EventLoopTimer *, double)> &func) {
      setTimerFunc_ = func;
  }

private:
  static uint64_t generateId() {
    static std::atomic<uint64_t> id = {0};
    return ++id;
  }
  uint64_t id_ = generateId();
  TLSClientContext tls_ctx_;
  function<void(uint64_t)> removeConnFunc_;
  function<void(const EventLoopTimer *)> cancelTimerFunc_;
  function<void(int, int, uint32_t)> setEventFunc_;
  function<void(const EventLoopTimer *, double)> setTimerFunc_;
  // requests contains URIs to request.
  std::list<shared_ptr<taf::TC_HttpRequest>> requests_;
  std::unique_ptr<Endpoint> endpoint_;
  sockaddr_in remote_addr_;
  std::map<int64_t, std::unique_ptr<Stream>> streams_;
  std::vector<uint32_t> offered_versions_;
  nghttp3_conn *httpconn_;
  // addr_ is the server host address.
  const char *addr_;
  // port_ is the server port.
  const char *port_;
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
      sockaddr_in remote_addr;
      unsigned int ecn;
      size_t datalen;
    } blocked;
    std::array<uint8_t, 64_k> data;
  } tx_;
  struct Timer : public EventLoopTimer {
      Timer(Client *client) : client_(client) {}
      void onTimeout() override;
      Client *client_;
  };
  shared_ptr<Timer> timer_;
};

void* createHttp3Conn(EventLoop *loop, const string& targetAddr, uint32_t targetPort);
void destroyHttp3Conn(void *conn);

#endif // CLIENT_H
