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

#include "tc_epoller.h"
#include "tc_timeout_queue_simple.h"
#include <iostream>
#include <sstream>
#include <atomic>
#include <list>

using namespace ngtcp2;

struct Stream {
  Stream(shared_ptr<Request> &req, int64_t stream_id);

  shared_ptr<Request> req;
  int64_t stream_id;
};

class Client;

struct Endpoint {
  Address addr;
  Client *client;
  int fd;
};

class EventLoop;
class Timer {
public:
  virtual void onTimeout() = 0;
  uint64_t getId() const {
    return id_;
  }
private:
  static uint64_t generateId() {
    static std::atomic<uint64_t> id = {0};
    return ++id;
  }
  uint64_t id_ = generateId();
};
class Client : public ClientBase {
  struct Timer : public ::Timer {
    Timer(Client *client) : client_(client) {}
    void onTimeout() override;
    Client *client_;
  };
public:
  Client(EventLoop *loop, uint32_t client_chosen_version,
         uint32_t original_version);
  ~Client();

  int init(int fd, const Address &local_addr, const Address &remote_addr,
           const char *addr, const char *port);
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
  uint64_t getId() const {
    return id_;
  }
  int getFd() const {
    return endpoint_->fd;
  }
  using Ptr = std::shared_ptr<Client>;
  void process(int events);
  void push_request(shared_ptr<Request> &req) {
    requests_.push_back(req);
  }
  void check_pushed_requests() {
    on_extend_max_streams();
    on_write();
  }

private:
  static uint64_t generateId() {
    static std::atomic<uint64_t> id = {0};
    return ++id;
  }
  EventLoop *loop_;
  uint64_t id_ = generateId();
  TLSClientContext tls_ctx_;
  // requests contains URIs to request.
  std::list<shared_ptr<Request>> requests_;
  std::unique_ptr<Endpoint> endpoint_;
  Address remote_addr_;
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
      Address remote_addr;
      unsigned int ecn;
      size_t datalen;
    } blocked;
    std::array<uint8_t, 64_k> data;
  } tx_;
  shared_ptr<Timer> timer_;
};

class TC_HttpConnKey {
    tuple<const string &, const uint32_t &> getTuple() const {
        return tie(targetAddr, targetPort);
    }
public:
    TC_HttpConnKey(const string &targetAddr, uint32_t targetPort)
        : targetAddr(targetAddr), targetPort(targetPort) {}
    string targetAddr;  //域名或ip
    uint32_t targetPort = 0;
    bool operator<(const TC_HttpConnKey &k) const {
        return getTuple() < k.getTuple();
    }
    friend ostream &operator<<(ostream &os, const TC_HttpConnKey &key) {
        os << "target=" << key.targetAddr << ":" << key.targetPort;
        return os;
    }
    string toString() const {
        ostringstream os;
        os << *this;
        return os.str();
    }
};

class TC_HttpConnPool {
public:
    using onCreateConnFunc =
        std::function<Client::Ptr(const TC_HttpConnKey &)>;
    using onGotIdleConnFunc = std::function<void(const Client *)>;
    shared_ptr<Client> id2Ptr(uint64_t id) {
        auto it = _id2Ptr.find(id);
        if (it == _id2Ptr.end()) return nullptr;
        return it->second;
    }
    void asyncGetConn(const string &targetAddr, uint32_t targetPort,
                      shared_ptr<Request> reqPtr,
                      const onCreateConnFunc &onCreateConn,
                      const onGotIdleConnFunc &onGotIdleConn) {
        TC_HttpConnKey key{targetAddr, targetPort};
        unique_lock<mutex> lock(asyncFuncMtx_);
        asyncFuncs_.push_back(
            [this, key = move(key), weakReqPtr = weak_ptr<Request>(reqPtr),
             onCreateConn, onGotIdleConn]() {
                getConn(key, weakReqPtr, onCreateConn, onGotIdleConn);
            });
    }
    void idleFunc() {
        vector<function<void()>> asyncFuncs;
        {
            unique_lock<mutex> lock(asyncFuncMtx_);
            asyncFuncs.swap(asyncFuncs_);
        }
        for (auto &func : asyncFuncs) {
            func();
        }
        for (auto &it : _id2Ptr) {
            auto &conn = it.second;
            conn->check_pushed_requests();
        }
    }
private:
    void getConn(const TC_HttpConnKey &key, weak_ptr<Request> weakReqPtr,
                 const onCreateConnFunc &onCreateConn,
                 const onGotIdleConnFunc &onGotIdleConn) {
        auto reqPtr = weakReqPtr.lock();
        if (!reqPtr) {
            cout << key << "|get idle failed|reqPtr expired" << endl;
            return;
        }
        auto it = _conns.find(key);
        if (it != _conns.end()) {
            auto conn = id2Ptr(it->second);
            onGotIdleConn(conn.get());
            cout << key << "|get idle conn" << endl;
            conn->push_request(reqPtr);
            return;
        }
        auto conn = onCreateConn(key);
        if (!conn) return;
        _conns[key] = conn->getId();
        _id2Ptr[conn->getId()] = conn;
        cout << key << "|create new conn" << endl;
        conn->push_request(reqPtr);
    }
    mutex asyncFuncMtx_;
    vector<function<void()>> asyncFuncs_;
    map<TC_HttpConnKey, uint64_t> _conns;
    unordered_map<uint64_t, shared_ptr<Client>> _id2Ptr;
};

class EventLoop {
public:
    EventLoop() {
        _epoller.create(1024);
    }
    void setTimer(shared_ptr<Timer> timer, int timeoutMs) {
        _data.push(timer, timer->getId(), timeoutMs);
    }
    void cancelTimer(const Timer* timer) {
        _data.erase(timer->getId());
    }
    void doRequest(const string &targetAddr, uint32_t targetPort,
                   shared_ptr<Request> reqPtr) {
        _connPool.asyncGetConn(targetAddr, targetPort, reqPtr,
                               getCreateConnFunc(),
                               [this](const Client *conn) {});
    }
    void setEvent(Client *c, uint32_t event) {
        //TODO
        _epoller.add(c->getFd(), c->getId(), event);
        _epoller.mod(c->getFd(), c->getId(), event);
    }
    void run() {
        while (!_terminate) {
            try {
                _data.timeout([](auto &ptr) { ptr->onTimeout(); });
                int waitTime = 10;
                int64_t now = TNOWMS;
                // 例如当前时间0，即将超时事件时间3，最大超时时间10
                // 那么wait 3即可
                if (_data.getFirstDeadline() != -1 &&
                    _data.getFirstDeadline() < now + waitTime) {
                    waitTime = _data.getFirstDeadline() - now;
                    waitTime = max(waitTime, 0);
                }

                int num = _epoller.wait(waitTime);

                for (int i = 0; i < num; ++i) {
                    epoll_event ev = _epoller.get(i);

                    uint64_t connId = ev.data.u64;

                    auto conn = _connPool.id2Ptr(connId);

                    if (!conn) continue;

                    conn->process(ev.events);
                }

                _connPool.idleFunc();
            } catch (exception &ex) {
                std::cerr << "[TC_HttpAsync::run] error:" << ex.what() << endl;
            }
        }
    }
private:
    TC_HttpConnPool::onCreateConnFunc getCreateConnFunc();
    TC_Epoller _epoller;
    bool _terminate = false;
    TC_TimeoutQueueSimple<shared_ptr<Timer>> _data;
    TC_HttpConnPool _connPool;
};

#endif // CLIENT_H
