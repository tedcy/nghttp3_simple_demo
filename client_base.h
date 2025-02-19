/*
 * ngtcp2
 *
 * Copyright (c) 2020 ngtcp2 contributors
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
#ifndef CLIENT_BASE_H
#define CLIENT_BASE_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // HAVE_CONFIG_H

#include <vector>
#include <deque>
#include <string>
#include "string_view.h"
#include <functional>

#include <ngtcp2/ngtcp2_crypto.h>

#include "tls_client_session.h"
#include "network.h"
#include "shared.h"

using namespace ngtcp2;

#include <iostream>
#include <functional>
#include <utility>
#include <type_traits>

// 兼容 C++14 的 Defer 类模板
template <typename F, typename... T>
class Defer {
private:
    std::function<void()> f; // 将所有函数封装成无参 void 返回值的函数
public:
    // 构造函数，使用 std::bind 包装传入的函数和参数
    Defer(F&& func, T&&... args)
        : f(std::bind(std::forward<F>(func), std::forward<T>(args)...)) {}

    // 支持移动构造函数
    Defer(Defer&& other) noexcept : f(std::move(other.f)) {}

    // 析构函数，在作用域结束时执行绑定的函数
    ~Defer() {
        if (f) f();
    }
};

// 工厂函数：帮助创建 Defer 对象
template <typename F, typename... T>
Defer<F, T...> defer(F&& func, T&&... args) {
    return Defer<F, T...>(std::forward<F>(func), std::forward<T>(args)...);
}

template <typename T, size_t N> constexpr size_t str_size(T (&)[N]) {
  return N - 1;
}
// User-defined literals for K, M, and G (powers of 1024)

#define LIBHTTP3_K 1024

#define LIBHTTP3_M 1024 * 1024

#define LIBHTTP3_G 1024 * 1024 * 1024

struct Config {
  // quiet suppresses the output normally shown except for the error
  // messages.
  bool quiet = true;
  // timeout is an idle timeout for QUIC connection.
  ngtcp2_duration timeout = 0 * NGTCP2_SECONDS;
  // no_quic_dump is true if hexdump of QUIC STREAM and CRYPTO data
  // should be disabled.
  bool no_quic_dump = false;
  // no_http_dump is true if hexdump of HTTP response body should be
  // disabled.
  bool no_http_dump = false;
  // max_data is the initial connection-level flow control window.
  uint64_t max_data = 15 * LIBHTTP3_M;
  // max_stream_data_bidi_local is the initial stream-level flow
  // control window for a bidirectional stream that the local endpoint
  // initiates.
  uint64_t max_stream_data_bidi_local = 6 * LIBHTTP3_M;
  // max_stream_data_bidi_remote is the initial stream-level flow
  // control window for a bidirectional stream that the remote
  // endpoint initiates.
  uint64_t max_stream_data_bidi_remote = 6 * LIBHTTP3_M;
  // max_stream_data_uni is the initial stream-level flow control
  // window for a unidirectional stream.
  uint64_t max_stream_data_uni = 6 * LIBHTTP3_M;
  // max_streams_bidi is the number of the concurrent bidirectional
  // streams.
  uint64_t max_streams_bidi;
  // max_streams_uni is the number of the concurrent unidirectional
  // streams.
  uint64_t max_streams_uni = 100;
  // max_window is the maximum connection-level flow control window
  // size if auto-tuning is enabled.
  uint64_t max_window = 24 * LIBHTTP3_M;
  // max_stream_window is the maximum stream-level flow control window
  // size if auto-tuning is enabled.
  uint64_t max_stream_window = 16 * LIBHTTP3_M;
  // static_secret is used to derive keying materials for Stateless
  // Retry token.
  std::array<uint8_t, 32> static_secret;
  // cc_algo is the congestion controller algorithm.
  ngtcp2_cc_algo cc_algo = NGTCP2_CC_ALGO_CUBIC;
  // initial_rtt is an initial RTT.
  ngtcp2_duration initial_rtt = NGTCP2_DEFAULT_INITIAL_RTT;
  // max_udp_payload_size is the maximum UDP payload size that client
  // transmits.
  size_t max_udp_payload_size;
  // handshake_timeout is the period of time before giving up QUIC
  // connection establishment.
  ngtcp2_duration handshake_timeout = UINT64_MAX;
  // no_pmtud disables Path MTU Discovery.
  bool no_pmtud;
  // ack_thresh is the minimum number of the received ACK eliciting
  // packets that triggers immediate acknowledgement.
  size_t ack_thresh = 2;
};

class ClientBase {
public:
  ClientBase();
  ~ClientBase();

  ngtcp2_conn *conn() const;

  int write_transport_params(const char *path,
                             const ngtcp2_transport_params *params);
  int read_transport_params(const char *path, ngtcp2_transport_params *params);

  void write_qlog(const void *data, size_t datalen);

  ngtcp2_crypto_conn_ref *conn_ref();

protected:
  ngtcp2_crypto_conn_ref conn_ref_;
  TLSClientSession tls_session_;
  FILE *qlog_;
  ngtcp2_conn *conn_;
  ngtcp2_ccerr last_error_;
};

void qlog_write_cb(void *user_data, uint32_t flags, const void *data,
                   size_t datalen);

#endif // CLIENT_BASE_H
