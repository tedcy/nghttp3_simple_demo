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
#ifndef TLS_CLIENT_SESSION_H
#define TLS_CLIENT_SESSION_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // HAVE_CONFIG_H

#if defined(ENABLE_EXAMPLE_OPENSSL) && defined(WITH_EXAMPLE_OPENSSL)
#  include "tls_client_session_openssl.h"
#endif // ENABLE_EXAMPLE_OPENSSL && WITH_EXAMPLE_OPENSSL

#if defined(ENABLE_EXAMPLE_GNUTLS) && defined(WITH_EXAMPLE_GNUTLS)
#  include "tls_client_session_gnutls.h"
#endif // ENABLE_EXAMPLE_GNUTLS && WITH_EXAMPLE_GNUTLS

#if defined(ENABLE_EXAMPLE_BORINGSSL) && defined(WITH_EXAMPLE_BORINGSSL)
#  include "tls_client_session_boringssl.h"
#endif // ENABLE_EXAMPLE_BORINGSSL && WITH_EXAMPLE_BORINGSSL

#if defined(ENABLE_EXAMPLE_PICOTLS) && defined(WITH_EXAMPLE_PICOTLS)
#  include "tls_client_session_picotls.h"
#endif // ENABLE_EXAMPLE_PICOTLS && WITH_EXAMPLE_PICOTLS

#if defined(ENABLE_EXAMPLE_WOLFSSL) && defined(WITH_EXAMPLE_WOLFSSL)
#  include "tls_client_session_wolfssl.h"
#endif // ENABLE_EXAMPLE_WOLFSSL && WITH_EXAMPLE_WOLFSSL

#endif // TLS_CLIENT_SESSION_H
