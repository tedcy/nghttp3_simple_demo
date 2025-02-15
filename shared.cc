/*
 * ngtcp2
 *
 * Copyright (c) 2019 ngtcp2 contributors
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
#include "shared.h"

#include <nghttp3/nghttp3.h>

#include <cstring>
#include <cassert>
#include <iostream>

#include <unistd.h>
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif // HAVE_NETINET_IN_H
#ifdef HAVE_ASM_TYPES_H
#  include <asm/types.h>
#endif // HAVE_ASM_TYPES_H
#ifdef HAVE_LINUX_NETLINK_H
#  include <linux/netlink.h>
#endif // HAVE_LINUX_NETLINK_H
#ifdef HAVE_LINUX_RTNETLINK_H
#  include <linux/rtnetlink.h>
#endif // HAVE_LINUX_RTNETLINK_H

#include "template.h"

namespace ngtcp2 {

unsigned int msghdr_get_ecn(msghdr *msg, int family) {
  switch (family) {
  case AF_INET:
    for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
      if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS &&
          cmsg->cmsg_len) {
        return *reinterpret_cast<uint8_t *>(CMSG_DATA(cmsg));
      }
    }
    break;
  case AF_INET6:
    for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
      if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS &&
          cmsg->cmsg_len) {
        return *reinterpret_cast<uint8_t *>(CMSG_DATA(cmsg));
      }
    }
    break;
  }

  return 0;
}

void fd_set_ecn(int fd, int family, unsigned int ecn) {
  switch (family) {
  case AF_INET:
    if (setsockopt(fd, IPPROTO_IP, IP_TOS, &ecn,
                   static_cast<socklen_t>(sizeof(ecn))) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
    }
    break;
  case AF_INET6:
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &ecn,
                   static_cast<socklen_t>(sizeof(ecn))) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
    }
    break;
  }
}

void fd_set_recv_ecn(int fd, int family) {
  unsigned int tos = 1;
  switch (family) {
  case AF_INET:
    if (setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &tos,
                   static_cast<socklen_t>(sizeof(tos))) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
    }
    break;
  case AF_INET6:
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &tos,
                   static_cast<socklen_t>(sizeof(tos))) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
    }
    break;
  }
}

void fd_set_ip_mtu_discover(int fd, int family) {
#if defined(IP_MTU_DISCOVER) && defined(IPV6_MTU_DISCOVER)
  int val;

  switch (family) {
  case AF_INET:
    val = IP_PMTUDISC_DO;
    if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &val,
                   static_cast<socklen_t>(sizeof(val))) == -1) {
      std::cerr << "setsockopt: IP_MTU_DISCOVER: " << strerror(errno)
                << std::endl;
    }
    break;
  case AF_INET6:
    val = IPV6_PMTUDISC_DO;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &val,
                   static_cast<socklen_t>(sizeof(val))) == -1) {
      std::cerr << "setsockopt: IPV6_MTU_DISCOVER: " << strerror(errno)
                << std::endl;
    }
    break;
  }
#endif // defined(IP_MTU_DISCOVER) && defined(IPV6_MTU_DISCOVER)
}

void fd_set_ip_dontfrag(int fd, int family) {
#if defined(IP_DONTFRAG) && defined(IPV6_DONTFRAG)
  int val = 1;

  switch (family) {
  case AF_INET:
    if (setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &val,
                   static_cast<socklen_t>(sizeof(val))) == -1) {
      std::cerr << "setsockopt: IP_DONTFRAG: " << strerror(errno) << std::endl;
    }
    break;
  case AF_INET6:
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &val,
                   static_cast<socklen_t>(sizeof(val))) == -1) {
      std::cerr << "setsockopt: IPV6_DONTFRAG: " << strerror(errno)
                << std::endl;
    }
    break;
  }
#endif // defined(IP_DONTFRAG) && defined(IPV6_DONTFRAG)
}

} // namespace ngtcp2
