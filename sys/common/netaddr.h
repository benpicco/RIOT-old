
/*
 * The olsr.org Optimized Link-State Routing daemon(olsrd)
 * Copyright (c) 2004-2012, the olsr.org team - see HISTORY file
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of olsr.org, olsrd nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Visit http://www.olsr.org for more information.
 *
 * If you find this software useful feel free to make a donation
 * to the project. For more information see the website or contact
 * the copyright holders.
 *
 */

#define _RIOT 1	// put this elsewhere

#ifndef NETADDR_H_
#define NETADDR_H_

#ifdef _RIOT
// do we really need all of them?
#include "sys/net/destiny/udp.h"
#include "sys/net/destiny/tcp.h"
#include "sys/net/destiny/socket.h"
#include "sys/net/destiny/in.h"
#include "sys/net/destiny/destiny.h"
#include "sys/net/destiny/tcp_timer.h"
#include "sys/net/net_help/net_help.h"
#include "sys/net/net_help/msg_help.h"

typedef unsigned int sa_family_t;
typedef int socklen_t;
#define INET6_ADDRSTRLEN        (48)

#else
#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <net/if.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>

#define IF_NAMESIZE 16
#endif
#endif

#include <assert.h>
#include <string.h>

#include "common_types.h"
#include "autobuf.h"

enum {
  AF_MAC48 = AF_MAX + 1,
  AF_EUI64 = AF_MAX + 2,
};

enum { NETADDR_MAX_LENGTH = 16 };

/**
 * Representation of an address including address type
 * At the moment we support AF_INET, AF_INET6 and AF_MAC48
 */
struct netaddr {
  /* 16 bytes of memory for address */
  uint8_t _addr[NETADDR_MAX_LENGTH];

  /* address type */
  uint8_t _type;

  /* address prefix length */
  uint8_t _prefix_len;
};

/**
 * Representation of a sockaddr object. Allows access
 * to all variants without casting and compiler warnings.
 */
 union netaddr_socket {
//  sockaddr6_t v4;
  sockaddr6_t v6;
  sockaddr6_t std;
  sockaddr6_t storage;
};

/**
 * Maximum text length of netaddr_to_string
 *
 * INET_ADDRSTRLEN and INET6_ADDRSTRLEN have been defined
 * in netinet/in.h, which has been included by this file
 */
enum {
  MAC48_ADDRSTRLEN = 18,
  MAC48_PREFIXSTRLEN = MAC48_ADDRSTRLEN + 3,
  EUI64_ADDRSTRLEN = 24,
  EUI64_PREFIXSTRLEN = EUI64_ADDRSTRLEN + 3,
  INET6_PREFIXSTRLEN = INET6_ADDRSTRLEN + 4,
};

/**
 * Buffer for writing string representation of netaddr
 * and netaddr_socket objects
 */
struct netaddr_str {
  char buf[INET6_ADDRSTRLEN+16];
};

EXPORT extern const struct netaddr NETADDR_IPV4_ANY;
EXPORT extern const struct netaddr NETADDR_IPV6_ANY;
EXPORT extern const struct netaddr NETADDR_IPV4_MULTICAST;
EXPORT extern const struct netaddr NETADDR_IPV6_MULTICAST;
EXPORT extern const struct netaddr NETADDR_IPV4_LINKLOCAL;
EXPORT extern const struct netaddr NETADDR_IPV6_LINKLOCAL;
EXPORT extern const struct netaddr NETADDR_IPV6_ULA;

EXPORT int netaddr_from_binary_prefix(struct netaddr *dst,
    const void *binary, size_t len, uint8_t addr_type, uint8_t prefix_len);
EXPORT int netaddr_to_binary(void *dst, const struct netaddr *src, size_t len);
EXPORT int netaddr_from_socket(struct netaddr *dst, const union netaddr_socket *src);
EXPORT int netaddr_to_socket(union netaddr_socket *dst, const struct netaddr *src);
EXPORT int netaddr_to_autobuf(struct autobuf *, const struct netaddr *src);
EXPORT int netaddr_create_host_bin(struct netaddr *host, const struct netaddr *netmask,
    const void *number, size_t num_length);
EXPORT int netaddr_socket_init(union netaddr_socket *combined,
    const struct netaddr *addr, uint16_t port, unsigned if_index);
EXPORT uint16_t netaddr_socket_get_port(const union netaddr_socket *sock);

EXPORT const char *netaddr_to_prefixstring(
    struct netaddr_str *dst, const struct netaddr *src, bool forceprefix);
EXPORT int netaddr_from_string(struct netaddr *, const char *) __attribute__((warn_unused_result));
EXPORT const char *netaddr_socket_to_string(struct netaddr_str *, const union netaddr_socket *);

EXPORT int netaddr_cmp_to_socket(const struct netaddr *, const union netaddr_socket *);
EXPORT bool netaddr_isequal_binary(const struct netaddr *addr,
    const void *bin, size_t len, uint16_t af, uint8_t prefix_len);
EXPORT bool netaddr_is_in_subnet(const struct netaddr *subnet, const struct netaddr *addr);
EXPORT bool netaddr_binary_is_in_subnet(const struct netaddr *subnet,
    const void *bin, size_t len, uint8_t af_family);

EXPORT uint8_t netaddr_get_af_maxprefix(const uint32_t);

EXPORT int netaddr_avlcmp(const void *, const void *, void *);
EXPORT int netaddr_socket_avlcmp(const void *, const void *, void *);

/**
 * Sets the address type of a netaddr object to AF_UNSPEC
 * @param addr netaddr object
 */
static INLINE void
netaddr_invalidate(struct netaddr *addr) {
  addr->_type = AF_UNSPEC;
}
/**
 * Calculates the maximum prefix length of an address type
 * @param addr netaddr object
 * @return prefix length, 0 if unknown address family
 */
static INLINE uint8_t
netaddr_get_maxprefix(const struct netaddr *addr) {
  return netaddr_get_af_maxprefix(addr->_type);
}

/**
 * Converts a netaddr object into a string.
 * Prefix will be added if necessary.
 * @param dst target buffer
 * @param src netaddr source
 * @return pointer to target buffer, NULL if an error happened
 */
static INLINE const char *
netaddr_to_string(struct netaddr_str *dst, const struct netaddr *src) {
  return netaddr_to_prefixstring(dst, src, false);
}

/**
 * Creates a host address from a netmask and a host number part. This function
 * will copy the netmask and then overwrite the bits after the prefix length
 * with the one from the host number.
 * @param host target buffer
 * @param netmask prefix of result
 * @param host_number postfix of result
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
netaddr_create_host(struct netaddr *host, const struct netaddr *netmask,
    const struct netaddr *host_number) {
  return netaddr_create_host_bin(host, netmask, host_number->_addr,
      netaddr_get_maxprefix(host_number));
}

/**
 * Read the binary representation of an address into a netaddr object
 * @param dst pointer to netaddr object
 * @param binary source pointer
 * @param len length of source buffer
 * @param addr_type address type of source
 * @return 0 if successful read binary data, -1 otherwise
 */
static INLINE int
netaddr_from_binary(struct netaddr *dst, const void *binary,
    size_t len, uint8_t addr_type) {
  return netaddr_from_binary_prefix(dst, binary, len, addr_type, 255);
}

/**
 * Compares two addresses.
 * Address type will be compared last.
 * @param a1 address 1
 * @param a2 address 2
 * @return >0 if a1>a2, <0 if a1<a2, 0 otherwise
 */
static INLINE int
netaddr_cmp(const struct netaddr *a1, const struct netaddr *a2) {
  return memcmp(a1, a2, sizeof(*a1));
}

/**
 * Compares two sockets.
 * @param a1 address 1
 * @param a2 address 2
 * @return >0 if a1>a2, <0 if a1<a2, 0 otherwise
 */
static INLINE int
netaddr_socket_cmp(const union netaddr_socket *s1, const union netaddr_socket *s2) {
  return memcmp(s1, s2, sizeof(*s1));
}

/**
 * @param n pointer to netaddr
 * @return pointer to start of binary address
 */
static INLINE const void *
netaddr_get_binptr(const struct netaddr *n) {
  return &n->_addr[0];
}

/**
 * @param n pointer to netaddr
 * @return number of bytes of binary address
 */
static INLINE size_t
netaddr_get_binlength(const struct netaddr *n) {
  return netaddr_get_maxprefix(n) >> 3;
}

/**
 * @param n pointer to netaddr
 * @return address family
 */
static INLINE uint8_t
netaddr_get_address_family(const struct netaddr *n) {
  return n->_type;
}

/**
 * @param n pointer to netaddr
 * @return prefix length
 */
static INLINE uint8_t
netaddr_get_prefix_length(const struct netaddr *n) {
  return n->_prefix_len;
}

/**
 * @param n pointer to netaddr
 * @param prefix_length new prefix length
 */
static INLINE void
netaddr_set_prefix_length(struct netaddr *n, uint8_t prefix_len) {
  n->_prefix_len = prefix_len;
}

/**
 * @param s pointer to netaddr socket
 * @return address family of socket
 */
static INLINE sa_family_t
netaddr_socket_get_addressfamily(const union netaddr_socket *s) {
  return s->std.sin6_family;
}

#endif /* NETADDR_H_ */
