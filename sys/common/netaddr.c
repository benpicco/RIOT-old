
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <net/if.h>
#include "sys/net/net_help/net_help.h"

#include "common_types.h"
#include "string_common.h"
#include "netaddr.h"

#include "sys/net/net_help/inet_pton.c"
#include "sys/net/net_help/inet_ntop.c"

static char *_mac_to_string(char *dst, const void *bin, size_t dst_size,
    size_t bin_size, char separator);
static int _mac_from_string(void *bin, size_t bin_size,
    const char *src, char separator);
static int _subnetmask_to_prefixlen(const char *src);
static int _read_hexdigit(const char c);
static bool _binary_is_in_subnet(const struct netaddr *subnet,
    const void *bin);

const struct netaddr NETADDR_IPV4_ANY = { {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, AF_INET, 0 };
const struct netaddr NETADDR_IPV6_ANY = { {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, AF_INET6, 0 };

const struct netaddr NETADDR_IPV4_MULTICAST = { { 224,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, AF_INET, 4 };
const struct netaddr NETADDR_IPV6_MULTICAST = { { 0xff,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, AF_INET6, 8 };

const struct netaddr NETADDR_IPV4_LINKLOCAL = { { 169,254,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, AF_INET, 16 };
const struct netaddr NETADDR_IPV6_LINKLOCAL = { { 0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, AF_INET6, 10 };

const struct netaddr NETADDR_IPV6_ULA = { { 0xfc,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, AF_INET6, 7 };

/**
 * Read the binary representation of an address into a netaddr object
 * @param dst pointer to netaddr object
 * @param binary source pointer
 * @param len length of source buffer
 * @param addr_type address type of source,
 *     0 to autodetect type from length
 * @param prefix_len prefix length of source,
 *     255 for maximum prefix length depending on type
 * @return 0 if successful read binary data, -1 otherwise
 */
int
netaddr_from_binary_prefix(struct netaddr *dst, const void *binary,
    size_t len, uint8_t addr_type, uint8_t prefix_len) {
  uint32_t addr_len;

  if (addr_type == 0) {
    switch (len) {
      case 4:
        addr_type = AF_INET;
        break;
      case 6:
        addr_type = AF_MAC48;
        break;
      case 8:
        addr_type = AF_EUI64;
        break;
      case 16:
        addr_type = AF_INET6;
        break;
      default:
        dst->_type = AF_UNSPEC;
        return -1;
    }
  }

  if (prefix_len == 255) {
    prefix_len = netaddr_get_af_maxprefix(addr_type);
  }

  addr_len = prefix_len >> 3;

  if (addr_len == 0 || len < addr_len) {
    /* unknown address type */
    dst->_type = AF_UNSPEC;
    return -1;
  }

  memset(dst->_addr, 0, sizeof(dst->_addr));
  dst->_type = addr_type;
  dst->_prefix_len = prefix_len;
  memcpy(dst->_addr, binary, addr_len);

  return 0;
}

/**
 * Writes a netaddr object into a binary buffer
 * @param dst binary buffer
 * @param src netaddr source
 * @param len length of destination buffer
 * @return 0 if successful read binary data, -1 otherwise
 */
int
netaddr_to_binary(void *dst, const struct netaddr *src, size_t len) {
  uint32_t addr_len;

  addr_len = netaddr_get_maxprefix(src) >> 3;
  if (addr_len == 0 || len < addr_len) {
    /* unknown address type */
    return -1;
  }

  memcpy(dst, src->_addr, addr_len);
  return 0;
}

/**
 * Reads the address and address-type part of an
 * netaddr_socket into a netaddr object
 * @param dst netaddr object
 * @param src netaddr_socket source
 * @return 0 if successful read binary data, -1 otherwise
 */
int
netaddr_from_socket(struct netaddr *dst, const union netaddr_socket *src) {
  memset(dst->_addr, 0, sizeof(dst->_addr));
  if (src->std.sin6_family == AF_INET6){
    /* ipv6 */
    memcpy(dst->_addr, &src->v6.sin6_addr, 16);
    dst->_prefix_len = 128;
  }
  else {
    /* unknown address type */
    dst->_type = AF_UNSPEC;
    return -1;
  }
  dst->_type = (uint8_t)src->std.sin6_family;
  return 0;
}

/**
 * Writes the address and address-type of a netaddr object
 * into a netaddr_socket.
 * @param dst pointer to netaddr_socket
 * @param src netaddr source
 * @return 0 if successful read binary data, -1 otherwise
 */
int
netaddr_to_socket(union netaddr_socket *dst, const struct netaddr *src) {
  /* copy address type */
  dst->std.sin6_family = src->_type;

  switch (src->_type) {
    case AF_INET6:
      /* ipv6 */
      memcpy(&dst->v6.sin6_addr, src->_addr, 16);
      break;
    default:
      /* unknown address type */
      return -1;
  }

  /* copy address type */
  dst->std.sin6_family= src->_type;
  return 0;
}

/**
 * Append binary address to autobuf
 * @param abuf pointer to target autobuf
 * @param src pointer to source address
 * @return -1 if an error happened, 0 otherwise
 */
int
netaddr_to_autobuf(struct autobuf *abuf, const struct netaddr *src) {
  uint32_t addr_len;

  addr_len = netaddr_get_maxprefix(src) >> 3;
  if (addr_len == 0) {
    /* unknown address type */
    return -1;
  }

  return abuf_memcpy(abuf, src->_addr, addr_len);
}

/**
 * Creates a host address from a netmask and a host number part. This function
 * will copy the netmask and then overwrite the bits after the prefix length
 * with the one from the host number.
 * @param host target buffer
 * @param netmask prefix of result
 * @param number postfix of result
 * @param num_length length of the postfix in bytes
 * @return -1 if an error happened, 0 otherwise
 */
int
netaddr_create_host_bin(struct netaddr *host, const struct netaddr *netmask,
    const void *number, size_t num_length) {
  size_t host_index, number_index;
  uint8_t host_part_length;
  const uint8_t *number_byte;
  uint8_t mask;

  number_byte = number;

  /* copy netmask with prefixlength max */
  memcpy(host, netmask, sizeof(*netmask));
  host->_prefix_len = netaddr_get_maxprefix(host);

  /* unknown address type */
  if (host->_prefix_len == 0) {
    return -1;
  }

  /* netmask has no host part */
  if (host->_prefix_len == netmask->_prefix_len || num_length == 0) {
    return 0;
  }

  /* calculate starting byte in host and number */
  host_part_length = (host->_prefix_len - netmask->_prefix_len + 7)/8;
  if (host_part_length > num_length) {
    host_index = host->_prefix_len/8 - num_length;
    number_index = 0;
  }
  else {
    host_index = netmask->_prefix_len / 8;
    number_index = num_length - host_part_length;

    /* copy bit masked part */
    if ((netmask->_prefix_len & 7) != 0) {
      mask = (255 >> (netmask->_prefix_len & 7));
      host->_addr[host_index] &= (~mask);
      host->_addr[host_index] |= (number_byte[number_index++]) & mask;
      host_index++;
    }
  }

  /* copy bytes */
  memcpy(&host->_addr[host_index], &number_byte[number_index], num_length - number_index);
  return 0;
}

/**
 * Initialize a netaddr_socket with a netaddr and a port number
 * @param combined pointer to netaddr_socket to be initialized
 * @param addr pointer to netaddr source
 * @param port port number for socket
 * @param if_index interface index for linklocal ipv6 sockets
 * @return 0 if successful read binary data, -1 otherwise
 */
int
netaddr_socket_init(union netaddr_socket *combined, const struct netaddr *addr,
    uint16_t port, unsigned if_index) {
  /* initialize memory block */
  memset(combined, 0, sizeof(*combined));

  switch (addr->_type) {
    case AF_INET6:
      /* ipv6 */
      memcpy(&combined->v6.sin6_addr, addr->_addr, 16);
      combined->v6.sin6_port = HTONS(port);
//      combined->v6.sin6_scope_id = if_index;
      break;
    default:
      /* unknown address type */
      return -1;
  }

  /* copy address type */
  combined->std.sin6_family = addr->_type;
  return 0;
}

/**
 * @param sock pointer to netaddr_socket
 * @return port of socket
 */
uint16_t
netaddr_socket_get_port(const union netaddr_socket *sock) {
  switch (sock->std.sin6_family) {
    case AF_INET6:
      return NTOHS(sock->v6.sin6_port);
    default:
      return 0;
  }
}

/**
 * Converts a netaddr into a string
 * @param dst target string buffer
 * @param src netaddr source
 * @param forceprefix true if a prefix should be appended even with maximum
 *   prefix length, false if only shorter prefixes should be appended
 * @return pointer to target buffer, NULL if an error happened
 */
const char *
netaddr_to_prefixstring(struct netaddr_str *dst,
    const struct netaddr *src, bool forceprefix) {
  const char *result = NULL;
  int maxprefix;

  maxprefix = netaddr_get_maxprefix(src);
  switch (src->_type) {
    case AF_INET:
      result = inet_ntop(AF_INET, src->_addr, dst->buf, sizeof(*dst));
      break;
    case AF_INET6:
      result = inet_ntop(AF_INET6, src->_addr, dst->buf, sizeof(*dst));
      break;
    case AF_MAC48:
      result = _mac_to_string(dst->buf, src->_addr, sizeof(*dst), 6, ':');
      break;
    case AF_EUI64:
      result = _mac_to_string(dst->buf, src->_addr, sizeof(*dst), 8, '-');
      break;
    case AF_UNSPEC:
      result = strcpy(dst->buf, "-");
      forceprefix = false;
      break;
    default:
      return NULL;
  }
  if (forceprefix || src->_prefix_len < maxprefix) {
    /* append prefix */
    snprintf(dst->buf + strlen(result), 5, "/%d", src->_prefix_len);
  }
  return result;
}

/**
 * Generates a netaddr from a string.
 * @param dst pointer to netaddr object
 * @param src pointer to input string
 * @return -1 if an error happened because of an unknown string,
 *   0 otherwise
 */
int
netaddr_from_string(struct netaddr *dst, const char *src) {
  struct netaddr_str buf;
  unsigned int colon_count, minus_count;
  int result;
  int prefix_len;
  bool has_coloncolon, has_point;
  bool last_was_colon;
  char *ptr1, *ptr2, *ptr3;

  memset(dst, 0, sizeof(*dst));

  if (strcmp(src, "-") == 0) {
    /* unspec */
    return 0;
  }

  colon_count = 0;
  minus_count = 0;
  has_coloncolon = false;
  has_point = false;

  last_was_colon = false;

  result = -1;
  prefix_len = -1;

  /* copy input string in temporary buffer */
  strscpy(buf.buf, src, sizeof(buf));
  ptr1 = buf.buf;

  ptr1 = str_trim(ptr1);

  ptr2 = ptr1;
  while (*ptr2 != 0 && !isspace((int) *ptr2) && *ptr2 != '/') {
    switch (*ptr2) {
      case ':':
        if (last_was_colon) {
          has_coloncolon = true;
        }
        colon_count++;
        break;

      case '.':
        has_point = true;
        break;

      case '-':
        minus_count++;
        break;

      default:
        break;
    }
    last_was_colon = *ptr2++ == ':';
  }

  if (*ptr2) {
    /* split strings */
    while (isspace((int) *ptr2)) *ptr2++ = 0;
    if (*ptr2 == '/') {
      *ptr2++ = 0;
    }
    while (isspace((int) *ptr2)) *ptr2++ = 0;

    if (*ptr2 == 0) {
      /* prefixlength is missing */
      dst->_type = AF_UNSPEC;
      return -1;
    }

    /* try to read numeric prefix length */
    prefix_len = (int)strtoul(ptr2, &ptr3, 10);
    if (ptr3 && *ptr3) {
      /* not a numeric prefix length */
      prefix_len = -1;
    }
  }

  /* use dst->prefix_len as storage for maximum prefixlen */
  if ((colon_count == 5 || minus_count == 5)
      && (colon_count == 0 || minus_count == 0)
      && !has_point && !has_coloncolon) {
    dst->_type = AF_MAC48;
    dst->_prefix_len = 48;
    if (colon_count > 0) {
      result = _mac_from_string(dst->_addr, 6, ptr1, ':');
    }
    else {
      result = _mac_from_string(dst->_addr, 6, ptr1, '-');
    }
  }
  else if (colon_count == 0 && !has_point && minus_count == 7) {
    dst->_type = AF_EUI64;
    dst->_prefix_len = 64;
    dst->_addr[7] = 2;
    result = _mac_from_string(dst->_addr, 8, ptr1, '-');
  }
  else if (colon_count == 0 && has_point && minus_count == 0) {
    dst->_type = AF_INET;
    dst->_prefix_len = 32;
    result = inet_pton(AF_INET, ptr1, dst->_addr) == 1 ? 0 : -1;

    if (result == 0 && *ptr2 && prefix_len == -1) {
      /* we need a prefix length, but its not a numerical one */
      prefix_len = _subnetmask_to_prefixlen(ptr2);
    }
  }
  else if ((has_coloncolon || colon_count == 7) && minus_count == 0) {
    dst->_type = AF_INET6;
    dst->_prefix_len = 128;
    result = inet_pton(AF_INET6, ptr1, dst->_addr) == 1 ? 0 : -1;
  }

  /* stop if an error happened */
  if (result) {
    dst->_type = AF_UNSPEC;
    return -1;
  }

  if (*ptr2) {
    if (prefix_len < 0 || prefix_len > dst->_prefix_len) {
      /* prefix is too long */
      dst->_type = AF_UNSPEC;
      return -1;
    }

    /* store real prefix length */
    dst->_prefix_len = (uint8_t)prefix_len;
  }
  return 0;
}

/**
 * Converts a netaddr_socket into a string
 * @param dst target string buffer
 * @param src netaddr_socket source
 * @return pointer to target buffer, NULL if an error happened
 */
const char *
netaddr_socket_to_string(struct netaddr_str *dst, const union netaddr_socket *src) {
  struct netaddr_str buf;

  if (src->std.sin6_family == AF_INET6) {
      snprintf(dst->buf, sizeof(*dst), "[%s]:%d",
          inet_ntop(AF_INET6, &src->v6.sin6_addr, buf.buf, sizeof(buf)),
          NTOHS(src->v6.sin6_port));
  }
  else {
    snprintf(dst->buf, sizeof(*dst), "\"Unknown socket type: %d\"", src->std.sin6_family);
  }

  return dst->buf;
}

/**
 * Compares two addresses in network byte order.
 * Address type will be compared last.
 *
 * This function is compatible with the avl comparator
 * prototype.
 * @param k1 address 1
 * @param k2 address 2
 * @param unused not used in this comparator
 * @return >0 if k1>k2, <0 if k1<k2, 0 otherwise
 */
int
netaddr_avlcmp(const void *k1, const void *k2, void *unused __attribute__((unused))) {
  return netaddr_cmp(k1, k2);
}

/**
 * Compares two netaddr sockets.
 *
 * This function is compatible with the avl comparator
 * prototype.
 * @param k1 address 1
 * @param k2 address 2
 * @param unused not used in this comparator
 * @return >0 if k1>k2, <0 if k1<k2, 0 otherwise
 */
int
netaddr_socket_avlcmp(const void *k1, const void *k2, void *unused __attribute__((unused))) {
  return netaddr_socket_cmp(k1, k2);
}

/**
 * Compares an netaddr object with the address part of
 * a netaddr_socket.
 * @param a1 address
 * @param a2 socket
 * @return >0 if k1>k2, <0 if k1<k2, 0 otherwise
 */
int
netaddr_cmp_to_socket(const struct netaddr *a1, const union netaddr_socket *a2) {
  int result = 0;

  result = (int)a1->_type - (int)a2->std.sin6_family;
  if (result) {
    return result;
  }

  if (a1->_type == AF_INET6) {
    /* ipv6 */
    result = memcmp(a1->_addr, &a2->v6.sin6_addr, 16);
  }

  if (result) {
    return result;
  }

  return (int)a1->_prefix_len - (a1->_type == AF_INET ? 32 : 128);
}

/**
 * Calculates if a binary address is equals to a netaddr one.
 * @param addr netaddr pointer
 * @param bin pointer to binary address
 * @param len length of binary address
 * @param af family of binary address
 * @param prefix_len prefix length of binary address
 * @return true if matches, false otherwise
 */
bool
netaddr_isequal_binary(const struct netaddr *addr,
    const void *bin, size_t len, uint16_t af, uint8_t prefix_len) {
  uint32_t addr_len;

  if (addr->_type != af || addr->_prefix_len != prefix_len) {
    return false;
  }

  addr_len = netaddr_get_maxprefix(addr) >> 3;
  if (addr_len != len) {
    return false;
  }

  return memcmp(addr->_addr, bin, addr_len) == 0;
}

/**
 * Checks if a binary address is part of a netaddr prefix.
 * @param subnet netaddr prefix
 * @param bin pointer to binary address
 * @param len length of binary address
 * @param af_family address family of binary address
 * @return true if part of the prefix, false otherwise
 */
bool
netaddr_binary_is_in_subnet(const struct netaddr *subnet,
    const void *bin, size_t len, uint8_t af_family) {
  if (subnet->_type != af_family
      || netaddr_get_maxprefix(subnet) != len * 8) {
    return false;
  }
  return _binary_is_in_subnet(subnet, bin);
}

/**
 * Checks if a netaddr object is part of another netaddr
 * prefix.
 * @param subnet netaddr prefix
 * @param addr netaddr object that might be inside the prefix
 * @return true if addr is part of subnet, false otherwise
 */
bool
netaddr_is_in_subnet(const struct netaddr *subnet,
    const struct netaddr *addr) {
  if (subnet->_type != addr->_type
      || subnet->_prefix_len > addr->_prefix_len) {
    return false;
  }

  return _binary_is_in_subnet(subnet, addr->_addr);
}

/**
 * Calculates the maximum prefix length of an address type
 * @param af_type address type
 * @return prefix length, 0 if unknown address family
 */
uint8_t
netaddr_get_af_maxprefix(uint32_t af_type) {
  switch (af_type) {
    case AF_INET:
      return 32;
      break;
    case AF_INET6:
      return 128;
    case AF_MAC48:
      return 48;
      break;
    case AF_EUI64:
      return 64;
      break;

    default:
      return 0;
  }
}

/**
 * Converts a binary mac address into a string representation
 * @param dst pointer to target string buffer
 * @param bin pointer to binary source buffer
 * @param dst_size size of string buffer
 * @param bin_size size of binary buffer
 * @param separator character for separating hexadecimal octets
 * @return pointer to target buffer, NULL if an error happened
 */
static char *
_mac_to_string(char *dst, const void *bin, size_t dst_size,
    size_t bin_size, char separator) {
  static const char hex[] = "0123456789abcdef";
  char *last_separator, *_dst;
  const uint8_t *_bin;

  _bin = bin;
  _dst = dst;
  last_separator = dst;

  if (dst_size == 0) {
    return NULL;
  }

  while (bin_size > 0 && dst_size >= 3) {
    *_dst++ = hex[(*_bin) >> 4];
    *_dst++ = hex[(*_bin) & 15];

    /* copy pointer to separator */
    last_separator = _dst;

    /* write separator */
    *_dst++ = separator;

    /* advance source pointer and decrease remaining length of buffer*/
    _bin++;
    bin_size--;

    /* calculate remaining destination size */
    dst_size-=3;
  }

  *last_separator = 0;
  return dst;
}

/**
 * Convert a string mac address into a binary representation
 * @param bin pointer to target binary buffer
 * @param bin_size pointer to size of target buffer
 * @param src pointer to source string
 * @param separator character used to separate octets in source string
 * @return 0 if sucessfully converted, -1 otherwise
 */
static int
_mac_from_string(void *bin, size_t bin_size, const char *src, char separator) {
  uint8_t *_bin;
  int num, digit_2;

  _bin = bin;

  while (bin_size > 0) {
    num = _read_hexdigit(*src++);
    if (num == -1) {
      return -1;
    }
    digit_2 = _read_hexdigit(*src);
    if (digit_2 >= 0) {
      num = (num << 4) + digit_2;
      src++;
    }
    *_bin++ = (uint8_t) num;

    bin_size--;

    if (*src == 0) {
      return bin_size ? -1 : 0;
    }
    if (*src++ != separator) {
      return -1;
    }
  }
  return -1;
}

/**
 * Reads a single hexadecimal digit
 * @param c digit to be read
 * @return integer value (0-15) of digit,
 *   -1 if not a hexadecimal digit
 */
static int
_read_hexdigit(const char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

/**
 * Converts a ipv4 subnet mask into a prefix length.
 * @param src string representation of subnet mask
 * @return prefix length, -1 if source was not a wellformed
 *   subnet mask
 */
static int
_subnetmask_to_prefixlen(const char *src) {
  uint32_t v4, shift;
  int len;

  if (inet_pton(AF_INET, src, &v4) != 1) {
    return -1;
  }

  /* transform into host byte order */
  v4 = NTOHL(v4);

  shift = 0xffffffff;
  for (len = 31; len >= 0; len--) {
    if (v4 == shift) {
      return len;
    }
    shift <<= 1;
  }

  /* not wellformed */
  return -1;
}

/**
 * Calculates if a binary address is part of a netaddr prefix.
 * It will assume that the length of the binary address and its
 * address family makes sense.
 * @param addr netaddr prefix
 * @param bin pointer to binary address
 * @return true if part of the prefix, false otherwise
 */
static bool
_binary_is_in_subnet(const struct netaddr *subnet, const void *bin) {
  size_t byte_length, bit_length;
  const uint8_t *_bin;

  _bin = bin;

  /* split prefix length into whole bytes and bit rest */
  byte_length = subnet->_prefix_len / 8;
  bit_length = subnet->_prefix_len % 8;

  /* compare whole bytes */
  if (memcmp(subnet->_addr, bin, byte_length) != 0) {
    return false;
  }

  /* compare bits if necessary */
  if (bit_length != 0) {
    return (subnet->_addr[byte_length] >> (8 - bit_length))
        == (_bin[byte_length] >> (8 - bit_length));
  }
  return true;
}
