/*
 * RFC 5444 handler library
 * Copyright (c) 2010 Henning Rogge <hrogge@googlemail.com>
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
 * Visit http://www.olsr.org/git for more information.
 *
 * If you find this software useful feel free to make a donation
 * to the project. For more information see the website or contact
 * the copyright holders.
 */

#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "sys/common/common_types.h"
#include "test_rfc5444_interop.h"

static uint8_t _binary[] = {
    0x0c, 0x00, 0x18, 0x00, 0x02, 0x01, 0x00, 0x01, 0x03, 0x00, 0x08, 0x00,
    0x02, 0x01, 0x00, 0x02, 0xf3, 0x00, 0x35, 0x0a, 0x00, 0x00, 0x01, 0xff,
    0x01, 0x30, 0x39, 0x00, 0x00, 0x02, 0xc0, 0x01, 0x0a, 0x01, 0x02, 0x00,
    0x00, 0x01, 0x01, 0x00, 0x00, 0x04, 0x08, 0x0a, 0x00, 0x00, 0x00, 0x0b,
    0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x05, 0x0a, 0x00, 0x00, 0x06, 0x20,
    0x20, 0x10, 0x18, 0x00, 0x03, 0x01, 0x40, 0x01 };

static uint8_t _addr1[] = { 10, 1, 1, 2 };
static uint8_t _addr2[] = { 10, 0, 0, 2 };
static uint8_t _addr3[] = { 10, 0, 0, 0 };
static uint8_t _addr4[] = { 11, 0, 0, 0 };
static uint8_t _addr5[] = { 10, 0, 0, 5 };
static uint8_t _addr6[] = { 10, 0, 0, 6 };

static struct test_tlv _addrtlv1[] = {
  { .type = 1 },
};

static struct test_address _addrs[] = {
  {
    .addr = _addr1,
    .plen = 32,
  },
  {
    .addr = _addr2,
    .plen = 32,
  },
  {
    .addr = _addr3,
    .plen = 32,
  },
  {
    .addr = _addr4,
    .plen = 32,

    .tlv_count = ARRAYSIZE(_addrtlv1),
    .tlvs = _addrtlv1,
  },
  {
    .addr = _addr5,
    .plen = 16,
  },
  {
    .addr = _addr6,
    .plen = 24,
  },
};

static uint8_t _originator[] = { 10, 0, 0, 1 };

static struct test_tlv _msgtlvs[] = {
  { .type = 1 },
};

static struct test_message _msgs[] = {
  {
    .type = 1,
    .addrlen = 4,

    .tlv_count = ARRAYSIZE(_msgtlvs),
    .tlvs = _msgtlvs,
  },
  {
    .type = 2,
    .addrlen = 4,
    .flags = 240,

    .has_originator = true,
    .originator = _originator,
    .has_hopcount = true,
    .hopcount = 1,
    .has_hoplimit = true,
    .hoplimit = 255,
    .has_seqno = true,
    .seqno = 12345,

    .address_count = ARRAYSIZE(_addrs),
    .addrs = _addrs,
  },
};

static struct test_tlv _pkttlvs[] = {
  { .type = 1 },
};

static struct test_packet test24 = {
  .test = "Interop 2010 Test 24",
  .binary = _binary,
  .binlen = ARRAYSIZE(_binary),

  .version = 0,
  .flags = 0x0c,

  .has_seq = true,
  .seqno = 24,

  .tlv_count = ARRAYSIZE(_pkttlvs),
  .tlvs = _pkttlvs,

  .msg_count = ARRAYSIZE(_msgs),
  .msgs = _msgs,
};

ADD_TEST(test24)
