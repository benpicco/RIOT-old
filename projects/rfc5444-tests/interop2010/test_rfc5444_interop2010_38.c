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
    0x08, 0x00, 0x26, 0x01, 0x05, 0x00, 0x12, 0x00, 0x00, 0x02, 0x80, 0x05,
    0x0a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00 };

static uint8_t _addr1[] = { 0x0a, 0x00, 0x00, 0x00, 0x00, 0x01, };
static uint8_t _addr2[] = { 0x0a, 0x00, 0x00, 0x00, 0x00, 0x02, };

static struct test_address _addrs[] = {
    {
      .addr = _addr1,
      .plen = 48,
    },
    {
      .addr = _addr2,
      .plen = 48,
    },
};

static struct test_message _msgs[] = {
  {
    .type = 1,
    .addrlen = 6,

    .address_count = ARRAYSIZE(_addrs),
    .addrs = _addrs,
  },
};

static struct test_packet test38 = {
  .test = "Interop 2010 Test 38",
  .binary = _binary,
  .binlen = ARRAYSIZE(_binary),

  .version = 0,
  .flags = 0x08,

  .has_seq = true,
  .seqno = 38,

  .msg_count = ARRAYSIZE(_msgs),
  .msgs = _msgs,
};

ADD_TEST(test38)
