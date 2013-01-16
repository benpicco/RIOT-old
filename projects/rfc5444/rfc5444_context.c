
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
#include <rfc5444/rfc5444_context.h>

static const char *_rfc5444_positive_result_texts[] = {
  [RFC5444_OKAY]                 = "Okay",
  [RFC5444_DROP_TLV]             = "Drop TLV",
  [RFC5444_DROP_MSG_BUT_FORWARD] = "Drop message but forward it",
  [RFC5444_DROP_MESSAGE]         = "Drop message",
  [RFC5444_DROP_PACKET]          = "Drop packet",
};

static const char *_rfc5444_negative_result_texts[] = {
  [RFC5444_OKAY]                 = "Okay",
  [-RFC5444_UNSUPPORTED_VERSION]  = "Version of rfc5444 not supported",
  [-RFC5444_END_OF_BUFFER]        = "Early end of packet",
  [-RFC5444_BAD_TLV_IDXFLAGS]     = "Bad combination of index flags",
  [-RFC5444_BAD_TLV_VALUEFLAGS]   = "Bad combination of value flags",
  [-RFC5444_BAD_TLV_LENGTH]       = "TLV length is no multiple of number of values",
  [-RFC5444_OUT_OF_MEMORY]        = "Memory allocation failed",
  [-RFC5444_EMPTY_ADDRBLOCK]      = "Address block with zero addresses",
  [-RFC5444_BAD_MSG_TAILFLAGS]    = "Bad combination of address tail flags",
  [-RFC5444_BAD_MSG_PREFIXFLAGS]  = "Bad combination of address prefix length flags",
  [-RFC5444_DUPLICATE_TLV]        = "Duplicate address TLV",
  [-RFC5444_OUT_OF_ADDRTLV_MEM]   = "Not enough memory for address-TLVs",
  [-RFC5444_MTU_TOO_SMALL]        = "Configured MTU size too small",
  [-RFC5444_NO_MSGCREATOR]        = "Cannot create message without message creator",
  [-RFC5444_FW_MESSAGE_TOO_LONG]  = "Cannot forward message, content too long",
  [-RFC5444_FW_BAD_SIZE]          = "Bad length field of message to be forwarded",
};

/**
 * @param result pbb result code
 * @return text message for result code
 */
const char *
rfc5444_strerror(enum rfc5444_result result) {
  const char *UNKNOWN = "Unknown pbb result";
  if (result >= RFC5444_OKAY && result <= RFC5444_RESULT_MAX) {
    return _rfc5444_positive_result_texts[result];
  }
  if (result < RFC5444_OKAY && result >= RFC5444_RESULT_MIN) {
    return _rfc5444_negative_result_texts[-result];
  }
  return UNKNOWN;
}
