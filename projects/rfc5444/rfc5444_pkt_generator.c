
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
#include <assert.h>
#include <string.h>

#include "sys/common/common_types.h"
#include "sys/common/list.h"
#include "rfc5444_writer.h"
#include "rfc5444_api_config.h"

static void _write_pktheader(struct rfc5444_writer_interface *interf);

/**
 * Internal function to start generation of a packet
 * This function should not be called by the user of the pbb API!
 *
 * @param writer pointer to writer context
 * @param interf pointer to interface for packet
 */
void
_rfc5444_writer_begin_packet(struct rfc5444_writer *writer,
    struct rfc5444_writer_interface *interf) {
  struct rfc5444_writer_pkthandler *handler;

  /* cleanup packet buffer data */
  _rfc5444_tlv_writer_init(&interf->_pkt, interf->packet_size, interf->packet_size);

#if WRITER_STATE_MACHINE == true
  writer->_state = RFC5444_WRITER_ADD_PKTHEADER;
#endif
  /* add packet header */
  if (interf->addPacketHeader) {
    interf->addPacketHeader(writer, interf);
  }
  else {
    rfc5444_writer_set_pkt_header(writer, interf, false);
  }

#if WRITER_STATE_MACHINE == true
  writer->_state = RFC5444_WRITER_ADD_PKTTLV;
#endif
  /* add packet tlvs */
  list_for_each_element(&writer->_pkthandlers, handler, _pkthandle_node) {
    handler->addPacketTLVs(writer, interf);
  }

  interf->_is_flushed = false;
#if WRITER_STATE_MACHINE == true
  writer->_state = RFC5444_WRITER_NONE;
#endif
}

/**
 * Flush the current messages in the writer buffer and send
 * a complete packet.
 * @param writer pointer to writer context
 * @param interf pointer to interface to flush
 * @param force true if the writer should create an empty packet if necessary
 */
void
rfc5444_writer_flush(struct rfc5444_writer *writer,
    struct rfc5444_writer_interface *interf, bool force) {
  struct rfc5444_writer_pkthandler *handler;
  size_t len;

#if WRITER_STATE_MACHINE == true
  assert(writer->_state == RFC5444_WRITER_NONE);
#endif

  assert(interf->sendPacket);

  if (interf->_is_flushed) {
    if (!force) {
      return;
    }

    /* begin a new packet, buffer is flushed at the moment */
    _rfc5444_writer_begin_packet(writer, interf);
  }

#if WRITER_STATE_MACHINE == true
  writer->_state = RFC5444_WRITER_FINISH_PKTTLV;
#endif

  /* finalize packet tlvs */
  list_for_each_element_reverse(&writer->_pkthandlers, handler, _pkthandle_node) {
    handler->finishPacketTLVs(writer, interf);
  }

#if WRITER_STATE_MACHINE == true
  writer->_state = RFC5444_WRITER_FINISH_PKTHEADER;
#endif
  /* finalize packet header */
  if (interf->finishPacketHeader) {
    interf->finishPacketHeader(writer, interf);
  }

  /* write packet header (including tlvblock length if necessary */
  _write_pktheader(interf);

  /* calculate true length of header (optional tlv block !) */
  len = 1;
  if (interf->_has_seqno) {
    len += 2;
  }
  if (interf->_pkt.added + interf->_pkt.set > 0) {
    len += 2;
  }

  /* compress packet buffer */
  if (interf->_bin_msgs_size) {
    memmove(&interf->_pkt.buffer[len + interf->_pkt.added + interf->_pkt.set],
        &interf->_pkt.buffer[interf->_pkt.header + interf->_pkt.added + interf->_pkt.allocated],
        interf->_bin_msgs_size);
  }

  /* send packet */
  interf->sendPacket(writer, interf, interf->_pkt.buffer,
      len + interf->_pkt.added + interf->_pkt.set + interf->_bin_msgs_size);

  /* cleanup length information */
  interf->_pkt.set  = 0;
  interf->_bin_msgs_size = 0;

  /* mark buffer as flushed */
  interf->_is_flushed = true;

#if WRITER_STATE_MACHINE == true
  writer->_state = RFC5444_WRITER_NONE;
#endif

#if DEBUG_CLEANUP == true
  memset(&interf->_pkt.buffer[len + interf->_pkt.added], 0,
      interf->_pkt.max - len - interf->_pkt.added);
#endif
}

/**
 * Adds a tlv to a packet.
 * This function must not be called outside the packet add_tlv callback.
 *
 * @param writer pointer to writer context
 * @param interf pointer to writer interface object
 * @param type tlv type
 * @param exttype tlv extended type, 0 if no extended type
 * @param value pointer to tlv value, NULL if no value
 * @param length number of bytes in tlv value, 0 if no value
 * @return RFC5444_OKAY if tlv has been added to packet, RFC5444_... otherwise
 */
enum rfc5444_result
rfc5444_writer_add_packettlv(struct rfc5444_writer *writer __attribute__ ((unused)),
    struct rfc5444_writer_interface *interf,
    uint8_t type, uint8_t exttype, void *value, size_t length) {
#if WRITER_STATE_MACHINE == true
  assert(writer->_state == RFC5444_WRITER_ADD_PKTTLV);
#endif
  return _rfc5444_tlv_writer_add(&interf->_pkt, type, exttype, value, length);
}

/**
 * Allocate memory for packet tlv.
 * This function must not be called outside the packet add_tlv callback.
 *
 * @param writer pointer to writer context
 * @param interf pointer to writer interface object
 * @param has_exttype true if tlv has an extended type
 * @param length number of bytes in tlv value, 0 if no value
 * @return RFC5444_OKAY if tlv has been added to packet, RFC5444_... otherwise
 */
enum rfc5444_result
rfc5444_writer_allocate_packettlv(struct rfc5444_writer *writer __attribute__ ((unused)),
    struct rfc5444_writer_interface *interf, bool has_exttype, size_t length) {
#if WRITER_STATE_MACHINE == true
  assert(writer->_state == RFC5444_WRITER_ADD_PKTTLV);
#endif
  return _rfc5444_tlv_writer_allocate(&interf->_pkt, has_exttype, length);
}

/**
 * Sets a tlv for a packet, which memory has been already allocated.
 * This function must not be called outside the packet finish_tlv callback.
 *
 * @param writer pointer to writer context
 * @param interf pointer to interface to set packet-tlv
 * @param type tlv type
 * @param exttype tlv extended type, 0 if no extended type
 * @param value pointer to tlv value, NULL if no value
 * @param length number of bytes in tlv value, 0 if no value
 * @return RFC5444_OKAY if tlv has been added to packet, RFC5444_... otherwise
 */
enum rfc5444_result
rfc5444_writer_set_packettlv(struct rfc5444_writer *writer __attribute__ ((unused)),
    struct rfc5444_writer_interface *interf,
    uint8_t type, uint8_t exttype, void *value, size_t length) {
#if WRITER_STATE_MACHINE == true
  assert(writer->_state == RFC5444_WRITER_FINISH_PKTTLV);
#endif
  return _rfc5444_tlv_writer_set(&interf->_pkt, type, exttype, value, length);
}

/**
 * Initialize the header of a packet.
 * This function must not be called outside the packet add_header callback.
 *
 * @param writer pointer to writer context
 * @param interf pointer to interface to set packet header
 * @param has_seqno true if packet has a sequence number
 */
void rfc5444_writer_set_pkt_header(
    struct rfc5444_writer *writer __attribute__ ((unused)),
    struct rfc5444_writer_interface *interf, bool has_seqno) {
#if WRITER_STATE_MACHINE == true
  assert(writer->_state == RFC5444_WRITER_ADD_PKTHEADER);
#endif

  /* we assume that we have always an TLV block and subtract the 2 bytes later */
  interf->_pkt.header = 1+2;

  /* handle sequence number */
  interf->_has_seqno = has_seqno;
  if (has_seqno) {
    interf->_pkt.header += 2;
  }
}

/**
 * Sets the sequence number of a packet.
 * This function must not be called outside the packet
 * add_header/finish_header callback.
 *
 * @param writer pointer to writer context
 * @param interf pointer to interface to set packet sequence number
 * @param seqno sequence number of packet
 */
void
rfc5444_writer_set_pkt_seqno(struct rfc5444_writer *writer __attribute__ ((unused)),
    struct rfc5444_writer_interface *interf, uint16_t seqno) {
#if WRITER_STATE_MACHINE == true
  assert(writer->_state == RFC5444_WRITER_ADD_PKTHEADER
      || writer->_state == RFC5444_WRITER_FINISH_PKTHEADER);
#endif
  interf->_seqno = seqno;
  interf->last_seqno = seqno;
}

/**
 * Write the header of a packet into the packet buffer
 * @param writer pointer to writer interface object
 */
static void
_write_pktheader(struct rfc5444_writer_interface *interf) {
  uint8_t *ptr;
  size_t len;

  ptr = interf->_pkt.buffer;
  *ptr++ = 0;
  if (interf->_has_seqno) {
    interf->_pkt.buffer[0] |= RFC5444_PKT_FLAG_SEQNO;
    *ptr++ = (interf->_seqno >> 8);
    *ptr++ = (interf->_seqno & 255);
  }

  /* tlv-block ? */
  len = interf->_pkt.added + interf->_pkt.set;
  if (len > 0) {
    interf->_pkt.buffer[0] |= RFC5444_PKT_FLAG_TLV;
    *ptr++ = (len >> 8);
    *ptr++ = (len & 255);
  }
}
