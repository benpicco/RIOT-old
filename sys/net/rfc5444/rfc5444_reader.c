
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
#include <stdlib.h>
#include <string.h>

#include "sys/common/avl.h"
#include "sys/common/avl_comp.h"
#include "sys/common/common_types.h"
#include "rfc5444_reader.h"
#include "rfc5444_api_config.h"

#if DISALLOW_CONSUMER_CONTEXT_DROP == true
#define RFC5444_CONSUMER_DROP_ONLY(value, def) (def)
#else
#define RFC5444_CONSUMER_DROP_ONLY(value, def) (value)
#endif

static int _consumer_avl_comp(const void *k1, const void *k2, void *ptr);
static int _calc_tlvconsumer_intorder(struct rfc5444_reader_tlvblock_consumer_entry *entry);
static int _calc_tlvblock_intorder(struct rfc5444_reader_tlvblock_entry *entry);
static bool _has_same_tlvtype(int int_type1, int int_type2);
static uint8_t _rfc5444_get_u8(uint8_t **ptr, uint8_t *end, enum rfc5444_result *result);
static uint16_t _rfc5444_get_u16(uint8_t **ptr, uint8_t *end, enum rfc5444_result *result);
static void _free_tlvblock(struct rfc5444_reader *parser, struct avl_tree *entries);
static int _parse_tlv(struct rfc5444_reader_tlvblock_entry *entry, uint8_t **ptr,
    uint8_t *eob, uint8_t addr_count);
static int _parse_tlvblock(struct rfc5444_reader *parser,
    struct avl_tree *tlvblock, uint8_t **ptr, uint8_t *eob, uint8_t addr_count);
static int _schedule_tlvblock(struct rfc5444_reader_tlvblock_consumer *consumer,
    struct rfc5444_reader_tlvblock_context *context, struct avl_tree *entries, uint8_t idx);
static int _parse_addrblock(struct rfc5444_reader_addrblock_entry *addr_entry,
    struct rfc5444_reader_tlvblock_context *tlv_context, uint8_t **ptr, uint8_t *eob);
static int _handle_message(struct rfc5444_reader *parser,
    struct rfc5444_reader_tlvblock_context *tlv_context, uint8_t **ptr, uint8_t *eob);
static struct rfc5444_reader_tlvblock_consumer *_add_consumer(
    struct rfc5444_reader_tlvblock_consumer *, struct avl_tree *consumer_tree,
    struct rfc5444_reader_tlvblock_consumer_entry *entries, int entrycount, int order);
static void _free_consumer(struct avl_tree *consumer_tree,
    struct rfc5444_reader_tlvblock_consumer *consumer);
static struct rfc5444_reader_addrblock_entry *_malloc_addrblock_entry(void);
static struct rfc5444_reader_tlvblock_entry *_malloc_tlvblock_entry(void);

static uint8_t rfc5444_get_pktversion(uint8_t v);

#if DISALLOW_CONSUMER_CONTEXT_DROP == false
static void _set_addr_bitarray(struct rfc5444_reader_bitarray256 *b, int idx);
static bool _test_addrbitarray(struct rfc5444_reader_bitarray256 *b, int idx);
#endif

static const int TLVTYPE_ORDER_INFINITE = 0x10000;

/**
 * Initalize the context of a parser with default values.
 * @param context pointer to parser context
 */
void
rfc5444_reader_init(struct rfc5444_reader *context) {
  avl_init(&context->packet_consumer, _consumer_avl_comp, true, NULL);
  avl_init(&context->message_consumer, _consumer_avl_comp, true, NULL);

  if (context->malloc_addrblock_entry == NULL)
    context->malloc_addrblock_entry = _malloc_addrblock_entry;
  if (context->malloc_tlvblock_entry == NULL)
    context->malloc_tlvblock_entry = _malloc_tlvblock_entry;

  if (context->free_addrblock_entry == NULL)
    context->free_addrblock_entry = free;
  if (context->free_tlvblock_entry == NULL)
    context->free_tlvblock_entry = free;
}

/**
 * Free all memory allocated for a parser context and clear it
 * to be sure that it's not used again.
 * @param context pointer to parser context
 */
void
rfc5444_reader_cleanup(struct rfc5444_reader *context) {
  memset(&context->packet_consumer, 0, sizeof(context->packet_consumer));
  memset(&context->message_consumer, 0, sizeof(context->message_consumer));
}

/**
 * parse a complete rfc5444 packet.
 * @param parser pointer to parser context
 * @param buffer pointer to begin of rfc5444 packet
 * @param length number of bytes in buffer
 * @return RFC5444_OKAY (0) if successful, RFC5444_... otherwise
 */
enum rfc5444_result
rfc5444_reader_handle_packet(struct rfc5444_reader *parser, uint8_t *buffer, size_t length) {
  struct rfc5444_reader_tlvblock_context context;
  struct avl_tree entries;
  struct rfc5444_reader_tlvblock_consumer *consumer, *last_started;
  uint8_t *ptr, *eob;
  bool has_tlv;
  uint8_t first_byte;
  enum rfc5444_result result = RFC5444_OKAY;

  /* copy pointer to prevent writing over parameter */
  ptr = buffer;
  eob = buffer + length;

  /* initialize tlv context */
  memset(&context, 0, sizeof(context));
  context.type = RFC5444_CONTEXT_PACKET;
  context.reader = parser;

  /* read header of packet */
  first_byte = _rfc5444_get_u8(&ptr, eob, &result);
  context.pkt_version = rfc5444_get_pktversion(first_byte);
  context.pkt_flags = first_byte & RFC5444_PKT_FLAGMASK;

  if (context.pkt_version!= 0) {
    /*
     * bad packet version, do not jump to cleanup_parse packet because
     * we have not allocated any resources at this point
     */
    return RFC5444_UNSUPPORTED_VERSION;
  }

  /* check for sequence number */
  context.has_pktseqno = ((context.pkt_flags & RFC5444_PKT_FLAG_SEQNO) != 0);
  if (context.has_pktseqno) {
    context.pkt_seqno = _rfc5444_get_u16(&ptr, eob, &result);
  }

  if (result != RFC5444_OKAY) {
    /*
     * error during parsing, do not jump to cleanup_parse packet because
     * we have not allocated any resources at this point
     */
    return result;
  }

  /* initialize avl_tree */
  avl_init(&entries, avl_comp_uint32, true, NULL);
  last_started = NULL;

  /* check for packet tlv */
  has_tlv = (context.pkt_flags & RFC5444_PKT_FLAG_TLV) != 0;
  if (has_tlv) {
    result = _parse_tlvblock(parser, &entries, &ptr, eob, 0);
    if (result != RFC5444_OKAY) {
      /*
       * error while parsing TLV block, do not jump to cleanup_parse packet because
       * we have not allocated any resources at this point
       */
      return result;
    }
  }

  /* handle packet consumers, call start callbacks */
  avl_for_each_element(&parser->packet_consumer, consumer, node) {
    last_started = consumer;
    /* this one can drop a packet */
    if (consumer->start_callback != NULL) {
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      result =
#endif
          consumer->start_callback(consumer, &context);
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      if (result != RFC5444_OKAY) {
        goto cleanup_parse_packet;
      }
#endif
    }
    /* handle packet tlv consumers */
    if (has_tlv && (consumer->tlv_callback != NULL || consumer->block_callback != NULL)) {
      /* can drop packet */
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      result =
#endif
          _schedule_tlvblock(consumer, &context, &entries, 0);
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      if (result != RFC5444_OKAY) {
        goto cleanup_parse_packet;
      }
#endif
    }
  }

  /* parse messages */
  while (result == RFC5444_OKAY && ptr < eob) {
    /* can drop packet (need to be there for error handling too) */
    result = _handle_message(parser, &context, &ptr, eob);
  }

#if DISALLOW_CONSUMER_CONTEXT_DROP == false
cleanup_parse_packet:
#endif
  /* call end-of-context callback */
  if (!avl_is_empty(&parser->packet_consumer)) {
    avl_for_first_to_element_reverse(&parser->packet_consumer, last_started, consumer, node) {
      if (consumer->end_callback) {
        consumer->end_callback(consumer, &context, result != RFC5444_OKAY);
      }
    }
  }
  _free_tlvblock(parser, &entries);

  /* do not tell caller about packet drop */
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
  if (result == RFC5444_DROP_PACKET) {
    return RFC5444_OKAY;
  }
#endif
  return result;
}

/**
 * Add a packet consumer to the parser
 * @param parser pointer to parser context
 * @param consumer pointer to tlvblock consumer
 * @param entries array of tlvblock_entries
 * @param entrycount number of elements in array
 * @param order
 */
void
rfc5444_reader_add_packet_consumer(struct rfc5444_reader *parser,
    struct rfc5444_reader_tlvblock_consumer *consumer,
    struct rfc5444_reader_tlvblock_consumer_entry *entries, size_t entrycount,
    int order) {
  _add_consumer(consumer, &parser->packet_consumer, entries, entrycount, order);
}

/**
 * Add a message consumer for a single message type to
 * the parser to process the message tlvs
 * @param parser pointer to parser context
 * @param consumer pointer to tlvblock consumer
 * @param entries array of tlvblock_entries
 * @param entrycount number of elements in array
 * @param msg_id type of the message for the consumer
 * @param order priority of message consumer
 */
void
rfc5444_reader_add_message_consumer(struct rfc5444_reader *parser,
    struct rfc5444_reader_tlvblock_consumer *consumer,
    struct rfc5444_reader_tlvblock_consumer_entry *entries, size_t entrycount,
    uint8_t msg_id, int order) {
  _add_consumer(consumer, &parser->message_consumer, entries, entrycount, order);
  consumer->addrblock_consumer = false;
  consumer->msg_id = msg_id;
}

/**
 * Add a message consumer for all message types to
 * the parser to process the message tlvs
 * @param parser pointer to parser context
 * @param consumer pointer to tlvblock consumer
 * @param entries array of tlvblock_entries
 * @param entrycount number of elements in array
 * @param order priority order within message/address-consumers
 */
void
rfc5444_reader_add_defaultmsg_consumer(struct rfc5444_reader *parser,
    struct rfc5444_reader_tlvblock_consumer *consumer,
    struct rfc5444_reader_tlvblock_consumer_entry *entries, size_t entrycount,
    int order) {
  _add_consumer(consumer, &parser->message_consumer, entries, entrycount, order);
  consumer->default_msg_consumer = true;
  consumer->addrblock_consumer = false;
}

/**
 * Add a message consumer for a single message type to
 * the parser to process addresses and their tlvs
 * @param parser pointer to parser context
 * @param consumer pointer to tlvblock consumer
 * @param entries array of tlvblock_entries
 * @param entrycount number of elements in array
 * @param msg_id type of the message for the consumer
 * @param order priority of the consumer
 */
void
rfc5444_reader_add_address_consumer(struct rfc5444_reader *parser,
    struct rfc5444_reader_tlvblock_consumer *consumer,
    struct rfc5444_reader_tlvblock_consumer_entry *entries, size_t entrycount,
    uint8_t msg_id, int order) {
  _add_consumer(consumer, &parser->message_consumer, entries, entrycount, order);
  consumer->addrblock_consumer = true;
  consumer->msg_id = msg_id;
}

/**
 * Add a message consumer for all message types to
 * the parser to process addresses and their tlvs
 * @param parser pointer to parser context
 * @param consumer pointer to tlvblock consumer
 * @param entries array of tlvblock_entries
 * @param entrycount number of elements in array
 * @param order priority of the consumer
 */
void
rfc5444_reader_add_defaultaddress_consumer(struct rfc5444_reader *parser,
    struct rfc5444_reader_tlvblock_consumer *consumer,
    struct rfc5444_reader_tlvblock_consumer_entry *entries, size_t entrycount,
    int order) {
  _add_consumer(consumer, &parser->message_consumer, entries, entrycount, order);
  consumer->default_msg_consumer = true;
  consumer->addrblock_consumer = true;
}

/**
 * Remove a packet consumer from the parser
 * @param parser pointer to parser context
 * @param consumer pointer to tlvblock consumer
 */
void
rfc5444_reader_remove_packet_consumer(struct rfc5444_reader *parser,
    struct rfc5444_reader_tlvblock_consumer *consumer) {
  assert (!consumer->addrblock_consumer && consumer->msg_id == 0);
  _free_consumer(&parser->packet_consumer, consumer);
}

/**
 * Remove a message/address consumer from the parser
 * @param parser pointer to parser context
 * @param consumer pointer to tlvblock consumer
 */
void
rfc5444_reader_remove_message_consumer(struct rfc5444_reader *parser,
    struct rfc5444_reader_tlvblock_consumer *consumer) {
  _free_consumer(&parser->message_consumer, consumer);
}

/**
 * Comparator for two tlvblock consumers. addrblock_consumer field is
 * used as a tie-breaker if order is the same.
 */
static int
_consumer_avl_comp(const void *k1, const void *k2,
    void *ptr __attribute__ ((unused))) {
  const struct rfc5444_reader_tlvblock_consumer *c1 = k1;
  const struct rfc5444_reader_tlvblock_consumer *c2 = k2;

  if (c1->order > c2->order) {
    return 1;
  }
  if (c1->order < c2->order) {
    return -1;
  }
  if (c1->addrblock_consumer && !c2->addrblock_consumer) {
    return 1;
  }
  if (!c1->addrblock_consumer && c2->addrblock_consumer) {
    return -1;
  }
  return 0;
}

/**
 * Calculate internal tlvtype from type and exttype
 * @param entry pointer tlvblock entry
 * @return 256*type + exttype
 */
static int
_calc_tlvconsumer_intorder(struct rfc5444_reader_tlvblock_consumer_entry *entry) {
  return (((int)entry->type) << 8) | ((int)entry->type_ext);
}

/**
 * Calculate internal tlvtype from type and exttype
 * @param entry pointer tlvblock entry
 * @return 256*type + exttype
 */
static int
_calc_tlvblock_intorder(struct rfc5444_reader_tlvblock_entry *entry) {
  return (((int)entry->type) << 8) | ((int)entry->type_ext);
}

/**
 * Checks if two internal types have the same tlv type
 * @param int_type1 first internal type
 * @param int_type2 second internal type
 * @return true if both have the same tlv type, false otherwise
 */
static bool
_has_same_tlvtype(int int_type1, int int_type2) {
  return (int_type1 & 0xff00) == (int_type2 & 0xff00);
}

/**
 * helper function to read a single byte from a data stream
 * @param ptr pointer to pointer to begin of datastream, will be
 *   incremented by one if no error happened.
 * @param end pointer to first byte after the datastream
 * @param error pointer to result variable, will be RFC5444_ERROR
 *   if an error happened
 * @return uint8_t value of the next byte
 */
static uint8_t
_rfc5444_get_u8(uint8_t **ptr, uint8_t *end, enum rfc5444_result *error) {
  uint8_t result;
  if (*error != RFC5444_OKAY) {
    return 0;
  }
  if (*ptr >= end) {
    *error = RFC5444_END_OF_BUFFER;
    return 0;
  }

  result = **ptr;
  *ptr += 1;
  return result;
}

/**
 * helper function to read a word (2 bytes) from a data stream
 * @param ptr pointer to pointer to begin of datastream, will be
 *   incremented by two if no error happened.
 * @param end pointer to first byte after the datastream
 * @param error pointer to result variable, will be RFC5444_ERROR
 *   if an error happened
 * @return uint16_t value of the next word (network byte order)
 */
static uint16_t
_rfc5444_get_u16(uint8_t **ptr, uint8_t *end, enum rfc5444_result *error) {
  uint16_t result = _rfc5444_get_u8(ptr, end, error);
  result <<= 8;
  result += _rfc5444_get_u8(ptr, end, error);
  return result;
}

/**
 * free a list of linked tlv_block entries
 * @param entries avl_tree of tlv_block entries
 */
static void
_free_tlvblock(struct rfc5444_reader *parser, struct avl_tree *entries) {
  struct rfc5444_reader_tlvblock_entry *tlv, *ptr;

  avl_remove_all_elements(entries, tlv, node, ptr) {
    parser->free_tlvblock_entry(tlv);
  }
}

/**
 * parse a TLV into a rfc5444_reader_tlvblock_entry and advance the data stream pointer
 * @param entry pointer to rfc5444_reader_tlvblock_entry
 * @param ptr pointer to pointer to begin of datastream, will be
 *   incremented to the first byte after the TLV if no error happened.
 *   Will be set to eob if an error happened.
 * @param eob pointer to first byte after the datastream
 * @param addr_count number of addresses corresponding to tlvblock, 0 if message or
 *   packet tlv
 * @return -1 if an error happened, 0 otherwise
 */
static enum rfc5444_result
_parse_tlv(struct rfc5444_reader_tlvblock_entry *entry, uint8_t **ptr, uint8_t *eob, uint8_t addr_count) {
  enum rfc5444_result result = RFC5444_OKAY;
  uint8_t masked, count;

  /* get tlv type (without extension) and flags */
  entry->type = _rfc5444_get_u8(ptr, eob, &result);
  entry->flags = _rfc5444_get_u8(ptr, eob, &result);

  /* check for tlvtype extension */
  if ((entry->flags & RFC5444_TLV_FLAG_TYPEEXT) != 0) {
    /* type extension */
    entry->type_ext = _rfc5444_get_u8(ptr, eob, &result);
  }
  else {
    entry->type_ext = 0;
  }

  /* calculate internal combination of tlv type and extension */
  entry->int_order = _calc_tlvblock_intorder(entry);

  /* check for TLV index values */
  masked = entry->flags & (RFC5444_TLV_FLAG_SINGLE_IDX | RFC5444_TLV_FLAG_MULTI_IDX);
  if (masked == 0) {
    entry->index1 = 0;
    entry->index2 = addr_count-1;
  }
  else if (masked == RFC5444_TLV_FLAG_SINGLE_IDX) {
    entry->index1 = entry->index2 = _rfc5444_get_u8(ptr, eob, &result);
  }
  else if (masked == RFC5444_TLV_FLAG_MULTI_IDX) {
    entry->index1 = _rfc5444_get_u8(ptr, eob, &result);
    entry->index2 = _rfc5444_get_u8(ptr, eob, &result);
  }
  else {
    result = RFC5444_BAD_TLV_IDXFLAGS;
  }

  /* check for length field */
  masked = entry->flags & (RFC5444_TLV_FLAG_VALUE | RFC5444_TLV_FLAG_EXTVALUE);
  if (masked == 0) {
    entry->length = 0;
  }
  else if (masked == RFC5444_TLV_FLAG_VALUE) {
    entry->length = _rfc5444_get_u8(ptr, eob, &result);
  }
  else if (masked == (RFC5444_TLV_FLAG_EXTVALUE | RFC5444_TLV_FLAG_VALUE)) {
    entry->length = _rfc5444_get_u16(ptr, eob, &result);
  }
  else {
    result = RFC5444_BAD_TLV_VALUEFLAGS;
  }

  /* check for multivalue tlv field */
  entry->int_multivalue_tlv = (entry->flags & RFC5444_TLV_FLAG_MULTIVALUE) != 0;

  /* not enough bytes left ? */
  if (*ptr + entry->length > eob) {
    result = RFC5444_END_OF_BUFFER;
  }
  if (result != RFC5444_OKAY) {
    *ptr = eob;
    return result;
  }

  /* copy pointer to value */
  if (entry->length == 0) {
    entry->int_value = NULL;
    return RFC5444_OKAY;
  }

  entry->int_value = *ptr;
  *ptr += entry->length;

  /* handle multivalue TLVs */
  count = entry->index2 - entry->index1 + 1;
  if (count == 1) {
    entry->int_multivalue_tlv = false;
  }
  if (!entry->int_multivalue_tlv) {
    /* copy internal value pointer if no multivalue tlv */
    entry->single_value = entry->int_value;
    return RFC5444_OKAY;
  }

  if ((entry->length % count) != 0) {
    /* bad length for multi value TLV */
    return RFC5444_BAD_TLV_LENGTH;
  }
  entry->length /= count;
  return RFC5444_OKAY;
}

/**
 * parse a TLV block into a list of linked tlvblock_entries.
 * @param tlvblock pointer to avl_tree to store generates tlvblock entries
 * @param ptr pointer to pointer to begin of datastream, will be
 *   incremented to the first byte after the block if no error happened.
 *   Will be set to eob if an error happened.
 * @param eob pointer to first byte after the datastream
 * @param addr_count number of addresses corresponding to tlvblock, 0 if message or
 *   packet tlv * @return -1 if an error happened, 0 otherwise
 */
static enum rfc5444_result
_parse_tlvblock(struct rfc5444_reader *parser,
    struct avl_tree *tlvblock, uint8_t **ptr, uint8_t *eob, uint8_t addr_count) {
  enum rfc5444_result result = RFC5444_OKAY;
  struct rfc5444_reader_tlvblock_entry *tlv1 = NULL;
  struct rfc5444_reader_tlvblock_entry entry;
  uint16_t length = 0;
  uint8_t *end = NULL;

  /* get length of TLV block */
  length = _rfc5444_get_u16(ptr, eob, &result);
  end = *ptr + length;
  if (end > eob) {
    /* not enough memory for TLV block */
    result = RFC5444_END_OF_BUFFER;
    goto cleanup_parse_tlvblock;
  }

  /* clear static buffer */
  memset(&entry, 0, sizeof(entry));

  /* parse tlvs */
  while (*ptr < end) {
    /* parse next TLV into static buffer */
    if ((result = _parse_tlv(&entry, ptr, eob, addr_count)) != RFC5444_OKAY) {
      /* error while parsing TLV */
      goto cleanup_parse_tlvblock;
    }

    /* get memory to store TLV block entry */
    tlv1 = parser->malloc_tlvblock_entry();
    if (tlv1 == NULL) {
      /* not enough memory left ! */
      result = RFC5444_OUT_OF_MEMORY;
      goto cleanup_parse_tlvblock;
    }

    /* copy TLV block entry into allocated memory */
    memcpy (tlv1, &entry, sizeof(entry));

    /* put into sorted list */
    tlv1->node.key = &tlv1->int_order;
    avl_insert(tlvblock, &tlv1->node);
  }
cleanup_parse_tlvblock:
  if (result != RFC5444_OKAY) {
    _free_tlvblock(parser, tlvblock);
    *ptr = eob;
  }
  return result;
}

/**
 * Call callbacks for parsed TLV blocks
 * @param consumer pointer to first consumer for this message type
 * @param context pointer to context for tlv block
 * @param entries pointer avl_tree of tlv block entries
 * @param index of current address inside the addressblock, 0 for message tlv block
 * @return RFC5444_TLV_DROP_ADDRESS if the current address should
 *   be dropped for later consumers, RFC5444_TLV_DROP_CONTEXT if
 *   the complete message/package should be dropped for
 *   later consumers, 0 if no error happened
 */
static enum rfc5444_result
_schedule_tlvblock(struct rfc5444_reader_tlvblock_consumer *consumer, struct rfc5444_reader_tlvblock_context *context,
    struct avl_tree *entries, uint8_t idx) {
  struct rfc5444_reader_tlvblock_entry *tlv = NULL;
  struct rfc5444_reader_tlvblock_consumer_entry *cons_entry;
  bool constraints_failed;
  int cons_order, tlv_order;
  enum rfc5444_result result = RFC5444_OKAY;

  constraints_failed = false;

  /* initialize tlv pointers, there must be TLVs */
  if (avl_is_empty(entries)) {
    tlv = NULL;
    tlv_order = TLVTYPE_ORDER_INFINITE;
  }
  else {
    tlv = avl_first_element(entries, tlv, node);
    tlv_order = tlv->int_order;
  }

  /* initialize consumer pointer */
  if (list_is_empty(&consumer->_consumer_list)) {
    cons_entry = NULL;
    cons_order = TLVTYPE_ORDER_INFINITE;
  }
  else {
    cons_entry = list_first_element(&consumer->_consumer_list, cons_entry, _node);
    cons_order = _calc_tlvconsumer_intorder(cons_entry);
    cons_entry->tlv = NULL;
    cons_entry->duplicate_tlv = false;
  }

  /* we are running in parallel through two sorted lists */
  while (cons_entry != NULL || tlv != NULL) {
    bool match = false;
    bool index_match = false;

    if (tlv) {
      index_match = RFC5444_CONSUMER_DROP_ONLY(!_test_addrbitarray(&tlv->int_drop_tlv, idx), true)
          && idx >= tlv->index1 && idx <= tlv->index2;
    }

    /* check index for address blocks */
    if (tlv != NULL && cons_entry != NULL && index_match) {
      /* calculate match between tlv and consumer */
      if (cons_entry->match_type_ext) {
        match = cons_order == tlv_order;
      }
      else {
        match = _has_same_tlvtype(cons_order, tlv_order);
      }
    }

    if (index_match && tlv->int_multivalue_tlv) {
      size_t offset;

      /* calculate value pointer for multivalue tlv */
      offset = (idx - tlv->index1) * tlv->length;
      tlv->single_value = &tlv->int_value[offset];
    }

    /* handle tlv_callback first */
    if (index_match && consumer->tlv_callback != NULL) {
      /* call consumer for TLV, can skip tlv, address, message and packet */
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      result =
#endif
          consumer->tlv_callback(consumer, tlv, context);
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      if (result == RFC5444_DROP_TLV) {
        /* mark dropped tlv */
        _set_addr_bitarray(&tlv->int_drop_tlv, idx);
        match = false;
        /* do not propagate result */
        result = RFC5444_OKAY;
      }
      else if (result != RFC5444_OKAY) {
        /* stop processing this TLV block/address/message/packet */
        goto cleanup_handle_tlvblock;
      }
#endif
    }

    /* run through both sorted lists until finding a match */
    if (cons_order <= tlv_order) {
      constraints_failed |= cons_entry->mandatory && !match;

      if (match) {
        if (cons_entry->match_length &&
            (tlv->length < cons_entry->min_length
                || tlv->length > cons_entry->max_length)) {
          constraints_failed = true;
        }

        if (cons_entry->tlv == NULL) {
          /* remember new tlv */
          cons_entry->tlv = tlv;

          if (cons_entry->copy_value != NULL && tlv->length > 0) {
            /* copy value into private buffer */
            uint16_t len = cons_entry->max_length;

            if (tlv->length < len) {
              len = tlv->length;
            }
            memcpy(cons_entry->copy_value, tlv->single_value, len);
          }
        }
        else {
          cons_entry->duplicate_tlv = true;
        }
      }
    }
    if (tlv_order <= cons_order && tlv != NULL) {
      /* advance tlv pointer */
      if (avl_is_last(entries, &tlv->node)) {
        tlv = NULL;
        tlv_order = TLVTYPE_ORDER_INFINITE;
      }
      else {
        tlv = avl_next_element(tlv, node);
        tlv_order = tlv->int_order;
      }
    }
    if (cons_order < tlv_order) {
      constraints_failed |= cons_entry->mandatory && !match;

      /* advance consumer pointer */
      if (list_is_last(&consumer->_consumer_list, &cons_entry->_node)) {
        cons_entry = NULL;
        cons_order = TLVTYPE_ORDER_INFINITE;
      }
      else {
        cons_entry = list_next_element(cons_entry, _node);
        cons_order = _calc_tlvconsumer_intorder(cons_entry);
        cons_entry->tlv = NULL;
        cons_entry->duplicate_tlv = false;
      }
    }
  }

  /* call consumer for tlvblock */
  if (consumer->block_callback != NULL && !constraints_failed) {
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
    result =
#endif
        consumer->block_callback(consumer, context);
  }
  else if (consumer->block_callback_failed_constraints != NULL && constraints_failed) {
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
    result =
#endif
        consumer->block_callback_failed_constraints(consumer, context);
  }
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
  if (result == RFC5444_DROP_TLV) {
    list_for_each_element(&consumer->_consumer_list, cons_entry, _node) {
      if (cons_entry->tlv != NULL && cons_entry->drop) {
        _set_addr_bitarray(&cons_entry->tlv->int_drop_tlv, idx);
        cons_entry->drop = false;
      }
    }

    /* do not propagate tlv drops */
    result = RFC5444_OKAY;
  }
#endif
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
cleanup_handle_tlvblock:
#endif
#if  DEBUG_CLEANUP == true
  list_for_each_element(&consumer->_consumer_list, cons_entry, _node) {
    cons_entry->tlv = NULL;
    cons_entry->drop = false;
  }
#endif

  return result;
}

/**
 * parse an address block and put it into an addrblock entry
 * @param addr_entry pointer to rfc5444_reader_addrblock_entry to store the data
 * @param tlv_context pointer to context
 * @param ptr pointer to pointer to begin of datastream, will be
 *   incremented to the first byte after the block if no error happened.
 *   Will be set to eob if an error happened.
 * @param eob pointer to first byte after the datastream
 * @return -1 if an error happened, 0 otherwise
 */
static enum rfc5444_result
_parse_addrblock(struct rfc5444_reader_addrblock_entry *addr_entry,
    struct rfc5444_reader_tlvblock_context *tlv_context, uint8_t **ptr, uint8_t *eob) {
  enum rfc5444_result result = RFC5444_OKAY;
  uint8_t flags;
  uint8_t tail_len;
  uint8_t masked;

  /* read addressblock header */
  addr_entry->num_addr = _rfc5444_get_u8(ptr, eob, &result);
  if (addr_entry->num_addr == 0) {
    /* no addresses. */
    return RFC5444_EMPTY_ADDRBLOCK;
  }

  flags = _rfc5444_get_u8(ptr, eob, &result);

  /* initialize head/tail of address */
  memset(addr_entry->addr, 0, tlv_context->addr_len);
  addr_entry->mid_len = tlv_context->addr_len;

  /* check for head flag */
  if ((flags & RFC5444_ADDR_FLAG_HEAD) != 0) {
    addr_entry->mid_start = _rfc5444_get_u8(ptr, eob, &result);
    if (*ptr + addr_entry->mid_start > eob) {
      /* not enough buffer for head */
      return RFC5444_END_OF_BUFFER;
    }

    /* copy address head into buffer */
    memcpy(addr_entry->addr, *ptr, addr_entry->mid_start);
    addr_entry->mid_len -= addr_entry->mid_start;
    *ptr += addr_entry->mid_start;
  }

  /* check for tail flags */
  masked = flags & (RFC5444_ADDR_FLAG_FULLTAIL | RFC5444_ADDR_FLAG_ZEROTAIL);
  if (masked == RFC5444_ADDR_FLAG_ZEROTAIL) {
    addr_entry->mid_len -= _rfc5444_get_u8(ptr, eob, &result);
  }
  else if (masked == RFC5444_ADDR_FLAG_FULLTAIL) {
    tail_len = _rfc5444_get_u8(ptr, eob, &result);
    if (*ptr + tail_len > eob) {
      /* not enough buffer for head */
      return RFC5444_END_OF_BUFFER;
    }

    /* copy address tail into buffer */
    memcpy(addr_entry->addr + tlv_context->addr_len - tail_len, *ptr, tail_len);
    addr_entry->mid_len -= tail_len;
    *ptr += tail_len;
  }
  else if (masked != 0) {
    return RFC5444_BAD_MSG_TAILFLAGS;
  }

  /* store mid part of addresses */
  addr_entry->mid_src = *ptr;
  *ptr += (addr_entry->mid_len * addr_entry->num_addr);
  if (*ptr > eob) {
    return RFC5444_END_OF_BUFFER;
  }

  /* check for prefix flags */
  masked = flags & (RFC5444_ADDR_FLAG_SINGLEPLEN | RFC5444_ADDR_FLAG_MULTIPLEN);
  if (masked == 0) {
    addr_entry->prefixlen = tlv_context->addr_len * 8;
  }
  else if (masked == RFC5444_ADDR_FLAG_SINGLEPLEN) {
    addr_entry->prefixlen = **ptr;
    *ptr += 1;
  }
  else if (masked == RFC5444_ADDR_FLAG_MULTIPLEN) {
    addr_entry->prefixes = *ptr;
    *ptr += addr_entry->num_addr;
  }
  else {
    return RFC5444_BAD_MSG_PREFIXFLAGS;
  }

  /* check for error */
  if (*ptr > eob) {
    return RFC5444_END_OF_BUFFER;
  }
  return result;
}

/**
 * Call start and tlvblock callbacks for message tlv consumer
 * @param consumer pointer to tlvblock consumer object
 * @param tlv_context current tlv context
 * @param tlv_entries pointer to tlventry avltree
 * @return RFC5444_OKAY if no error happend, RFC5444_DROP_ if a
 *   context (message or packet) should be dropped
 */
static enum rfc5444_result
schedule_msgtlv_consumer(struct rfc5444_reader_tlvblock_consumer *consumer,
    struct rfc5444_reader_tlvblock_context *tlv_context, struct avl_tree *tlv_entries) {
  enum rfc5444_result result = RFC5444_OKAY;
  tlv_context->type = RFC5444_CONTEXT_MESSAGE;

  /* call start-of-context callback */
  if (consumer->start_callback) {
    /* could drop tlv, message or packet */
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
    result =
#endif
        consumer->start_callback(consumer, tlv_context);
  }

  /* call consumer for message tlv block */
  if (RFC5444_CONSUMER_DROP_ONLY(result == RFC5444_OKAY, true)) {
    /* could drop message or packet */
    result = _schedule_tlvblock(consumer, tlv_context, tlv_entries, 0);
  }
  return result;
}

/**
 * Call callbacks for address tlv consumer
 * @param consumer pointer to tlvblock consumer object
 * @param tlv_context current tlv context
 * @param addr_head pointer to list of address block objects
 * @return RFC5444_OKAY if no error happend, RFC5444_DROP_ if a
 *   context (message or packet) should be dropped
 */
static enum rfc5444_result
schedule_msgaddr_consumer(struct rfc5444_reader_tlvblock_consumer *consumer,
    struct rfc5444_reader_tlvblock_context *tlv_context, struct list_entity *addr_head) {
  struct rfc5444_reader_addrblock_entry *addr;
  enum rfc5444_result result = RFC5444_OKAY;

  tlv_context->type = RFC5444_CONTEXT_ADDRESS;

  /* consume address tlv block(s) */
  /* iterate over all address blocks */
  list_for_each_element(addr_head, addr, list_node) {
    uint8_t i;

    /* iterate over all addresses in block */
    tlv_context->prefixlen = addr->prefixlen;
    for (i=0; i<addr->num_addr; i++) {
      /* test if we should skip this address */
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      if (_test_addrbitarray(&addr->dropAddr, i)) {
        continue;
      }
#endif

      /* assemble address for context */
      tlv_context->addr = addr->addr;
      memcpy(&addr->addr[addr->mid_start], &addr->mid_src[addr->mid_len * i], addr->mid_len);

      /* copy prefixlen if necessary */
      if (addr->prefixes) {
        tlv_context->prefixlen = addr->prefixes[i];
      }

      /* call start-of-context callback */
      if (consumer->start_callback) {
        /* can drop address, addressblock, message and packet */
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
        result =
#endif
            consumer->start_callback(consumer, tlv_context);
      }

      /* handle tlvblock callbacks */
      if (RFC5444_CONSUMER_DROP_ONLY(result == RFC5444_OKAY, true)) {
        result = _schedule_tlvblock(consumer, tlv_context, &addr->tlvblock, i);
      }

      /* call end-of-context callback */
      if (consumer->end_callback) {
        enum rfc5444_result r;
        r = consumer->end_callback(consumer, tlv_context, result != RFC5444_OKAY);
        if (r > result) {
          result = r;
        }
      }

#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      /* handle result from tlvblock callbacks */
      if (result == RFC5444_DROP_ADDRESS) {
        _set_addr_bitarray(&addr->dropAddr, i);
        result = RFC5444_OKAY;
      }
      else if (result != RFC5444_OKAY) {
        return result;
      }
#endif
    }
  }
  return result;
}

/**
 * Call end callbacks for message tlvblock consumer.
 * @param tlv_context context of current tlvblock
 * @param first begin of range of consumers which should be called
 * @param last end of range of consumers which should be called
 * @param result current 'drop context' level
 * @return new 'drop context level'
 */
static enum rfc5444_result
schedule_end_message_cbs(struct rfc5444_reader_tlvblock_context *tlv_context,
    struct rfc5444_reader_tlvblock_consumer *first, struct rfc5444_reader_tlvblock_consumer *last,
    enum rfc5444_result result) {
  struct rfc5444_reader_tlvblock_consumer *consumer;
  enum rfc5444_result r;

  tlv_context->type = RFC5444_CONTEXT_MESSAGE;

  avl_for_element_range_reverse(first, last, consumer, node) {
    if (consumer->end_callback
        && (consumer->default_msg_consumer || consumer->msg_id == tlv_context->msg_type)) {
      r = consumer->end_callback(consumer, tlv_context, result != RFC5444_OKAY);
      if (r > result) {
        result = r;
      }
    }
  }
  return result;
}
/**
 * parse a message including tlvblocks and addresses,
 * then calls the callbacks for everything inside
 * @param parser pointer to parser context
 * @param tlv_context pointer to tlv context
 * @param ptr pointer to pointer to begin of datastream, will be
 *   incremented to the first byte after the message if no error happened.
 *   Will be set to eob if an error happened.
 * @param eob pointer to first byte after the datastream
 * @return -1 if an error happened, 0 otherwise
 */
static enum rfc5444_result
_handle_message(struct rfc5444_reader *parser,
    struct rfc5444_reader_tlvblock_context *tlv_context, uint8_t **ptr, uint8_t *eob) {
  struct avl_tree tlv_entries;
  struct rfc5444_reader_tlvblock_consumer *consumer, *same_order[2];
  struct list_entity addr_head;
  struct rfc5444_reader_addrblock_entry *addr, *safe;
  uint8_t *start, *end = NULL;
  uint8_t flags;
  uint16_t size;

  enum rfc5444_result result;

  /* initialize variables */
  result = RFC5444_OKAY;
  same_order[0] = same_order[1] = NULL;
  avl_init(&tlv_entries, avl_comp_uint16, true, NULL);
  list_init_head(&addr_head);

  /* remember start of message */
  start = *ptr;

  /* parse message header */
  tlv_context->msg_type = _rfc5444_get_u8(ptr, eob, &result);
  flags = _rfc5444_get_u8(ptr, eob, &result);
  size = _rfc5444_get_u16(ptr, eob, &result);

  tlv_context->addr_len = (flags & RFC5444_MSG_FLAG_ADDRLENMASK) + 1;
  tlv_context->msg_flags = (flags & ~RFC5444_MSG_FLAG_ADDRLENMASK);

  /* test for originator address */
  tlv_context->has_origaddr = (flags & RFC5444_MSG_FLAG_ORIGINATOR) != 0;
  if (tlv_context->has_origaddr) {
    if ((*ptr + tlv_context->addr_len) > eob) {
      result = RFC5444_END_OF_BUFFER;
      goto cleanup_parse_message;
    }

    memcpy(tlv_context->orig_addr, *ptr, tlv_context->addr_len);
    *ptr += tlv_context->addr_len;
  }

  /* test for hop limit */
  tlv_context->has_hoplimit = (flags & RFC5444_MSG_FLAG_HOPLIMIT) != 0;
  if (tlv_context->has_hoplimit) {
    tlv_context->hoplimit = _rfc5444_get_u8(ptr, eob, &result);
  }

  /* test for hopcount */
  tlv_context->has_hopcount = (flags & RFC5444_MSG_FLAG_HOPCOUNT) != 0;
  if (tlv_context->has_hopcount) {
    tlv_context->hopcount = _rfc5444_get_u8(ptr, eob, &result);
  }

  /* test for sequence number */
  tlv_context->has_seqno = (flags & RFC5444_MSG_FLAG_SEQNO) != 0;
  if (tlv_context->has_seqno) {
    tlv_context->seqno = _rfc5444_get_u16(ptr, eob, &result);
  }

  /* check for error during header parsing or bad length */
  end = start + size;
  if (end > eob) {
    *ptr = eob;
    result = RFC5444_END_OF_BUFFER;
  }
  if (result != RFC5444_OKAY) {
    goto cleanup_parse_message;
  }

  /* parse message TLV block */
  result = _parse_tlvblock(parser, &tlv_entries, ptr, end, 0);
  if (result != RFC5444_OKAY) {
    /* error while allocating tlvblock data */
    goto cleanup_parse_message;
  }

  /* parse rest of message */
  while (*ptr < end) {
    /* get memory for storing the address block entry */
    addr = parser->malloc_addrblock_entry();
    if (addr == NULL) {
      result = RFC5444_OUT_OF_MEMORY;
      goto cleanup_parse_message;
    }

    /* initialize avl_tree */
    avl_init(&addr->tlvblock, avl_comp_uint16, true, NULL);

    /* parse address block... */
    if ((result = _parse_addrblock(addr, tlv_context, ptr, end)) != RFC5444_OKAY) {
      parser->free_addrblock_entry(addr);
      goto cleanup_parse_message;
    }

    /* ... and corresponding tlvblock */
    result = _parse_tlvblock(parser, &addr->tlvblock, ptr, end, addr->num_addr);
    if (result != RFC5444_OKAY) {
      parser->free_addrblock_entry(addr);
      goto cleanup_parse_message;
    }

    list_add_tail(&addr_head, &addr->list_node);
  }

  /* loop through list of message consumers */
  avl_for_each_element(&parser->message_consumer, consumer, node) {
    if (!consumer->default_msg_consumer && consumer->msg_id != tlv_context->msg_type) {
      /* wrong type of message, continue... */
      continue;
    }

    /* remember range of consumers with same order to call end_message() callbacks */
    if (same_order[0] != NULL && consumer->order > same_order[1]->order) {
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      result =
#endif
      schedule_end_message_cbs(tlv_context,
          same_order[0], same_order[1], result);
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      if (result != RFC5444_OKAY) {
        goto cleanup_parse_message;
      }
#endif
      same_order[0] = NULL;
    }

    if (consumer->addrblock_consumer) {
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      result =
#endif
      schedule_msgaddr_consumer(consumer, tlv_context, &addr_head);
    }
    else {
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      result =
#endif
      schedule_msgtlv_consumer(consumer, tlv_context, &tlv_entries);
      if (same_order[0] == NULL) {
        same_order[0] = consumer;
      }
      same_order[1] = consumer;
    }

#if DISALLOW_CONSUMER_CONTEXT_DROP == false
    if (result != RFC5444_OKAY) {
      break;
    }
#endif
  }

  /* handle last end_message() callback range */
  if (same_order[0] != NULL) {
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
    result =
#endif
    schedule_end_message_cbs(tlv_context,
        same_order[0], same_order[1], result);
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
    if (result != RFC5444_OKAY) {
      goto cleanup_parse_message;
    }
#endif
  }

cleanup_parse_message:
  /* handle message forwarding */
  if (
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
      (result == RFC5444_OKAY || result == RFC5444_DROP_MSG_BUT_FORWARD) &&
#endif
      parser->forward_message != NULL && tlv_context->has_hopcount) {
    uint8_t limit = tlv_context->has_hoplimit ? tlv_context->hoplimit : 255;

    /* check hopcount */
    if (tlv_context->hopcount < limit -1) {
      /* forward message if callback is available */
      tlv_context->type = RFC5444_CONTEXT_MESSAGE;
      parser->forward_message(tlv_context, start, end - start);
    }
  }

  /* free address tlvblocks */
  list_for_each_element_safe(&addr_head, addr, list_node, safe) {
    _free_tlvblock(parser, &addr->tlvblock);
    parser->free_addrblock_entry(addr);
  }

  /* free message tlvblock */
  _free_tlvblock(parser, &tlv_entries);
  *ptr = end;
#if DISALLOW_CONSUMER_CONTEXT_DROP == false
  if (result == RFC5444_DROP_MESSAGE) {
    /* do not propagate message drop */
    return RFC5444_OKAY;
  }
#endif
  return result;
}

/**
 * Add a tlvblock consumer to a linked list of consumers.
 * The list is kept sorted by the order of the consumers.
 * @param parser pointer to parser context
 * @param consumer_tree pointer to tree of consumers
 * @param entries pointer to rfc5444_reader_tlvblock_consumer_entry array
 * @param entrycount number of elements in array
 * @param order order of the consumer
 * @return pointer to rfc5444_reader_tlvblock_consumer,
 *   NULL if an error happened
 */
static struct rfc5444_reader_tlvblock_consumer *
_add_consumer(struct rfc5444_reader_tlvblock_consumer *consumer, struct avl_tree *consumer_tree,
    struct rfc5444_reader_tlvblock_consumer_entry *entries, int entrycount, int order) {
  struct rfc5444_reader_tlvblock_consumer_entry *e;
  int i, o;
  bool set;

  list_init_head(&consumer->_consumer_list);

  /* generate sorted list of entries */
  for (i=0; i<entrycount; i++) {
    o = _calc_tlvconsumer_intorder(&entries[i]);

    if (i == 0) {
      list_add_tail(&consumer->_consumer_list, &entries[i]._node);
    }
    else {
      set = false;
      list_for_each_element_reverse(&consumer->_consumer_list, e, _node) {
        if (_calc_tlvconsumer_intorder(e) <= o) {
          list_add_after(&e->_node, &entries[i]._node);
          set = true;
          break;
        }
      }
      if (!set) {
        list_add_head(&consumer->_consumer_list, &entries[i]._node);
      }
    }

    if (entries[i].min_length > entries[i].max_length) {
      entries[i].max_length = entries[i].min_length;
    }
  }

  /* initialize order */
  consumer->order = order;

  /* insert into global list of consumers */
  consumer->node.key = consumer;
  avl_insert(consumer_tree, &consumer->node);
  return consumer;
}

/**
 * Free a rfc5444_reader_tlvblock_consumer and remove it from its linked list
 * @param parser pointer to parser context
 * @param listhead pointer to listhead pointer
 * @param consumer pointer to rfc5444_reader_tlvblock_consumer
 */
static void
_free_consumer(struct avl_tree *consumer_tree,
    struct rfc5444_reader_tlvblock_consumer *consumer) {
  /* remove consumer from tree */
  if (avl_is_node_added(&consumer->node)) {
    avl_remove(consumer_tree, &consumer->node);
  }
}

/**
 * Internal memory allocation function for addrblock
 * @return pointer to cleared addrblock
 */
static struct rfc5444_reader_addrblock_entry *
_malloc_addrblock_entry(void) {
  return calloc(1, sizeof(struct rfc5444_reader_addrblock_entry));
}

/**
 * Internal memory allocation function for rfc5444_reader_tlvblock_entry
 * @return pointer to cleared rfc5444_reader_tlvblock_entry
 */
static struct rfc5444_reader_tlvblock_entry *
_malloc_tlvblock_entry(void) {
  return calloc(1, sizeof(struct rfc5444_reader_tlvblock_entry));
}

/**
 * @param v first byte of packet header
 * @return packet header version
 */
static uint8_t
rfc5444_get_pktversion(uint8_t v) {
  return v >> 4;
}

#if DISALLOW_CONSUMER_CONTEXT_DROP == false
/**
 * Set a bit in the bitarray256 struct
 * @param b pointer to bitarray
 * @param idx index of bit (0-255)
 */
static void
_set_addr_bitarray(struct rfc5444_reader_bitarray256 *b, int idx) {
  b->a[idx >> 5] |= (1 << (idx & 31));
}

/**
 * Test a bit in the bitarray256 struct
 * @param b pointer to bitarray
 * @param idx index of bit (0-255)
 * @return true if bit was set, false otherwise
 */
static bool
_test_addrbitarray(struct rfc5444_reader_bitarray256 *b, int idx) {
  return 0 != (b->a[idx >> 5] & (1 << (idx & 31)));
}
#endif
