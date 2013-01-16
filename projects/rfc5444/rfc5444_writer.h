
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

#ifndef RFC5444_WRITER_H_
#define RFC5444_WRITER_H_

struct rfc5444_writer;
struct rfc5444_writer_message;

#include "sys/common/avl.h"
#include "sys/common/common_types.h"
#include "sys/common/list.h"
#include "rfc5444/rfc5444_context.h"
#include "rfc5444/rfc5444_tlv_writer.h"

/*
 * Macros to iterate over existing addresses in a message(fragment)
 * during message generation (finishMessageHeader/finishMessageTLVs
 * callbacks)
 */
#define for_each_fragment_address(first, last, address, loop) list_for_element_range(first, last, address, addr_node, loop)
#define for_each_message_address(message, address, loop) list_for_each_element(&message->addr_head, address, addr_node, loop)

/**
 * state machine values for the writer.
 * If compiled with WRITE_STATE_MACHINE, this can check if the functions
 * of the writer are called from the right context.
 */
enum rfc5444_internal_state {
  RFC5444_WRITER_NONE,
  RFC5444_WRITER_ADD_PKTHEADER,
  RFC5444_WRITER_ADD_PKTTLV,
  RFC5444_WRITER_ADD_HEADER,
  RFC5444_WRITER_ADD_MSGTLV,
  RFC5444_WRITER_ADD_ADDRESSES,
  RFC5444_WRITER_FINISH_MSGTLV,
  RFC5444_WRITER_FINISH_HEADER,
  RFC5444_WRITER_FINISH_PKTTLV,
  RFC5444_WRITER_FINISH_PKTHEADER
};

/**
 * This INTERNAL struct represents a single address tlv
 * of an address during message serialization.
 */
struct rfc5444_writer_addrtlv {
  /* tree _if_node of tlvs of a certain type/exttype */
  struct avl_node tlv_node;

  /* backpointer to tlvtype */
  struct rfc5444_writer_tlvtype *tlvtype;

  /* tree _if_node of tlvs used by a single address */
  struct avl_node addrtlv_node;

  /* backpointer to address */
  struct rfc5444_writer_address *address;

  /* tlv type and extension is stored in writer_tlvtype */

  /* tlv value length */
  uint16_t length;

  /*
   * if multiple tlvs with the same type/ext have the same
   * value for a continous block of addresses, they should
   * use the same storage for the value (the pointer should
   * be the same)
   */
  void *value;

  /*
   * true if the TLV has the same length/value for the
   * address before this one too
   */
  bool same_length;
  bool same_value;
};

/**
 * This struct represents a single address during the pbb
 * message creation.
 */
struct rfc5444_writer_address {
  /* index of the address */
  int index;

  /* address/prefix */
  uint8_t addr[RFC5444_MAX_ADDRLEN];
  uint8_t prefixlen;

  /* node of address list in writer_message */
  struct list_entity _addr_node;

  /* node for quick access ( O(log n)) to addresses */
  struct avl_node _addr_tree_node;

  /* tree to connect all TLVs of this address */
  struct avl_tree _addrtlv_tree;

  /* address block with same prefix/prefixlen until certain address */
  struct rfc5444_writer_address *_block_end;
  uint8_t _block_headlen;
  bool _block_multiple_prefixlen;

  /* handle mandatory addresses for message fragmentation */
  bool _mandatory_addr;
  bool _done;
};

/**
 * This INTERNAL struct is preallocated for each tlvtype that can be added
 * to an address of a certain message type.
 */
struct rfc5444_writer_tlvtype {
  /* tlv type and extension is stored in writer_tlvtype */
  uint8_t type;

  /* tlv extension type */
  uint8_t exttype;

  /* _if_node of tlvtype list in rfc5444_writer_message */
  struct list_entity _tlvtype_node;

  /* back pointer to message _creator */
  struct rfc5444_writer_message *_creator;

  /* number of users of this tlvtype */
  int _usage_counter;

  /* head of writer_addrtlv list */
  struct avl_tree _tlv_tree;

  /* tlv type*256 + tlv_exttype */
  int _full_type;

  /* internal data for address compression */
  int _tlvblock_count[RFC5444_MAX_ADDRLEN];
  bool _tlvblock_multi[RFC5444_MAX_ADDRLEN];
};

/**
 * Struct to define a list of address TLVs that should be preallocated
 * for a certain message type
 */
struct rfc5444_writer_addrtlv_block {
  struct rfc5444_writer_tlvtype *_tlvtype;

  uint8_t type;
  uint8_t exttype;
};

/**
 * This struct represents a single content provider of
 * tlvs for a message context.
 */
struct rfc5444_writer_content_provider {
  /* priority of content provider */
  int priority;

  /* message type for this content provider */
  uint8_t msg_type;

  /* callbacks for adding tlvs and addresses to a message */
  void (*addMessageTLVs)(struct rfc5444_writer *,
    struct rfc5444_writer_content_provider *);
  void (*addAddresses)(struct rfc5444_writer *,
    struct rfc5444_writer_content_provider *);
  void (*finishMessageTLVs)(struct rfc5444_writer *,
    struct rfc5444_writer_content_provider *, struct rfc5444_writer_address *,
    struct rfc5444_writer_address *, bool);

  /* node for tree of content providers for a message creator */
  struct avl_node _provider_node;

  /* back pointer to message _creator */
  struct rfc5444_writer_message *_creator;
};

/**
 * This struct is allocated for each message type that can
 * be generated by the writer.
 */
struct rfc5444_writer_message {
  /* _if_node for tree of message creators */
  struct avl_node _msgcreator_node;

  /* tree of message content providers */
  struct avl_tree _provider_tree;

  /*
   * true if the creator has already registered
   * false if the creator was registered because of a tlvtype or content
   * provider registration
   */
  bool _registered;

  /* true if a different message must be generated for each interface */
  bool if_specific;

  /*
   * back pointer for interface this message is generated,
   * only used for interface specific message types
   */
  struct rfc5444_writer_interface *specific_if;

  /* message type */
  uint8_t type;

  /* message address length */
  uint8_t addr_len;

  /* message hopcount */
  bool has_hopcount;
  uint8_t hopcount;

  /* message hoplimit */
  bool has_hoplimit;
  uint8_t hoplimit;

  /* message originator */
  bool has_origaddr;
  uint8_t orig_addr[RFC5444_MAX_ADDRLEN];

  /* message sequence number */
  uint16_t seqno;
  bool has_seqno;

  /* head of writer_address list/tree */
  struct list_entity _addr_head;
  struct avl_tree _addr_tree;

  /* head of writer_tlvtype list */
  struct list_entity _tlvtype_head;

  /* callbacks for controling the message header fields */
  void (*addMessageHeader)(struct rfc5444_writer *, struct rfc5444_writer_message *);
  void (*finishMessageHeader)(struct rfc5444_writer *, struct rfc5444_writer_message *,
      struct rfc5444_writer_address *, struct rfc5444_writer_address *, bool);

  /* number of bytes necessary for addressblocks including tlvs */
  size_t _bin_addr_size;

  /* custom user data */
  void *user;
};

/**
 * This struct represents a single outgoing interface for
 * the pbb writer
 */
struct rfc5444_writer_interface {
  /* buffer for packet generation */
  uint8_t *packet_buffer;

  /* maximum number of bytes per packets allowed for interface */
  size_t packet_size;

  /* stores the last sequence number going through this interface */
  uint16_t last_seqno;

  /* callback for interface specific packet handling */
  void (*addPacketHeader)(struct rfc5444_writer *, struct rfc5444_writer_interface *);
  void (*finishPacketHeader)(struct rfc5444_writer *, struct rfc5444_writer_interface *);
  void (*sendPacket)(struct rfc5444_writer *, struct rfc5444_writer_interface *, void *, size_t);

  /* internal handling for packet sequence numbers */
  uint16_t _seqno;
  bool _has_seqno;

  /* _if_node for list of all _interfaces */
  struct list_entity _if_node;

  /* packet buffer is currently flushed */
  bool _is_flushed;

  /* buffer for constructing the current packet */
  struct rfc5444_tlv_writer_data _pkt;

  /* number of bytes used by messages */
  size_t _bin_msgs_size;
};

/**
 * This struct represents a content provider for adding
 * tlvs to a packet header.
 */
struct rfc5444_writer_pkthandler {
  /* _if_node for list of packet handlers */
  struct list_entity _pkthandle_node;

  /* callbacks for packet handler */
  void (*addPacketTLVs)(struct rfc5444_writer *, struct rfc5444_writer_interface *);
  void (*finishPacketTLVs)(struct rfc5444_writer *, struct rfc5444_writer_interface *);
};

/**
 * This struct represents the internal state of a
 * rfc5444 writer.
 */
struct rfc5444_writer {
  /* buffer for messages */
  uint8_t *msg_buffer;

  /* length of message buffer */
  size_t msg_size;

  /* buffer for addrtlv values of a message */
  uint8_t *addrtlv_buffer;
  size_t addrtlv_size;

  /* callbacks for memory management, NULL for calloc()/free() */
  struct rfc5444_writer_address* (*malloc_address_entry)(void);
  struct rfc5444_writer_addrtlv* (*malloc_addrtlv_entry)(void);

  void (*free_address_entry)(void *);
  void (*free_addrtlv_entry)(void *);

  /* tree of all message handlers */
  struct avl_tree _msgcreators;

  /* list of all packet handlers */
  struct list_entity _pkthandlers;

  /* list of all _interfaces */
  struct list_entity _interfaces;

  /* buffer for constructing the current message */
  struct rfc5444_tlv_writer_data _msg;

  /* number of bytes of addrtlv buffer currently used */
  size_t _addrtlv_used;

  /* internal state of writer */
  enum rfc5444_internal_state _state;
};

/* functions that can be called from addAddress callback */
EXPORT struct rfc5444_writer_address *rfc5444_writer_add_address(struct rfc5444_writer *writer,
    struct rfc5444_writer_message *msg, const void *addr, uint8_t prefix, bool mandatory);
EXPORT enum rfc5444_result rfc5444_writer_add_addrtlv(struct rfc5444_writer *writer,
    struct rfc5444_writer_address *addr, struct rfc5444_writer_tlvtype *tlvtype,
    const void *value, size_t length, bool allow_dup);

/* functions that can be called from add/finishMessageTLVs callback */
EXPORT enum rfc5444_result rfc5444_writer_add_messagetlv(struct rfc5444_writer *writer,
    uint8_t type, uint8_t exttype, const void *value, size_t length);
EXPORT enum rfc5444_result rfc5444_writer_allocate_messagetlv(struct rfc5444_writer *writer,
    bool has_exttype, size_t length);
EXPORT enum rfc5444_result rfc5444_writer_set_messagetlv(struct rfc5444_writer *writer,
    uint8_t type, uint8_t exttype, const void *value, size_t length);

/* functions that can be called from add/finishMessageHeader callback */
EXPORT void rfc5444_writer_set_msg_addrlen(struct rfc5444_writer *writer,
    struct rfc5444_writer_message *msg, uint8_t addrlen);
EXPORT void rfc5444_writer_set_msg_header(struct rfc5444_writer *writer,
    struct rfc5444_writer_message *msg, bool has_originator,
    bool has_hopcount, bool has_hoplimit, bool has_seqno);
EXPORT void rfc5444_writer_set_msg_originator(struct rfc5444_writer *writer,
    struct rfc5444_writer_message *msg, const void *originator);
EXPORT void rfc5444_writer_set_msg_hopcount(struct rfc5444_writer *writer,
    struct rfc5444_writer_message *msg, uint8_t hopcount);
EXPORT void rfc5444_writer_set_msg_hoplimit(struct rfc5444_writer *writer,
    struct rfc5444_writer_message *msg, uint8_t hoplimit);
EXPORT void rfc5444_writer_set_msg_seqno(struct rfc5444_writer *writer,
    struct rfc5444_writer_message *msg, uint16_t seqno);

/* functions that can be called from add/finishPacketTLVs callback */
EXPORT enum rfc5444_result rfc5444_writer_add_packettlv(
    struct rfc5444_writer *writer, struct rfc5444_writer_interface *interf,
    uint8_t type, uint8_t exttype, void *value, size_t length);
EXPORT enum rfc5444_result rfc5444_writer_allocate_packettlv(
    struct rfc5444_writer *writer, struct rfc5444_writer_interface *interf,
    bool has_exttype, size_t length);
EXPORT enum rfc5444_result rfc5444_writer_set_packettlv(
    struct rfc5444_writer *writer, struct rfc5444_writer_interface *interf,
    uint8_t type, uint8_t exttype, void *value, size_t length);

/* functions that can be called from add/finishPacketHeader */
EXPORT void rfc5444_writer_set_pkt_header(
    struct rfc5444_writer *writer, struct rfc5444_writer_interface *interf, bool has_seqno);
EXPORT void rfc5444_writer_set_pkt_seqno(
    struct rfc5444_writer *writer, struct rfc5444_writer_interface *interf, uint16_t seqno);

/* functions that can be called outside the callbacks */
EXPORT struct rfc5444_writer_tlvtype *rfc5444_writer_register_addrtlvtype(
    struct rfc5444_writer *writer, uint8_t msgtype, uint8_t tlv, uint8_t tlvext);
EXPORT void rfc5444_writer_unregister_addrtlvtype(struct rfc5444_writer *writer,
    struct rfc5444_writer_tlvtype *tlvtype);

EXPORT int rfc5444_writer_register_msgcontentprovider(
    struct rfc5444_writer *writer, struct rfc5444_writer_content_provider *cpr,
    struct rfc5444_writer_addrtlv_block *addrtlvs, size_t addrtlv_count);
EXPORT void rfc5444_writer_unregister_content_provider(
    struct rfc5444_writer *writer, struct rfc5444_writer_content_provider *cpr,
    struct rfc5444_writer_addrtlv_block *addrtlvs, size_t addrtlv_count);

EXPORT struct rfc5444_writer_message *rfc5444_writer_register_message(
    struct rfc5444_writer *writer, uint8_t msgid, bool if_specific, uint8_t addr_len);
EXPORT void rfc5444_writer_unregister_message(struct rfc5444_writer *writer,
    struct rfc5444_writer_message *msg);

EXPORT void rfc5444_writer_register_pkthandler(struct rfc5444_writer *writer,
    struct rfc5444_writer_pkthandler *pkt);
EXPORT void rfc5444_writer_unregister_pkthandler(struct rfc5444_writer *writer,
    struct rfc5444_writer_pkthandler *pkt);

EXPORT void rfc5444_writer_register_interface(struct rfc5444_writer *writer,
    struct rfc5444_writer_interface *interf);
EXPORT void rfc5444_writer_unregister_interface(
    struct rfc5444_writer *writer, struct rfc5444_writer_interface *interf);

/* prototype for message creation interface filter */
typedef bool (*rfc5444_writer_ifselector)(struct rfc5444_writer *, struct rfc5444_writer_interface *, void *);

EXPORT bool rfc5444_writer_singleif_selector(struct rfc5444_writer *, struct rfc5444_writer_interface *, void *);
EXPORT bool rfc5444_writer_allif_selector(struct rfc5444_writer *, struct rfc5444_writer_interface *, void *);

EXPORT enum rfc5444_result rfc5444_writer_create_message(
    struct rfc5444_writer *writer, uint8_t msgid,
    rfc5444_writer_ifselector useIf, void *param);

EXPORT enum rfc5444_result rfc5444_writer_forward_msg(struct rfc5444_writer *writer,
    uint8_t *msg, size_t len, rfc5444_writer_ifselector useIf, void *param);

EXPORT void rfc5444_writer_flush(struct rfc5444_writer *, struct rfc5444_writer_interface *, bool);

EXPORT void rfc5444_writer_init(struct rfc5444_writer *);
EXPORT void rfc5444_writer_cleanup(struct rfc5444_writer *writer);

/* internal functions that are not exported to the user */
void _rfc5444_writer_free_addresses(struct rfc5444_writer *writer, struct rfc5444_writer_message *msg);
void _rfc5444_writer_begin_packet(struct rfc5444_writer *writer, struct rfc5444_writer_interface *interf);

/**
 * creates a message of a certain ID for a single interface
 * @param writer pointer to writer context
 * @param msgid type of message
 * @param interf pointer to outgoing interface
 * @return RFC5444_OKAY if message was created and added to packet buffer,
 *   RFC5444_... otherwise
 */
static INLINE enum rfc5444_result
rfc5444_writer_create_message_singleif(
    struct rfc5444_writer *writer, uint8_t msgid, struct rfc5444_writer_interface *interf) {
  return rfc5444_writer_create_message(writer, msgid, rfc5444_writer_singleif_selector, interf);
}

/**
 * creates a message of a certain ID for all interface
 * @param writer pointer to writer context
 * @param msgid type of message
 * @return RFC5444_OKAY if message was created and added to packet buffer,
 *   RFC5444_... otherwise
 */
static INLINE enum rfc5444_result
rfc5444_writer_create_message_allif(
    struct rfc5444_writer *writer, uint8_t msgid) {
  return rfc5444_writer_create_message(writer, msgid, rfc5444_writer_allif_selector, NULL);
}

#endif /* RFC5444_WRITER_H_ */
