/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_SENDER_H__
#define __OPENQUIC_SENDER_H__

#include "platform/platform.h"
#include "modules/retransmission.h"
#include "utils/buf.h"
#include "module.h"
#include "liteco.h"

#define quic_send_packet_init(send_pkt, size) {                    \
    (send_pkt) = quic_malloc(sizeof(quic_send_packet_t) + (size)); \
    if ((send_pkt) == NULL) {                                      \
        return NULL;                                               \
    }                                                              \
    liteco_link_init((send_pkt));                                  \
    liteco_link_init(&(send_pkt)->frames);                         \
    (send_pkt)->buf.buf = (send_pkt)->data;                        \
    (send_pkt)->buf.capa = (size);                                 \
    (send_pkt)->largest_ack = 0;                                   \
    (send_pkt)->included_unacked = false;                          \
    quic_buf_setpl(&(send_pkt)->buf);                              \
}

typedef struct quic_send_packet_s quic_send_packet_t;
struct quic_send_packet_s {
    LITECO_LINKNODE_BASE

    uint64_t num;
    uint64_t largest_ack;
    bool included_unacked;
    quic_retransmission_module_t *retransmission_module;

    liteco_linknode_t frames;
    quic_buf_t buf;

    uint8_t data[0];
};

typedef struct quic_sender_module_s quic_sender_module_t;
struct quic_sender_module_s {
    QUIC_MODULE_FIELDS

    uint64_t next_send_time;
};

extern quic_module_t quic_sender_module;

quic_send_packet_t *quic_sender_pack_connection_close(quic_sender_module_t *const sender, const uint64_t type, const uint64_t errcode, const quic_buf_t reason);

#endif
