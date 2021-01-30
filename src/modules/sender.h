/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_SENDER_H__
#define __OPENQUIC_SENDER_H__

#include "module.h"
#include "modules/retransmission.h"
#include "utils/link.h"
#include "utils/buf.h"

#define quic_send_packet_init(send_pkt, size) {               \
    (send_pkt) = malloc(sizeof(quic_send_packet_t) + (size)); \
    if ((send_pkt) == NULL) {                                 \
        return NULL;                                          \
    }                                                         \
    quic_link_init(((quic_link_t *) (send_pkt)));             \
    quic_link_init(&(send_pkt)->frames);                      \
    (send_pkt)->buf.buf = (send_pkt)->data;                   \
    (send_pkt)->buf.capa = (size);                            \
    (send_pkt)->largest_ack = 0;                              \
    (send_pkt)->included_unacked = false;                     \
    quic_buf_setpl(&(send_pkt)->buf);                         \
}

typedef struct quic_send_packet_s quic_send_packet_t;
struct quic_send_packet_s {
    QUIC_LINK_FIELDS

    uint64_t num;
    uint64_t largest_ack;
    bool included_unacked;
    quic_retransmission_module_t *retransmission_module;

    quic_link_t frames;
    quic_buf_t buf;

    uint8_t data[0];
};

typedef struct quic_sender_module_s quic_sender_module_t;
struct quic_sender_module_s {
    QUIC_MODULE_FIELDS

    uint64_t next_send_time;
};

extern quic_module_t quic_sender_module;

#endif
