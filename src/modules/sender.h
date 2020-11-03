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
#include "utils/link.h"
#include "utils/buf.h"

#define quic_send_packet_init(send_packet, size) {               \
    (send_packet) = malloc(sizeof(quic_send_packet_t) + (size)); \
    if ((send_packet) == NULL) {                                 \
        return NULL;                                             \
    }                                                            \
    quic_link_init(((quic_link_t *) (send_packet)));             \
    quic_link_init(&(send_packet)->frames);                      \
    (send_packet)->buf.buf = (send_packet)->data;                \
    (send_packet)->buf.capa = (size);                            \
    (send_packet)->largest_ack = 0;                              \
    (send_packet)->included_unacked = false;                     \
    quic_buf_setpl(&(send_packet)->buf);                         \
}

typedef struct quic_sender_module_s quic_sender_module_t;
struct quic_sender_module_s {
    QUIC_MODULE_FIELDS

    uint32_t mtu;
};

extern quic_module_t quic_sender_module;

#endif
