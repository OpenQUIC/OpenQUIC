/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_UDP_RECVER_H__
#define __OPENQUIC_UDP_RECVER_H__

#include "module.h"
#include "utils/link.h"
#include <netinet/in.h>
#include <pthread.h>

typedef struct quic_recv_packet_s quic_recv_packet_t;
struct quic_recv_packet_s {
    QUIC_LINK_FIELDS

    union {
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
    } addr;

    uint64_t recv_time;

    uint32_t len;
    uint8_t data[0];
};

typedef struct quic_udp_recver_module_s quic_udp_recver_module_t;
struct quic_udp_recver_module_s {
    pthread_mutex_t mtx;
    quic_link_t queue;

    quic_recv_packet_t *curr_packet;
};

static inline quic_err_t quic_udp_recver_push(quic_udp_recver_module_t *const module, quic_recv_packet_t *const packet) {
    pthread_mutex_lock(&module->mtx);
    quic_link_insert_before(&module->queue, packet);
    pthread_mutex_unlock(&module->mtx);

    return quic_err_success;
}

extern quic_module_t quic_udp_recver_module;

#endif
