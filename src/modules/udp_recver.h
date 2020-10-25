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
#include "recv_packet.h"
#include "session.h"
#include "utils/link.h"
#include <netinet/in.h>
#include <pthread.h>

typedef struct quic_udp_recver_module_s quic_udp_recver_module_t;
struct quic_udp_recver_module_s {
    pthread_mutex_t mtx;
    quic_link_t queue;

    quic_recv_packet_t *curr_packet;
};

extern quic_module_t quic_udp_recver_module;

static inline quic_err_t quic_udp_recver_push(quic_udp_recver_module_t *const module, quic_recv_packet_t *const packet) {
    quic_session_t *const session = quic_module_of_session(module, quic_udp_recver_module);
    pthread_mutex_lock(&module->mtx);
    quic_link_insert_before(&module->queue, packet);
    pthread_mutex_unlock(&module->mtx);

    quic_module_activate(session, quic_udp_recver_module);
    return quic_err_success;
}

#endif
