/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_UDP_RUNWAY_H__
#define __OPENQUIC_UDP_RUNWAY_H__

#include "module.h"
#include "session.h"
#include "utils/link.h"
#include "utils/buf.h"
#include <pthread.h>

typedef struct quic_send_packet_s quic_send_packet_t;
struct quic_send_packet_s {
    QUIC_LINK_FIELDS

    quic_link_t frames;
    quic_buf_t buf;

    uint8_t data[0];
};

typedef struct quic_udp_runway_module_s quic_udp_runway_module_t;
struct quic_udp_runway_module_s {
    quic_link_t packets;

    pthread_mutex_t mtx;
};

extern quic_module_t quic_udp_runway_module;

static inline quic_err_t quic_udp_runway_push(quic_udp_runway_module_t *const module, quic_send_packet_t *const packet) {
    quic_session_t *const session = quic_module_of_session(module, quic_udp_runway_module);

    pthread_mutex_lock(&module->mtx);
    quic_link_insert_before(&module->packets, packet);
    pthread_mutex_unlock(&module->mtx);

    quic_module_activate(session, quic_udp_runway_module);

    return quic_err_success;
}

#endif
