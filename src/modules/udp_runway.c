/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "modules/udp_runway.h"
#include "modules/udp_fd.h"

static quic_err_t quic_udp_runway_module_init(void *const module);
static quic_err_t quic_udp_runway_module_process(void *const module);

static quic_err_t quic_udp_runway_module_init(void *const module) {
    quic_udp_runway_module_t *const ur_module = module;

    quic_link_init(&ur_module->packets);
    pthread_mutex_init(&ur_module->mtx, NULL);

    return quic_err_success;
}


static quic_err_t quic_udp_runway_module_process(void *const module) {
    quic_udp_runway_module_t *const ur_module = module;
    quic_session_t *const session = quic_module_of_session(module, quic_udp_runway_module);
    quic_udp_fd_module_t *const uf_module = quic_session_module(quic_udp_fd_module_t, session, quic_udp_fd_module);

    pthread_mutex_lock(&ur_module->mtx);

    while (!quic_link_empty(&ur_module->packets)) {
        quic_send_packet_t *packet = (quic_send_packet_t *) quic_link_next(&ur_module->packets);
        quic_link_remove(packet);
        pthread_mutex_unlock(&ur_module->mtx);

        quic_udp_fd_write(uf_module, packet->data, packet->buf.pos - packet->buf.buf);
        free(packet);

        pthread_mutex_lock(&ur_module->mtx);
    }

    pthread_mutex_unlock(&ur_module->mtx);

    return quic_err_success;
}

quic_module_t quic_udp_runway_module = {
    .module_size = sizeof(quic_udp_runway_module_t),
    .init = quic_udp_runway_module_init,
    .process = quic_udp_runway_module_process,
    .destory = NULL
};