/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "modules/udp_recver.h"
#include "parse_packet.h"

static quic_err_t quic_udp_recver_module_init(void *const module);
static quic_err_t quic_udp_recver_module_process(void *const module);

static quic_err_t quic_udp_recver_module_init(void *const module) {
    quic_udp_recver_module_t *const ur_module = module;

    pthread_mutex_init(&ur_module->mtx, NULL);
    quic_link_init(&ur_module->queue);
    ur_module->curr_packet = NULL;

    return quic_err_success;
}

static quic_err_t quic_udp_recver_module_process(void *const module) {
    quic_udp_recver_module_t *const ur_module = module;
    quic_session_t *const session = quic_module_of_session(module, quic_udp_recver_module);

    pthread_mutex_lock(&ur_module->mtx);
    ur_module->curr_packet = (quic_recv_packet_t *) quic_link_next(&ur_module->queue);
    quic_link_remove(ur_module->curr_packet);
    pthread_mutex_unlock(&ur_module->mtx);

    quic_buf_t recv_buf = { .buf = ur_module->curr_packet->data, .capa = ur_module->curr_packet->len };
    quic_buf_setpl(&recv_buf);

    quic_handle_packet(session, recv_buf, ur_module->curr_packet->recv_time);

    free(ur_module->curr_packet);
    ur_module->curr_packet = NULL;

    return quic_err_success;
}

quic_module_t quic_udp_recver_module = {
    .module_size = sizeof(quic_udp_recver_module_t),
    .init = quic_udp_recver_module_init,
    .process = quic_udp_recver_module_process,
    .destory = NULL
};
