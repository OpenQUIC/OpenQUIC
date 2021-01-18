/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "modules/udp_fd.h"
#include <stddef.h>

static quic_err_t quic_udp_fd_module_init(void *const module);
static int quic_udp_fd_recv_co(void *const arg);

typedef struct quic_udp_recver_s quic_udp_recver_t;
struct quic_udp_recver_s {
    liteco_co_t co;

    quic_recver_module_t *recver_module;
    liteco_chan_t *rchan;

    uint8_t st[0];
};

static quic_err_t quic_udp_fd_module_init(void *const module) {
    quic_udp_fd_module_t *const u_module = module;
    quic_session_t *const session = quic_module_of_session(u_module);
    quic_recver_module_t *const r_module = quic_session_module(quic_recver_module_t, session, quic_recver_module);

    liteco_chan_create(&u_module->rchan, 0, liteco_runtime_readycb, session->rt);

    quic_rbt_tree_init(u_module->sockets);
    quic_rbt_tree_init(u_module->active_socket);

    quic_udp_recver_t *const recver = malloc(sizeof(quic_udp_recver_t) + 4096);
    if (!recver) {
        return quic_err_internal_error;
    }
    recver->recver_module = r_module;
    recver->rchan = &u_module->rchan;
    liteco_create(&recver->co, quic_udp_fd_recv_co, recver, NULL, recver->st, 4096);
    liteco_runtime_join(session->rt, &recver->co, true);

    return quic_err_success;
}

static int quic_udp_fd_recv_co(void *const arg) {
    quic_udp_recver_t *const recver = arg;

    for ( ;; ) {

        liteco_udp_pkt_t *pkt = (liteco_udp_pkt_t *) liteco_chan_pop(recver->rchan, true);
        if (!pkt) {
            return 0;
        }

        quic_recv_packet_t *recv_pkt = ((void *) pkt) - offsetof(quic_recv_packet_t, pkt);
        recv_pkt->recv_time = quic_now();

        quic_recver_push(recver->recver_module, recv_pkt);
    }

    return 0;
}

quic_module_t quic_udp_fd_module = {
    .name        = "udp_fd",
    .module_size = sizeof(quic_udp_fd_module_t),
    .init        = quic_udp_fd_module_init,
    .process     = NULL,
    .loop        = NULL,
    .destory     = NULL
};
