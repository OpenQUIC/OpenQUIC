/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "utils/time.h"
#include "transmission.h"
#include "lc_coroutine.h"

typedef struct quic_transmission_recver_s quic_treansmission_recver_t;
struct quic_transmission_recver_s {
    liteco_co_t co;

    quic_transmission_t *trans;
    quic_err_t (*cb) (quic_transmission_t *const, quic_recv_packet_t *const);

    uint8_t st[0];
};

static int quic_transmission_recver_process_co(void *const arg);
static int quic_transmission_recver_process_finish(liteco_co_t *const co);
static int quic_transmission_recv_alloc(liteco_udp_pkt_t **const pkt, liteco_udp_t *const udp);
static void quic_transmission_pkt_recovery(liteco_udp_pkt_t *const pkt);

quic_err_t quic_transmission_init(quic_transmission_t *const trans, liteco_runtime_t *const rt) {

    liteco_chan_create(&trans->rchan, 1, liteco_runtime_readycb, rt);

    trans->cb = NULL;
    quic_rbt_tree_init(trans->sockets);

    quic_treansmission_recver_t *const recver = malloc(sizeof(quic_treansmission_recver_t) + 4096);
    if (!recver) {
        return quic_err_internal_error;
    }
    recver->trans = trans;
    liteco_create(&recver->co,
                  quic_transmission_recver_process_co, recver,
                  quic_transmission_recver_process_finish,
                  recver->st, 4096);

    liteco_runtime_join(rt, &recver->co, true);

    return quic_err_success;
}

static int quic_transmission_recver_process_co(void *const arg) {
    quic_treansmission_recver_t *const recver = arg;

    for ( ;; ) {
        liteco_udp_pkt_t *const pkt = liteco_chan_pop(&recver->trans->rchan, true);
        if (pkt == liteco_chan_pop_failed) {
            return 0;
        }

        quic_recv_packet_t *recvpkt = ((void *) pkt) - offsetof(quic_recv_packet_t, pkt);
        recvpkt->recv_time = quic_now();

        if (recver->trans->cb) {
            recver->trans->cb(recver->trans, recvpkt);
        }
        else {
            free(recvpkt);
        }
    }

    return 0;
}

static int quic_transmission_recver_process_finish(liteco_co_t *const co) {
    quic_treansmission_recver_t *const recver = (((void *) co) - offsetof(quic_treansmission_recver_t, co));
    free(recver);
    return 0;
}

quic_err_t quic_transmission_listen(liteco_eloop_t *const eloop, quic_transmission_t *const trans, const uint32_t mtu, const quic_addr_t local_addr) {
    if (!quic_rbt_is_nil(quic_transmission_socket_find(trans->sockets, &local_addr))) {
        return quic_err_conflict;
    }
    quic_transmission_socket_t *const socket = malloc(sizeof(quic_transmission_socket_t));
    if (!socket) {
        return quic_err_internal_error;
    }
    quic_rbt_init(socket);

    liteco_udp_init(eloop, &socket->udp, AF_INET);
    liteco_udp_bind(&socket->udp, (struct sockaddr *) &local_addr, sizeof(local_addr));
    liteco_udp_set_recv(&socket->udp, quic_transmission_recv_alloc, &trans->rchan);
    socket->key = local_addr;
    socket->mtu = mtu;

    quic_transmission_socket_insert(&trans->sockets, socket);

    return quic_err_success;
}

static int quic_transmission_recv_alloc(liteco_udp_pkt_t **const pkt, liteco_udp_t *const udp) {
    quic_transmission_socket_t *const socket = ((void *) udp) - offsetof(quic_transmission_socket_t, udp);
    quic_recv_packet_t *const recvpkt = malloc(sizeof(quic_recv_packet_t) + socket->mtu);
    *pkt = &recvpkt->pkt;

    (*pkt)->cap = socket->mtu;
    (*pkt)->recovery = quic_transmission_pkt_recovery;
    (*pkt)->len = 0;

    return 0;
}

static void quic_transmission_pkt_recovery(liteco_udp_pkt_t *const pkt) {
    quic_recv_packet_t *recvpkt = ((void *) pkt) - offsetof(quic_recv_packet_t, pkt);
    free(recvpkt);
}
