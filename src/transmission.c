/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "liteco.h"
#include "utils/rbt_extend.h"
#include "utils/time.h"
#include "utils/container_of.h"
#include "transmission.h"

typedef struct quic_transmission_recver_s quic_treansmission_recver_t;
struct quic_transmission_recver_s {
    liteco_co_t co;

    quic_transmission_t *trans;
    quic_err_t (*cb) (quic_transmission_t *const, quic_recv_packet_t *const);

    uint8_t st[0];
};

static int quic_transmission_recver_process_co(void *const args);
static int quic_transmission_recver_process_finish(void *const args);
static void quic_transmission_recv_alloc(liteco_udp_chan_t *const uchan, liteco_udp_chan_ele_t **const ele);
static void quic_transmission_recv_recovery(liteco_udp_chan_t *const uchan, liteco_udp_chan_ele_t *const ele);

quic_err_t quic_transmission_init(quic_transmission_t *const trans, liteco_runtime_t *const rt) {

    liteco_chan_init(&trans->rchan, 1, rt);

    trans->cb = NULL;
    liteco_rbt_init(trans->sockets);

    quic_treansmission_recver_t *const recver = malloc(sizeof(quic_treansmission_recver_t) + 4096);
    if (!recver) {
        return quic_err_internal_error;
    }
    recver->trans = trans;
    liteco_co_init(&recver->co, quic_transmission_recver_process_co, recver, recver->st, 4096);
    liteco_co_finished(&recver->co, quic_transmission_recver_process_finish, recver);

    liteco_runtime_join(rt, &recver->co);

    return quic_err_success;
}

static int quic_transmission_recver_process_co(void *const args) {
    quic_treansmission_recver_t *const recver = args;

    for ( ;; ) {
        liteco_udp_chan_ele_t *const pkt = liteco_chan_pop(&recver->trans->rchan, true);
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

static int quic_transmission_recver_process_finish(void *const args) {
    quic_treansmission_recver_t *const recver = args;
    free(recver);
    return 0;
}

quic_err_t quic_transmission_listen(liteco_eloop_t *const eloop, quic_transmission_t *const trans, const liteco_addr_t local_addr, const uint32_t mtu) {
    if (liteco_rbt_is_not_nil(liteco_rbt_find(trans->sockets, &local_addr))) {
        return quic_err_conflict;
    }
    quic_transmission_socket_t *const socket = quic_malloc(sizeof(quic_transmission_socket_t));
    if (!socket) {
        return quic_err_internal_error;
    }
    liteco_rbt_node_init(socket);

    liteco_udp_chan_init(eloop, &socket->udp);
    liteco_udp_chan_bind(&socket->udp, (struct sockaddr *) &local_addr, &trans->rchan);
    liteco_udp_chan_recv(&socket->udp, quic_transmission_recv_alloc, quic_transmission_recv_recovery);
    socket->key = local_addr;
    socket->mtu = mtu;

    liteco_rbt_insert(&trans->sockets, socket);

    return quic_err_success;
}

static void quic_transmission_recv_alloc(liteco_udp_chan_t *const uchan, liteco_udp_chan_ele_t **const ele) {
    quic_transmission_socket_t *const socket = ((void *) uchan) - offsetof(quic_transmission_socket_t, udp);
    quic_recv_packet_t *const recvpkt = malloc(sizeof(quic_recv_packet_t) + socket->mtu);

    *ele = &recvpkt->pkt;
    (*ele)->b_size = socket->mtu;
    (*ele)->ret = 0;
}

static void quic_transmission_recv_recovery(liteco_udp_chan_t *const uchan, liteco_udp_chan_ele_t *const ele) {
    (void) uchan;
    quic_recv_packet_t *const recvpkt = container_of(ele, quic_recv_packet_t, pkt);

    quic_free(recvpkt);
}
