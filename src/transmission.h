/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_TRANSMISSION_H__
#define __OPENQUIC_TRANSMISSION_H__

#include "recv_packet.h"
#include "utils/addr.h"
#include "utils/rbt.h"
#include "lc_runtime.h"
#include "lc_channel.h"
#include "lc_udp.h"
#include <netinet/in.h>

typedef struct quic_transmission_socket_s quic_transmission_socket_t;
struct quic_transmission_socket_s {
    QUIC_RBT_ADDR_FIELDS
    uint32_t mtu;
    liteco_udp_t udp;
};

#define quic_transmission_socket_insert(sockets, socket) \
    quic_rbt_insert((sockets), (socket), quic_rbt_addr_comparer)

#define quic_transmission_socket_find(sockets, key) \
    ((quic_transmission_socket_t *) quic_rbt_find((sockets), (key), quic_rbt_addr_key_comparer))

typedef struct quic_transmission_s quic_transmission_t;
struct quic_transmission_s {
    quic_transmission_socket_t *sockets;

    liteco_chan_t rchan;

    quic_err_t (*cb) (quic_transmission_t *const, quic_recv_packet_t *const);
};

quic_err_t quic_transmission_init(quic_transmission_t *const trans, liteco_runtime_t *const rt);
quic_err_t quic_transmission_listen(liteco_eloop_t *const eloop, quic_transmission_t *const trans, const quic_addr_t local_addr, const uint32_t mtu);

static inline quic_err_t quic_transmission_recv(quic_transmission_t *const trans, quic_err_t (*cb) (quic_transmission_t *const, quic_recv_packet_t *const)) {
    trans->cb = cb;
    return quic_err_success;
}
static inline bool quic_transmission_exist(quic_transmission_t *const trans, const quic_addr_t addr) {
    return !quic_rbt_is_nil(quic_transmission_socket_find(trans->sockets, &addr));
}

static inline quic_err_t quic_transmission_send(quic_transmission_t *const trans, const quic_path_t path, const void *const data, const uint32_t len) {
    quic_transmission_socket_t *const socket = quic_transmission_socket_find(trans->sockets, &path.local_addr);
    if (quic_rbt_is_nil(socket)) {
        return quic_err_not_implemented;
    }

    liteco_udp_sendto(&socket->udp, (struct sockaddr *) &path.remote_addr, quic_addr_size(path.remote_addr), data, len);

    return quic_err_success;
}

static inline quic_err_t quic_transmission_set_mtu(quic_transmission_t *const trans, const quic_addr_t local_addr, const uint32_t mtu) {
    quic_transmission_socket_t *const socket = quic_transmission_socket_find(trans->sockets, &local_addr);
    if (quic_rbt_is_nil(socket)) {
        return quic_err_not_implemented;
    }
    socket->mtu = mtu;

    return quic_err_success;
}

static inline uint32_t quic_transmission_get_mtu(quic_transmission_t *const trans, const quic_addr_t local_addr) {
    quic_transmission_socket_t *const socket = quic_transmission_socket_find(trans->sockets, &local_addr);
    if (quic_rbt_is_nil(socket)) {
        return 0;
    }

    return socket->mtu;
}

#endif
