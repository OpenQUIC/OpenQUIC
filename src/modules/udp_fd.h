/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_UDP_FD_H__
#define __OPENQUIC_UDP_FD_H__

#include "module.h"
#include "recv_packet.h"
#include "session.h"
#include "modules/recver.h"
#include "utils/time.h"
#include "lc_udp.h"
#include <netinet/in.h>
#include <errno.h>

typedef struct quic_socket_s quic_socket_t;
struct quic_socket_s {
    QUIC_RBT_UINT64_FIELDS

    uint32_t mtu;

    quic_addr_t remote_addr;
    quic_addr_t local_addr;

    quic_session_t *session;

    liteco_udp_t udp;
};

#define quic_udp_fd_socket_insert(sockets, socket) \
    quic_rbt_insert((sockets), (socket), quic_rbt_uint64_comparer)

#define quic_udp_fd_socket_find(sockets, key) \
    ((quic_socket_t *) quic_rbt_find((sockets), (key), quic_rbt_uint64_key_comparer))

typedef struct quic_udp_fd_module_s quic_udp_fd_module_t;
struct quic_udp_fd_module_s {
    QUIC_MODULE_FIELDS

    liteco_chan_t rchan;
    quic_socket_t *sockets;
    quic_socket_t *active_socket;
};

extern quic_module_t quic_udp_fd_module;

static inline quic_err_t quic_udp_fd_path_add(liteco_eloop_t *const eloop,
                                              quic_udp_fd_module_t *const module,
                                              int (*alloc_cb) (liteco_udp_pkt_t **const, liteco_udp_t *const),
                                              const uint64_t key,
                                              const quic_addr_t local_addr,
                                              const quic_addr_t remote_addr) {
    if (!quic_rbt_is_nil(quic_udp_fd_socket_find(module->sockets, &key))) {
        return quic_err_conflict;
    }

    quic_socket_t *socket = malloc(sizeof(quic_socket_t));
    quic_rbt_init(socket);

    liteco_udp_init(eloop, &socket->udp, AF_INET);
    liteco_udp_bind(&socket->udp, (struct sockaddr *) &local_addr, sizeof(local_addr));
    liteco_udp_set_recv(&socket->udp, alloc_cb, &module->rchan);
    socket->key = key;
    socket->local_addr = local_addr;
    socket->remote_addr = remote_addr;
    socket->session = quic_module_of_session(module);

    quic_udp_fd_socket_insert(&module->sockets, socket);

    return quic_err_success;
}

static inline quic_err_t quic_udp_fd_migrate(quic_udp_fd_module_t *const module, const uint64_t key) {
    quic_socket_t *const socket = quic_udp_fd_socket_find(module->sockets, &key);
    if (quic_rbt_is_nil(socket)) {
        return quic_err_internal_error;
    }
    module->active_socket = socket;

    return quic_err_success;
}

static inline quic_err_t quic_udp_fd_write(quic_udp_fd_module_t *const module, const void *const data, const uint32_t len) {
    quic_socket_t *const socket = module->active_socket;

    liteco_udp_sendto(&socket->udp, (struct sockaddr *) &socket->remote_addr, sizeof(struct sockaddr_in), data, len);

    return quic_err_success;
}

#endif
