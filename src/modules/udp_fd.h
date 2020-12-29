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
#include <netinet/in.h>
#include <errno.h>

#define QUIC_IPV4 4
#define QUIC_IPV6 6

typedef struct quic_socket_s quic_socket_t;
struct quic_socket_s {
    QUIC_RBT_UINT64_FIELDS

    uint32_t mtu;

    int fd;
    uint8_t type;

    union {
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
    } remote_addr;

    union {
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
    } local_addr;
};

#define quic_udp_fd_socket_insert(sockets, socket) \
    quic_rbt_insert((sockets), (socket), quic_rbt_uint64_comparer)

#define quic_udp_fd_socket_find(sockets, key) \
    ((quic_socket_t *) quic_rbt_find((sockets), (key), quic_rbt_uint64_key_comparer))

typedef struct quic_udp_fd_module_s quic_udp_fd_module_t;
struct quic_udp_fd_module_s {
    QUIC_MODULE_FIELDS

    quic_socket_t *sockets;
    quic_socket_t *active_socket;
};

extern quic_module_t quic_udp_fd_module;

static inline quic_err_t quic_udp_fd_new_socket(quic_udp_fd_module_t *const module, const uint64_t key, const uint64_t mtu, struct sockaddr_in local_addr, struct sockaddr_in remote_addr) {
    if (!quic_rbt_is_nil(quic_udp_fd_socket_find(module->sockets, &key))) {
        return quic_err_conflict;
    }

    int fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        return quic_err_internal_error;
    }
    if (bind(fd, (const struct sockaddr *) &local_addr, sizeof(struct sockaddr_in)) == -1) {
        return quic_err_internal_error;
    }

    quic_socket_t *socket = malloc(sizeof(quic_socket_t));
    quic_rbt_init(socket);

    socket->key = key;
    socket->fd = fd;
    socket->type = QUIC_IPV4;
    socket->mtu = mtu;
    socket->local_addr.v4 = local_addr;
    socket->remote_addr.v4 = remote_addr;

    quic_udp_fd_socket_insert(&module->sockets, socket);

    return quic_err_success;
}

static inline quic_err_t quic_udp_fd_migrate(quic_udp_fd_module_t *const module, const uint64_t key) {
    quic_socket_t *const socket = quic_udp_fd_socket_find(module->sockets, &key);
    if (!quic_rbt_is_nil(socket)) {
        return quic_err_conflict;
    }
    module->active_socket = socket;

    return quic_err_success;
}

static inline quic_err_t quic_udp_fd_write(quic_udp_fd_module_t *const module, const void *const data, const uint32_t len) {
    quic_socket_t *const socket = module->active_socket;

    sendto(socket->fd,
           data, len, 0,
           (struct sockaddr *) &socket->remote_addr,
           socket->type == QUIC_IPV4 ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));

    return quic_err_success;
}

// abandon
static inline quic_err_t quic_udp_fd_read(quic_udp_fd_module_t *const module) {
    quic_session_t *const session = quic_module_of_session(module);
    quic_recver_module_t *ur_module = quic_session_module(quic_recver_module_t, session, quic_recver_module);

    quic_recv_packet_t *rp = malloc(sizeof(quic_recv_packet_t) + module->active_socket->mtu);
    if (rp == NULL) {
        return quic_err_internal_error;
    }
    socklen_t socklen = 0;

    int ret = recvfrom(module->active_socket->fd, rp->data, module->active_socket->mtu, 0, (struct sockaddr *) &rp->remote_addr.v4, &socklen);

    rp->len = ret;
    rp->recv_time = quic_now();

    quic_recver_push(ur_module, rp);

    return quic_err_success;
}

#define quic_session_recv_packet(session) \
    quic_udp_fd_read(quic_session_module(quic_udp_fd_module_t, (session), quic_udp_fd_module))

#endif
