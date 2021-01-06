/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_CLIENT_H__
#define __OPENQUIC_CLIENT_H__

#include "session.h"
#include "events/epoll.h"
#include "modules/migrate.h"
#include "modules/udp_fd.h"
#include "liteco.h"

typedef struct quic_client_s quic_client_t;
struct quic_client_s {
    quic_event_epoll_t epoll;

    liteco_runtime_t rt;
    quic_session_t *session;

    uint8_t *stack;
};

extern const quic_config_t quic_client_default_config;

quic_err_t quic_client_init(quic_client_t *const client, const quic_config_t cfg);
static inline quic_err_t quic_client_create_ipv4_path(quic_client_t *const client, const uint64_t key, const uint64_t mtu, struct sockaddr_in local_addr, struct sockaddr_in remote_addr) {
    quic_migrate_module_t *const migrate = quic_session_module(quic_migrate_module_t, client->session, quic_migrate_module);
    quic_udp_fd_module_t *const udp_fd = quic_session_module(quic_udp_fd_module_t, client->session, quic_udp_fd_module);

    quic_migrate_new_ipv4_path(migrate, key, mtu, local_addr, remote_addr);

    quic_socket_t *const socket = quic_udp_fd_socket_find(udp_fd->sockets, &key);
    if (quic_rbt_is_nil(socket)) {
        return quic_err_internal_error;
    }

    quic_event_epoll_register_fd(&client->epoll, socket->fd, socket);

    return quic_err_success;
}

static inline quic_err_t quic_client_use_path(quic_client_t *const client, const uint64_t key) {
    quic_migrate_module_t *const migrate = quic_session_module(quic_migrate_module_t, client->session, quic_migrate_module);
    quic_migrate_use_path(migrate, key);

    return quic_err_success;
}

quic_err_t quic_client_start_loop(quic_client_t *const client);

#endif
