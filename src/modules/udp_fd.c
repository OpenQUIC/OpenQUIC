/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "modules/udp_fd.h"

static quic_err_t quic_udp_fd_module_init(void *const module);

static quic_err_t quic_udp_fd_module_init(void *const module) {
    quic_udp_fd_module_t *const uf_module = module;
    quic_session_t *const session = quic_module_of_session(module, quic_udp_fd_module);

    uf_module->local_addr.v4 = session->cfg.local_addr.v4;
    uf_module->remote_addr.v4 = session->cfg.remote_addr.v4;

    if ((uf_module->fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
        return quic_err_internal_error;
    }

    if (bind(uf_module->fd, (const struct sockaddr *) &uf_module->local_addr, sizeof(struct sockaddr_in)) == -1) {
        return quic_err_internal_error;
    }

    uf_module->mtu = 1460;

    return quic_err_success;
}

quic_module_t quic_udp_fd_module = {
    .module_size = sizeof(quic_udp_fd_module_t),
    .init = quic_udp_fd_module_init,
    .process = NULL,
    .destory = NULL
};
