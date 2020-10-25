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

    uf_module->fd = 0;

    return quic_err_success;
}

quic_module_t quic_udp_fd_module = {
    .module_size = sizeof(quic_udp_fd_module_t),
    .init = quic_udp_fd_module_init,
    .process = NULL,
    .destory = NULL
};
