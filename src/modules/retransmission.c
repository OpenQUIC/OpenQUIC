/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "modules/retransmission.h"

static quic_err_t quic_retransmission_module_init(void *const module);

static quic_err_t quic_retransmission_module_init(void *const module) {
    quic_retransmission_module_t *r_module = (quic_retransmission_module_t *) module;

    r_module->sent_count = 0;
    quic_rbt_tree_init(r_module->sent_mem);

    return quic_err_success;
}

quic_module_t quic_initial_retransmission_module = {
    .module_size = sizeof(quic_retransmission_module_t),
    .init = quic_retransmission_module_init,
    .process = NULL,
    .destory = NULL
};

quic_module_t quic_handshake_retransmission_module = {
    .module_size = sizeof(quic_retransmission_module_t),
    .init = quic_retransmission_module_init,
    .process = NULL,
    .destory = NULL
};

quic_module_t quic_app_retransmission_module = {
    .module_size = sizeof(quic_retransmission_module_t),
    .init = quic_retransmission_module_init,
    .process = NULL,
    .destory = NULL
};
