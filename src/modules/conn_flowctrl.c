/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "modules/conn_flowctrl.h"

static quic_err_t quic_conn_flowctrl_module_init(void *const module);

static quic_err_t quic_conn_flowctrl_module_init(void *const module) {
    quic_conn_flowctrl_module_t *const f_module = module;
    quic_session_t *const session = quic_module_of_session(f_module);

    f_module->rwnd = session->cfg.conn_flowctrl_initial_rwnd;
    f_module->rwnd_size = session->cfg.conn_flowctrl_max_rwnd_size;
    f_module->recv_off = 0;
    f_module->read_off = 0;

    f_module->swnd = session->cfg.conn_flowctrl_initial_swnd;
    f_module->sent_bytes = 0;

    f_module->epoch_off = 0;
    f_module->epoch_time = 0;

    pthread_mutex_init(&f_module->rwnd_updated_mtx, NULL);
    f_module->updated = false;

    return quic_err_success;
}

quic_module_t quic_conn_flowctrl_module = {
    .name        = "conn_flowctrl",
    .module_size = sizeof(quic_conn_flowctrl_module_t),
    .init        = NULL,
    .process     = NULL,
    .loop        = NULL,
    .destory     = NULL
};
