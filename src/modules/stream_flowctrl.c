/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "modules/stream_flowctrl.h"

typedef struct quic_stream_flowctrl_s quic_stream_flowctrl_t;
struct quic_stream_flowctrl_s {

};

static quic_err_t quic_stream_flowctrl_module_init(void *const module);

static quic_err_t quic_stream_flowctrl_module_init(void *const module) {
    quic_stream_flowctrl_module_t *const sf_module = module;

    sf_module->module_size = sizeof(quic_stream_flowctrl_t);

    return quic_err_success;
}

quic_module_t quic_stream_flowctrl_module = {
    .module_size = sizeof(quic_stream_flowctrl_module_t),
    .init        = quic_stream_flowctrl_module_init,
    .process     = NULL,
    .loop        = NULL,
    .destory     = NULL
};
