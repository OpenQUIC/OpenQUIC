/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "modules/migrate.h"

static quic_err_t quic_migrate_module_init(void *const module);

static quic_err_t quic_migrate_module_init(void *const module) {
    quic_migrate_module_t *const m_module = module;

    quic_rbt_tree_init(m_module->paths);
    m_module->active_id = -1L;

    return quic_err_success;
}

quic_module_t quic_migrate_module = {
    .name        = "migrate",
    .module_size = sizeof(quic_migrate_module_t),
    .init        = quic_migrate_module_init,
    .process     = NULL,
    .loop        = NULL,
    .destory     = NULL
};
