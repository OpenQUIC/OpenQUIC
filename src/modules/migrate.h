/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_MIGRATE_H__
#define __OPENQUIC_MIGRATE_H__

#include "module.h"
#include "session.h"
#include "modules/congestion.h"
#include "utils/rbt.h"

typedef struct quic_migrate_module_s quic_migrate_module_t;
struct quic_migrate_module_s {
    QUIC_MODULE_FIELDS

    bool setup;
};

extern quic_module_t quic_migrate_module;

static inline quic_err_t quic_migrate_path_use(quic_migrate_module_t *const module, const quic_path_t path) {
    quic_session_t *const session = quic_module_of_session(module);
    quic_congestion_module_t *c_module = quic_session_module(session, quic_congestion_module);

    quic_congestion_migrate(c_module, path);
    if (module->setup) {
        // TODO send path_challenge
    }
    module->setup = true;

    return quic_err_success;
}

#endif
