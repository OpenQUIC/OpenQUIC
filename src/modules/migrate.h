/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_MIGRATE_H__
#define __OPENQUIC_MIGRATE_H__

#include "module.h"
#include "modules/udp_fd.h"
#include "modules/congestion.h"
#include "utils/rbt.h"

typedef struct quic_path_s quic_path_t;
struct quic_path_s {
    QUIC_RBT_UINT64_FIELDS
};

#define quic_migrate_path_insert(paths, path) \
    quic_rbt_insert((paths), (path), quic_rbt_uint64_comparer)

#define quic_migrate_path_find(paths, key) \
    ((quic_path_t *) quic_rbt_find((paths), (key), quic_rbt_uint64_key_comparer))

typedef struct quic_migrate_module_s quic_migrate_module_t;
struct quic_migrate_module_s {
    QUIC_MODULE_FIELDS

    uint64_t active_id;
    quic_path_t *paths;
};

extern quic_module_t quic_migrate_module;

static inline quic_err_t quic_migrate_new_ipv4_path(quic_migrate_module_t *const module,
                                                    const uint64_t key,
                                                    const uint64_t mtu,
                                                    struct sockaddr_in local_addr,
                                                    struct sockaddr_in remote_addr) {
    if (!quic_rbt_is_nil(quic_migrate_path_find(module->paths, &key))) {
        return quic_err_conflict;
    }

    quic_session_t *const session = quic_module_of_session(module);
    quic_udp_fd_module_t *u_module = quic_session_module(quic_udp_fd_module_t, session, quic_udp_fd_module);
    quic_congestion_module_t *c_module = quic_session_module(quic_congestion_module_t, session, quic_congestion_module);

    quic_path_t *path = malloc(sizeof(quic_path_t));
    quic_rbt_init(path);
    path->key = key;

    quic_migrate_path_insert(&module->paths, path);
    quic_udp_fd_new_socket(u_module, key, mtu, local_addr, remote_addr);
    quic_congestion_new_instance(c_module, key);

    return quic_err_success;
}

static inline quic_err_t quic_migrate_use_path(quic_migrate_module_t *const module, const uint64_t key) {
    quic_path_t *const path = quic_migrate_path_find(module->paths, &key);
    if (quic_rbt_is_nil(path)) {
        return quic_err_internal_error;
    }
    quic_session_t *const session = quic_module_of_session(module);
    quic_udp_fd_module_t *u_module = quic_session_module(quic_udp_fd_module_t, session, quic_udp_fd_module);
    quic_congestion_module_t *c_module = quic_session_module(quic_congestion_module_t, session, quic_congestion_module);

    quic_udp_fd_migrate(u_module, key);
    quic_congestion_migrate(c_module, key);

    return quic_err_success;
}

#endif
