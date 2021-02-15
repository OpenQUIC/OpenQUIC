/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_SERVER_H__
#define __OPENQUIC_SERVER_H__

#include "session.h"
#include "transmission.h"
#include "utils/rbt.h"
#include "lc_eloop.h"
#include "lc_runtime.h"

typedef struct quic_session_store_s quic_session_store_t;
struct quic_session_store_s {
    QUIC_RBT_STRING_FIELDS

    quic_session_t *session;
};

#define quic_session_store_insert(store, session) \
    quic_rbt_insert((store), (session), quic_rbt_string_comparer)

#define quic_session_store_find(store, key) \
    ((quic_session_store_t *) quic_rbt_find((store), (key), quic_rbt_string_key_comparer))

typedef struct quic_server_s quic_server_t;
struct quic_server_s {
    liteco_eloop_t eloop;
    liteco_runtime_t rt;

    quic_transmission_t transmission;

    size_t st_size;
    quic_config_t cfg;
    size_t connid_len;
    quic_session_store_t *sessions;

    quic_err_t (*accept_cb) (quic_server_t *const, quic_session_t *const);
};

quic_err_t quic_server_init(quic_server_t *const server, const size_t st_size);

quic_err_t quic_server_cert_file(quic_server_t *const server, const char *const cert_file);

quic_err_t quic_server_key_file(quic_server_t *const server, const char *const key_file);

quic_err_t quic_server_listen(quic_server_t *const server, const quic_addr_t local_addr);

quic_err_t quic_server_accept(quic_server_t *const server, quic_err_t (*accept_cb) (quic_server_t *const, quic_session_t *const));

quic_err_t quic_server_start_loop(quic_server_t *const server);

#endif
