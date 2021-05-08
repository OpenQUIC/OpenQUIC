/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_SERVER_H__
#define __OPENQUIC_SERVER_H__

#include "utils/rbt_extend.h"
#include "session.h"
#include "transmission.h"
#include "liteco.h"

typedef struct quic_session_store_s quic_session_store_t;
struct quic_session_store_s {
    QUIC_RBT_KEY_STRING_FIELDS

    quic_session_t *session;
};

typedef struct quic_server_s quic_server_t;
struct quic_server_s {
    liteco_eloop_t eloop;
    liteco_runtime_t rt;

    quic_transmission_t transmission;

    size_t st_size;
    quic_config_t cfg;
    size_t connid_len;

    quic_session_store_t *sessions;
    quic_closed_session_t *closed_sessions;

    size_t session_extends_size;
    quic_err_t (*accept_cb) (quic_session_t *const);
};

quic_err_t quic_server_init(quic_server_t *const server, const size_t extends_size, const size_t st_size);

quic_err_t quic_server_cert_file(quic_server_t *const server, const char *const cert_file);

quic_err_t quic_server_key_file(quic_server_t *const server, const char *const key_file);

quic_err_t quic_server_listen(quic_server_t *const server, const liteco_addr_t local_addr);

quic_err_t quic_server_accept(quic_server_t *const server, quic_err_t (*accept_cb) (quic_session_t *const));

quic_err_t quic_server_start_loop(quic_server_t *const server);

quic_server_t *quic_session_server(quic_session_t *const session);

#endif
