/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "client.h"
#include "modules/udp_fd.h"
#include "modules/recver.h"
#include "modules/stream.h"
#include <stdlib.h>

const quic_config_t quic_client_default_config = {
    .co_stack_size = 8192,
    .is_cli = true,
    .conn_len = 6,
    .stream_recv_timeout = 0,
    .mtu = 1460,
    .disable_prr = false,
    .initial_cwnd = 1460,
    .min_cwnd = 1460,
    .max_cwnd = 10 * 1460,
    .slowstart_large_reduction = true,
    .stream_flowctrl_initial_rwnd = 1460,
    .stream_flowctrl_max_rwnd_size = 5 * 1460,
    .stream_flowctrl_initial_swnd = 5 * 1460,
    .conn_flowctrl_initial_rwnd = 1460,
    .conn_flowctrl_max_rwnd_size = 5 * 1460,
    .conn_flowctrl_initial_swnd = 1460,
    .tls_ciphers = NULL,
    .tls_curve_groups = NULL,
    .tls_cert_chain_file = NULL,
    .tls_key_file = NULL,
    .tls_verify_client_ca = NULL,
    .tls_ca = NULL,
    .tls_capath = NULL,
    .stream_sync_close = true,
    .stream_destory_timeout = 0,
};

quic_err_t quic_client_init(quic_client_t *const client, const quic_config_t cfg) {
    if ((client->st = malloc(cfg.co_stack_size)) == NULL) {
        return quic_err_internal_error;
    }

    liteco_eloop_init(&client->eloop);

    liteco_runtime_init(&client->eloop, &client->rt);
    client->session = quic_session_create(cfg);

    quic_session_run(client->session, &client->eloop, &client->rt, client->st, cfg.co_stack_size);

    return quic_err_success;
}

quic_err_t quic_client_start_loop(quic_client_t *const client) {
    for ( ;; ) {
        liteco_eloop_run(&client->eloop, -1);
    }
}

quic_err_t quic_client_path_add(quic_client_t *const client, const uint64_t key, quic_addr_t local_addr, quic_addr_t remote_addr) {
    return quic_session_path_add(&client->eloop, client->session, key, local_addr, remote_addr);
}

quic_err_t quic_client_path_use(quic_client_t *const client, const uint64_t key) {
    return quic_session_path_use(client->session, key);
}

quic_err_t quic_client_accept(quic_client_t *const client, quic_err_t (*accept_cb) (quic_session_t *const, quic_stream_t *const)) {
    return quic_session_accept(client->session, accept_cb);
}

quic_err_t quic_client_handshake_done(quic_client_t *const client, quic_err_t (*handshake_done_cb) (quic_session_t *const)) {
    return quic_session_handshake_done(client->session, handshake_done_cb);
}

