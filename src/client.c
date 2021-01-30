/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "client.h"
#include "modules/recver.h"
#include "modules/stream.h"
#include <stdlib.h>

const quic_config_t quic_client_default_config = {
    .is_cli = true,
    .conn_len = 6,
    .stream_recv_timeout = 0,
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

static quic_err_t quic_client_transmission_recv_cb(quic_transmission_t *const transmission, quic_recv_packet_t *const recvpkt);

quic_err_t quic_client_init(quic_client_t *const client, const quic_config_t cfg, void *const st, const size_t st_size) {

    liteco_eloop_init(&client->eloop);
    liteco_runtime_init(&client->eloop, &client->rt);
    quic_transmission_init(&client->transmission, &client->rt);
    quic_transmission_recv(&client->transmission, quic_client_transmission_recv_cb);

    client->session = quic_session_create(&client->transmission, cfg);
    quic_session_run(client->session, &client->eloop, &client->rt, st, st_size);

    return quic_err_success;
}

quic_err_t quic_client_start_loop(quic_client_t *const client) {
    for ( ;; ) {
        liteco_eloop_run(&client->eloop, -1);
    }
}

quic_err_t quic_client_listen(quic_client_t *const client, const quic_addr_t local_addr, const uint32_t mtu) {
    return quic_transmission_listen(&client->eloop, &client->transmission, local_addr, mtu);
}

quic_err_t quic_client_path_use(quic_client_t *const client, const quic_path_t path) {
    if (!quic_transmission_exist(&client->transmission, path.local_addr)) {
        quic_client_listen(client, path.local_addr, 1460);
    }

    return quic_session_path_use(client->session, path);
}

quic_err_t quic_client_path_target_use(quic_client_t *const client, const quic_addr_t remote_addr) {
    return quic_session_path_target_use(client->session, remote_addr);
}

quic_err_t quic_client_accept(quic_client_t *const client, quic_err_t (*accept_cb) (quic_session_t *const, quic_stream_t *const)) {
    return quic_session_accept(client->session, accept_cb);
}

quic_stream_t *quic_client_open(quic_client_t *const client, bool bidi) {
    return quic_session_open(client->session, bidi);
}

quic_err_t quic_client_handshake_done(quic_client_t *const client, quic_err_t (*handshake_done_cb) (quic_session_t *const)) {
    return quic_session_handshake_done(client->session, handshake_done_cb);
}

static quic_err_t quic_client_transmission_recv_cb(quic_transmission_t *const transmission, quic_recv_packet_t *const recvpkt) {
    quic_client_t *const client = ((void *) transmission) - offsetof(quic_client_t, transmission);
    quic_recver_module_t *const r_module = quic_session_module(quic_recver_module_t, client->session, quic_recver_module);

    return quic_recver_push(r_module, recvpkt);
}
