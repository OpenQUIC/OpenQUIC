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
#include <stdlib.h>

static int quic_client_recv_alloc_cb(liteco_udp_pkt_t **const pkt_storage, liteco_udp_t *const udp);
static void quic_client_recovery_pkt(liteco_udp_pkt_t *const pkt);

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

    .handshake_done_cb = NULL,
    .accept_stream_cb = NULL,
    .stream_write_done_cb = NULL,
    .stream_read_done_cb = NULL
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

quic_err_t quic_client_create_ipv4_path(quic_client_t *const client, const uint64_t key, struct sockaddr_in local_addr, struct sockaddr_in remote_addr) {
    quic_migrate_module_t *const migrate = quic_session_module(quic_migrate_module_t, client->session, quic_migrate_module);

    quic_migrate_new_ipv4_path(&client->eloop, migrate, quic_client_recv_alloc_cb, key, local_addr, remote_addr);

    return quic_err_success;
}

static int quic_client_recv_alloc_cb(liteco_udp_pkt_t **const pkt_storage, liteco_udp_t *const udp) {
    (void) udp;
    quic_recv_packet_t *const pkt = malloc(sizeof(quic_recv_packet_t) + 1460);
    *pkt_storage = &pkt->pkt;
    (*pkt_storage)->cap = 1460;
    (*pkt_storage)->recovery = quic_client_recovery_pkt;
    (*pkt_storage)->len = 0;
    return 0;
}

static void quic_client_recovery_pkt(liteco_udp_pkt_t *const pkt) {
    quic_recv_packet_t *recv_pkt = ((void *) pkt) - offsetof(quic_recv_packet_t, pkt);
    free(recv_pkt);
}
