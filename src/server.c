/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "format/header.h"
#include "modules/recver.h"
#include "modules/connid_gen.h"
#include "utils/time.h"
#include "server.h"
#include <openssl/rand.h>

const quic_config_t quic_server_default_config = {
    .is_cli = false,
    .stream_recv_timeout = 0,
    .active_connid_count = 2,
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
    .stream_destory_timeout = 0,
    .disable_migrate = false,
};

static quic_err_t quic_server_transmission_recv_cb(quic_transmission_t *const transmission, quic_recv_packet_t *const recvpkt);
static int quic_server_session_free_st_cb(void *const args);

static bool quic_server_new_connid_cb(quic_session_t *const session, const quic_buf_t connid);
static void quic_server_retire_connid_cb(quic_session_t *const session, const quic_buf_t connid);
static void quic_server_session_replace_close_cb(quic_session_t *const session, const quic_buf_t pkt);

static void quic_session_close_foreach_src_cb(const quic_buf_t connid, void *args);

quic_err_t quic_server_init(quic_server_t *const server, const size_t st_size) {
    uint8_t rand = 0;
    /*if (RAND_bytes(&rand, 1) <= 0) {*/
        /*return quic_err_internal_error;*/
    /*}*/

    liteco_eloop_init(&server->eloop);
    liteco_runtime_init(&server->eloop, &server->rt);
    quic_transmission_init(&server->transmission, &server->rt);
    quic_transmission_recv(&server->transmission, quic_server_transmission_recv_cb);

    server->st_size = st_size;
    server->connid_len = 8 + rand % 11;
    server->cfg = quic_server_default_config;

    quic_rbt_tree_init(server->sessions);
    quic_rbt_tree_init(server->closed_sessions);

    server->accept_cb = NULL;

    return quic_err_success;
}

quic_err_t quic_server_cert_file(quic_server_t *const server, const char *const cert_file) {
    server->cfg.tls_cert_chain_file = cert_file;

    return quic_err_success;
}

quic_err_t quic_server_key_file(quic_server_t *const server, const char *const key_file) {
    server->cfg.tls_key_file = key_file;

    return quic_err_success;
}

quic_err_t quic_server_listen(quic_server_t *const server, const quic_addr_t local_addr) {
    return quic_transmission_listen(&server->eloop, &server->transmission, local_addr, 1460);
}

quic_err_t quic_server_accept(quic_server_t *const server, quic_err_t (*accept_cb) (quic_server_t *const, quic_session_t *const)) {
    server->accept_cb = accept_cb;

    return quic_err_success;
}

quic_err_t quic_server_start_loop(quic_server_t *const server) {
    for ( ;; ) {
        liteco_eloop_run(&server->eloop, -1);
    }
    return quic_err_success;
}

static quic_err_t quic_server_transmission_recv_cb(quic_transmission_t *const transmission, quic_recv_packet_t *const recvpkt) {
    quic_server_t *const server = ((void *) transmission) - offsetof(quic_server_t, transmission);

    quic_header_t *const header = (quic_header_t *) recvpkt->pkt.data;
    if (quic_packet_type(header) == quic_packet_initial_type) {
        quic_buf_t cli_dst = quic_long_header_dst_conn(header);
        quic_buf_t cli_src = quic_long_header_src_conn(header);
        quic_buf_setpl(&cli_dst);
        quic_buf_setpl(&cli_src);

        quic_session_t *const session = quic_session_create(&server->transmission, quic_server_default_config);
        quic_buf_copy(&session->src, &cli_dst);
        quic_buf_copy(&session->dst, &cli_src);
        session->cfg = server->cfg;
        session->replace_close = quic_server_session_replace_close_cb;

        void *st = malloc(server->st_size);
        if (!st) {
            return quic_err_internal_error;
        }
        quic_session_init(session, &server->eloop, &server->rt, st, server->st_size);
        quic_session_finished(session, quic_server_session_free_st_cb, st);

        quic_connid_gen_module_t *g_module = quic_session_module(session, quic_connid_gen_module);
        g_module->new_connid = quic_server_new_connid_cb;
        g_module->retire_connid = quic_server_retire_connid_cb;
 
        liteco_runtime_join(&server->rt, &session->co, true);

        quic_session_path_use(session, quic_path_addr(quic_litecoaddr(recvpkt->pkt.local_addr), quic_litecoaddr(recvpkt->pkt.remote_addr)));

        if (server->accept_cb) {
            server->accept_cb(server, session);
        }

        quic_recver_module_t *const r_module = quic_session_module(session, quic_recver_module);
        return quic_recver_push(r_module, recvpkt);
    }

    quic_buf_t target;
    quic_buf_init(&target);
    if (quic_header_is_long(header)) {
        quic_buf_t cli_dst = quic_long_header_dst_conn(header);
        target = cli_dst;
    }
    else {
        quic_buf_t cli_dst = quic_short_header_dst_conn(header, server->connid_len);
        target = cli_dst;
    }
    quic_buf_setpl(&target);

    quic_session_store_t *store = quic_session_store_find(server->sessions, &target);
    if (quic_rbt_is_nil(store)) {
        quic_recv_packet_recovery(recvpkt);
        return quic_err_success;
    }

    quic_recver_module_t *const r_module = quic_session_module(store->session, quic_recver_module);
    return quic_recver_push(r_module, recvpkt);
}

static int quic_server_session_free_st_cb(void *const args) {
    free(args);

    return 0;
}

static bool quic_server_new_connid_cb(quic_session_t *const session, const quic_buf_t connid) {
    quic_server_t *const server = ((void *) session->transmission) - offsetof(quic_server_t, transmission);

    quic_session_store_t *store = quic_session_store_find(server->sessions, &connid);
    if (!quic_rbt_is_nil(store)) {
        return false;
    }
    store = malloc(sizeof(quic_session_store_t));
    if (!store) {
        return false;
    }
    quic_rbt_init(store);
    store->key = connid;
    store->session = session;

    quic_session_store_insert(&server->sessions, store);

    return true;
}

static void quic_server_retire_connid_cb(quic_session_t *const session, const quic_buf_t connid) {
    quic_server_t *const server = ((void *) session->transmission) - offsetof(quic_server_t, transmission);

    quic_session_store_t *store = quic_session_store_find(server->sessions, &connid);
    if (quic_rbt_is_nil(store)) {
        return;
    }

    quic_rbt_remove(&server->sessions, &store);
    free(store);
}

typedef struct quic_connid_gen_foreach_src_param_s quic_connid_gen_foreach_src_param_t;
struct quic_connid_gen_foreach_src_param_s {
    quic_session_t *const session;
    const quic_buf_t *const pkt;
};

static void quic_server_session_replace_close_cb(quic_session_t *const session, const quic_buf_t pkt) {
    quic_connid_gen_module_t *const g_module = quic_session_module(session, quic_connid_gen_module);

    quic_connid_gen_foreach_src_param_t params = { .session = session, .pkt = &pkt };
    quic_connid_gen_foreach_src(g_module, quic_session_close_foreach_src_cb, &params);

    quic_transmission_send(session->transmission, session->path, pkt.buf, quic_buf_size(&pkt));
}


static void quic_session_close_foreach_src_cb(const quic_buf_t connid, void *args) {
    quic_connid_gen_foreach_src_param_t *const param = args;
    quic_session_t *const session = param->session;
    const quic_buf_t *const pkt = param->pkt;

    quic_server_t *const server = ((void *) session->transmission) - offsetof(quic_server_t, transmission);

    quic_closed_session_t *const closed_session = malloc(sizeof(quic_closed_session_t));
    if (!closed_session) {
        return;
    }
    quic_rbt_init(closed_session);

    closed_session->closed_at = quic_now();
    quic_buf_init(&closed_session->key);
    quic_buf_copy(&closed_session->key, &connid);
    closed_session->transmission = &server->transmission;
    closed_session->path = session->path;
    quic_buf_init(&closed_session->pkt);
    quic_buf_copy(&closed_session->pkt, pkt);

    quic_closed_sessions_insert(&server->closed_sessions, closed_session);
}
