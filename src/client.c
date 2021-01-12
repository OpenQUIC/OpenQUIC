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

static int quic_client_epoll_cb(void *const client_);
static void *quic_client_epoll_process_thread(void *const client_);

quic_err_t quic_client_init(quic_client_t *const client, const quic_config_t cfg) {
    if ((client->stack = malloc(cfg.co_stack_size)) == NULL) {
        return quic_err_internal_error;
    }

    liteco_runtime_init(&client->rt);
    client->session = quic_session_create(cfg, client->stack, cfg.co_stack_size);
    liteco_runtime_join(&client->rt, &client->session->co);

    quic_event_epoll_init(&client->epoll, quic_client_epoll_cb);
    return quic_err_success;
}

quic_err_t quic_client_start_loop(quic_client_t *const client) {
    pthread_t thread;
    pthread_create(&thread, NULL, quic_client_epoll_process_thread, client);

    while (client->session->co.status != LITECO_TERMINATE) {
        /*uint64_t waiting = 0;*/
        switch (liteco_runtime_execute(NULL, &client->rt, &client->session->co)) {
        case LITECO_SUCCESS:
        case LITECO_BLOCKED:
            /*quic_event_epoll_process(&client->epoll, waiting > 5000 ? 5 : waiting / 1000);*/
            break;
        default:
            goto finished;
        }
    }
finished:
    return quic_err_success;
}

static void *quic_client_epoll_process_thread(void *const client_) {
    quic_client_t *const client = client_;

    for ( ;; ) {
        quic_event_epoll_process(&client->epoll, 1000);
    }

    return NULL;
}

static int quic_client_epoll_cb(void *const socket_) {
    quic_socket_t *const socket = socket_;
    quic_recver_module_t *const recver = quic_session_module(quic_recver_module_t, socket->session, quic_recver_module);
    if (quic_rbt_is_nil(socket)) {
        return quic_err_internal_error;
    }

    for ( ;; ) {
        quic_recv_packet_t *rp = malloc(sizeof(quic_recv_packet_t) + socket->mtu);
        if (rp == NULL) {
            return quic_err_internal_error;
        }
        socklen_t socklen = 0;

        int ret = recvfrom(socket->fd, rp->data, socket->mtu, 0, (struct sockaddr *) &rp->remote_addr, &socklen);

        if (ret <= 0 && errno == EAGAIN) {
            free(rp);
            return quic_err_success;
        }
        else if (ret <= 0) {
            // TODO
            return quic_err_internal_error;
        }

        rp->len = ret;
        rp->recv_time = quic_now();

        quic_recver_push(recver, rp);
    }
    return quic_err_success;
}
