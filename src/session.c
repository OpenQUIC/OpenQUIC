/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "session.h"
#include "module.h"
#include "modules/stream.h"
#include "modules/sealer.h"
#include "modules/migrate.h"
#include "utils/time.h"
#include <malloc.h>
#include <arpa/inet.h>

static int quic_session_recv_alloc_cb(liteco_udp_pkt_t **const pkt_storage, liteco_udp_t *const udp);
static void quic_session_recovery_pkt(liteco_udp_pkt_t *const pkt);
static int quic_session_run_co(void *const session_);

quic_addr_t quic_ipv4(const char *const addr, const uint16_t port) {
    quic_addr_t ret = { };
    ret.v4.sin_family = AF_INET;
    ret.v4.sin_addr.s_addr = inet_addr(addr);
    ret.v4.sin_port = htons(port);

    return ret;
}

quic_session_t *quic_session_create(const quic_config_t cfg) {
    uint32_t modules_size = quic_modules_size();

    quic_session_t *session = malloc(sizeof(quic_session_t) + modules_size);
    if (session == NULL) {
        return NULL;
    }
    quic_rbt_init(session);
    session->dst.buf = NULL;

    session->key.ref = false;
    session->key.buf = NULL;
    quic_buf_copy(&session->key, &cfg.src);
    session->cfg = cfg;
    session->loop_deadline = 0;

    return session;
}

quic_err_t quic_session_run(quic_session_t *const session, liteco_eloop_t *const eloop, liteco_runtime_t *const rt, void *const st, const size_t st_len) {
    session->eloop = eloop;
    session->rt = rt;

    liteco_chan_create(&session->mod_chan, 0, liteco_runtime_readycb, rt);
    liteco_chan_create(&session->timer_chan, 0, liteco_runtime_readycb, rt);

    liteco_create(&session->co, quic_session_run_co, session, NULL, st, st_len);
    liteco_timer_init(eloop, &session->timer, &session->timer_chan);

    liteco_runtime_join(rt, &session->co, true);

    uint32_t i;
    for (i = 0; quic_modules[i]; i++) {
        quic_base_module_t *module = quic_session_module(quic_base_module_t, session, *quic_modules[i]);
        module->module_declare = quic_modules[i];

        quic_module_init(module);
    }

    return quic_err_success;
}

static int quic_session_run_co(void *const session_) {
    uint32_t i;
    quic_session_t *const session = session_;

    // event loop
    for ( ;; ) {
        quic_module_t *active_module = NULL;
        uint64_t now = quic_now();
        if (session->loop_deadline) {
            int timeout = session->loop_deadline - now;
            if (timeout <= 0) {
                quic_session_reset_loop_deadline(session);

                active_module = liteco_chan_pop(&session->mod_chan, false);
                if (active_module == liteco_chan_pop_failed) {
                    active_module = NULL;
                }
                goto module_loop;
            }

            liteco_timer_expire(&session->timer, timeout, 0);
        }
        liteco_case_t cases[] = {
            { .chan = &session->mod_chan, .type = liteco_casetype_pop, .ele = NULL },
            { .chan = &session->timer_chan, .type = liteco_casetype_pop, .ele = NULL }
        };
        liteco_case_t *choosed_case = liteco_select(cases, 2, true);
        if (choosed_case->chan == &session->mod_chan) {
            active_module = choosed_case->ele;
        }

module_loop:
        if (session->mod_chan.closed) {
            break;
        }

        quic_session_reset_loop_deadline(session);

        if (active_module) {
            void *module = quic_session_module(void, session, *active_module);
            quic_module_process(module);
        }

        now = quic_now();
        for (i = 0; quic_modules[i]; i++) {
            void *module = quic_session_module(void, session, *quic_modules[i]);
            quic_module_loop(module, now);
        }
    }

    for (i = 0; quic_modules[i]; i++) {
        void *module = quic_session_module(void, session, *quic_modules[i]);
        quic_module_destory(module);
    }

    return 0;
}

quic_err_t quic_session_accept(quic_session_t *const session, quic_err_t (*accept_cb) (quic_session_t *const, quic_stream_t *const)) {
    quic_stream_module_t *const module = quic_session_module(quic_stream_module_t, session, quic_stream_module);
    return quic_stream_accept(module, accept_cb);
}

quic_err_t quic_session_handshake_done(quic_session_t *const session, quic_err_t (*handshake_done_cb) (quic_session_t *const)) {
    quic_sealer_module_t *const module = quic_session_module(quic_sealer_module_t, session, quic_sealer_module);
    return quic_sealer_handshake_done(module, handshake_done_cb);
}

quic_stream_t *quic_session_open(quic_session_t *const session, const bool bidi) {
    quic_stream_module_t *const module = quic_session_module(quic_stream_module_t, session, quic_stream_module);
    return quic_stream_open(module, bidi);
}

quic_err_t quic_session_path_add(liteco_eloop_t *const eloop, quic_session_t *const session, const uint64_t key, quic_addr_t local_addr, quic_addr_t remote_addr) {
    quic_migrate_module_t *const migrate = quic_session_module(quic_migrate_module_t, session, quic_migrate_module);
    quic_migrate_path_add(eloop, migrate, quic_session_recv_alloc_cb, key, local_addr, remote_addr);

    return quic_err_success;
}

quic_err_t quic_session_path_use(quic_session_t *const session, const uint64_t key) {
    quic_migrate_module_t *const migrate = quic_session_module(quic_migrate_module_t, session, quic_migrate_module);
    quic_migrate_path_use(migrate, key);

    return quic_err_success;
}

static int quic_session_recv_alloc_cb(liteco_udp_pkt_t **const pkt_storage, liteco_udp_t *const udp) {
    quic_session_t *const session = ((quic_socket_t *) (((void *) udp) - offsetof(quic_socket_t, udp)))->session;
    quic_recv_packet_t *const pkt = malloc(sizeof(quic_recv_packet_t) + 1460);
    *pkt_storage = &pkt->pkt;
    (*pkt_storage)->cap = session->cfg.mtu;
    (*pkt_storage)->recovery = quic_session_recovery_pkt;
    (*pkt_storage)->len = 0;
    return 0;
}

static void quic_session_recovery_pkt(liteco_udp_pkt_t *const pkt) {
    quic_recv_packet_t *recv_pkt = ((void *) pkt) - offsetof(quic_recv_packet_t, pkt);
    free(recv_pkt);
}
