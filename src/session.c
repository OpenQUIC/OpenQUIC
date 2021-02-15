/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
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
#include "modules/connid_gen.h"
#include "utils/time.h"
#include <malloc.h>

static int quic_session_run_co(void *const session_);

quic_session_t *quic_session_create(quic_transmission_t *const transmission, const quic_config_t cfg) {
    uint32_t modules_size = quic_modules_size();

    quic_session_t *session = malloc(sizeof(quic_session_t) + modules_size);
    if (session == NULL) {
        return NULL;
    }
    quic_buf_init(&session->src);
    quic_buf_init(&session->dst);

    session->cfg = cfg;
    session->loop_deadline = 0;

    session->transmission = transmission;

    session->new_connid = NULL;
    session->retire_connid = NULL;

    return session;
}

quic_err_t quic_session_init(quic_session_t *const session, liteco_eloop_t *const eloop, liteco_runtime_t *const rt, void *const st, const size_t st_len) {
    session->eloop = eloop;
    session->rt = rt;
    session->st = st;

    liteco_chan_create(&session->mod_chan, 0, liteco_runtime_readycb, rt);
    liteco_chan_create(&session->timer_chan, 0, liteco_runtime_readycb, rt);

    liteco_create(&session->co, quic_session_run_co, session, st, st_len);
    liteco_timer_init(eloop, &session->timer, &session->timer_chan);

    liteco_runtime_join(rt, &session->co, true);

    uint32_t i;
    for (i = 0; quic_modules[i]; i++) {
        quic_base_module_t *module = quic_session_module(session, *quic_modules[i]);
        module->module_declare = quic_modules[i];

        quic_module_init(module);
    }

    return quic_err_success;
}

quic_err_t quic_session_finished(quic_session_t *const session, int (*finished_cb) (void *const args), void *const args) {
    liteco_finished(&session->co, finished_cb, args);

    return quic_err_success;
}

static int quic_session_run_co(void *const session_) {
    uint32_t i;
    quic_session_t *const session = session_;

    for (i = 0; quic_modules[i]; i++) {
        quic_base_module_t *module = quic_session_module(session, *quic_modules[i]);
        module->module_declare = quic_modules[i];

        quic_module_start(module);
    }

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
            void *module = quic_session_module(session, *active_module);
            quic_module_process(module);
        }

        now = quic_now();
        for (i = 0; quic_modules[i]; i++) {
            void *module = quic_session_module(session, *quic_modules[i]);
            quic_module_loop(module, now);
        }
    }

    for (i = 0; quic_modules[i]; i++) {
        void *module = quic_session_module(session, *quic_modules[i]);
        quic_module_destory(module);
    }

    return 0;
}

quic_err_t quic_session_cert_file(quic_session_t *const session, const char *const cert_file) {
    session->cfg.tls_cert_chain_file = cert_file;
    return quic_err_success;
}

quic_err_t quic_session_key_file(quic_session_t *const session, const char *const key_file) {
    session->cfg.tls_key_file = key_file;
    return quic_err_success;
}

quic_err_t quic_session_accept(quic_session_t *const session, quic_err_t (*accept_cb) (quic_session_t *const, quic_stream_t *const)) {
    quic_stream_module_t *const module = quic_session_module(session, quic_stream_module);
    return quic_stream_accept(module, accept_cb);
}

quic_err_t quic_session_handshake_done(quic_session_t *const session, quic_err_t (*handshake_done_cb) (quic_session_t *const)) {
    quic_sealer_module_t *const module = quic_session_module(session, quic_sealer_module);
    return quic_sealer_handshake_done(module, handshake_done_cb);
}

quic_stream_t *quic_session_open(quic_session_t *const session, const bool bidi) {
    quic_stream_module_t *const module = quic_session_module(session, quic_stream_module);
    return quic_stream_open(module, bidi);
}

uint32_t quic_session_path_mtu(quic_session_t *const session) {
    return quic_transmission_get_mtu(session->transmission, session->path.local_addr);
}

quic_err_t quic_session_path_use(quic_session_t *const session, const quic_path_t path) {
    quic_migrate_module_t *const migrate = quic_session_module(session, quic_migrate_module);
    session->path = path;
    quic_migrate_path_use(migrate, session->path);

    return quic_err_success;
}

quic_err_t quic_session_path_target_use(quic_session_t *const session, const quic_addr_t remote_addr) {
    quic_migrate_module_t *const migrate = quic_session_module(session, quic_migrate_module);
    session->path.remote_addr = remote_addr;
    quic_migrate_path_use(migrate, session->path);

    return quic_err_success;
}

quic_err_t quic_session_send(quic_session_t *const session, const void *const data, const uint32_t len) {
    return quic_transmission_send(session->transmission, session->path, data, len);
}

quic_transport_parameter_t quic_session_get_transport_parameter(quic_session_t *const session) {
    quic_transport_parameter_t params;
    quic_transport_parameter_init(&params);

    params.active_connid = session->cfg.active_connid_count;

    // TODO

    return params;
}

quic_err_t quic_session_set_transport_parameter(quic_session_t *const session, const quic_transport_parameter_t params) {
    // TODO
    if (params.active_connid) {
        quic_connid_gen_module_t *const c_module = quic_session_module(session, quic_connid_gen_module);

        uint64_t i;
        for (i = 0; i < params.active_connid; i++) {
            quic_connid_gen_issue_src(c_module);
        }
    }

    return quic_err_success;
}
