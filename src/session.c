/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "session.h"
#include "module.h"
#include "utils/time.h"
#include <malloc.h>
#include <arpa/inet.h>

static int quic_session_run_co(void *const session_);

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
        if (session->loop_deadline != 0) {
            liteco_timer_expire(&session->timer, session->loop_deadline - quic_now(), 0);
        }
        liteco_case_t cases[] = {
            { .chan = &session->mod_chan, .type = liteco_casetype_pop, .ele = NULL },
            { .chan = &session->timer_chan, .type = liteco_casetype_pop, .ele = NULL }
        };
        liteco_case_t *choosed_case = liteco_select(cases, 2, true);

        if (session->mod_chan.closed) {
            break;
        }

        quic_session_reset_loop_deadline(session);

        if (choosed_case->chan == &session->mod_chan) {
            quic_module_t *active_module = choosed_case->ele;
            void *module = quic_session_module(void, session, *active_module);
            quic_module_process(module);
        }

        const uint64_t now = quic_now();
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
