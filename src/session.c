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

quic_session_t *quic_session_create(const quic_config_t cfg, uint8_t *const stack, const uint32_t stack_len) {
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

    liteco_channel_init(&session->module_event_pipeline);

    uint32_t i;
    for (i = 0; quic_modules[i]; i++) {
        quic_base_module_t *module = quic_session_module(quic_base_module_t, session, *quic_modules[i]);
        module->module_declare = quic_modules[i];

        quic_module_init(module);
    }

    liteco_create(&session->co, stack, stack_len, quic_session_run_co, session, NULL);

    return session;
}

static int quic_session_run_co(void *const session_) {
    uint32_t i;
    quic_session_t *const session = session_;
    const quic_module_t *active_module = NULL;

    // event loop
    for ( ;; ) {
        active_module = NULL;
        liteco_recv((const void **) &active_module, NULL, __CURR_CO__->runtime, session->loop_deadline, &session->module_event_pipeline);
        if (session->module_event_pipeline.closed) {
            break;
        }

        quic_session_reset_loop_deadline(session);

        if (active_module) {
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

    return LITECO_SUCCESS;
}
