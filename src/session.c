/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "session.h"
#include "module.h"
#include <malloc.h>
#include <arpa/inet.h>

static void *quic_session_background(void *const session_);
static int quic_session_background_co(void *const session_);

quic_session_t *quic_session_create(const quic_config_t cfg) {
    uint32_t modules_size = quic_modules_size();

    quic_session_t *session = malloc(sizeof(quic_session_t) + modules_size);
    if (session == NULL) {
        return NULL;
    }
    quic_rbt_init(session);
    session->dst.buf = NULL;
    quic_rtt_init(&session->rtt);

    quic_buf_copy(&session->key, &cfg.src);
    session->cfg = cfg;

    liteco_channel_init(&session->module_event_pipeline);

    int i;
    for (i = 0; quic_modules[i]; i++) {
        quic_base_module_t *module = quic_session_module(quic_base_module_t, session, *quic_modules[i]);;
        module->module_declare = quic_modules[i];

        quic_module_init(module);
    }

    pthread_create(&session->background_thread, NULL, quic_session_background, session);

    return session;
}

static void *quic_session_background(void *const session_) {
    liteco_runtime_t rt;
    liteco_runtime_init(&rt);
    uint8_t stack[4096];

    liteco_coroutine_t co;
    liteco_create(&co, stack, sizeof(stack), quic_session_background_co, session_, NULL);
    liteco_runtime_join(&rt, &co);

    while (co.status != LITECO_TERMINATE) {
        if (liteco_runtime_execute(&rt, &co) != LITECO_SUCCESS) {
            break;
        }
    }

    return NULL;
}

static int quic_session_background_co(void *const session_) {
    quic_session_t *const session = session_;
    const quic_module_t *active_module = NULL;

    for ( ;; ) {

        liteco_recv((const void **) &active_module, NULL, __CURR_CO__->runtime, 0, &session->module_event_pipeline);

        if (active_module == NULL || !active_module->process) {
            continue;
        }

        active_module->process(quic_session_module(void, session, *active_module));
    }

    return LITECO_SUCCESS;
}
