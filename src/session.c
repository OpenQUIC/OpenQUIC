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

quic_session_t *quic_session_create(const quic_buf_t src, const quic_buf_t dst) {
    uint32_t modules_size = quic_modules_size();

    quic_session_t *session = malloc(sizeof(quic_session_t) + modules_size);
    if (session == NULL) {
        return NULL;
    }
    quic_rbt_init(session);

    quic_buf_copy(&session->key, &src);
    quic_buf_copy(&session->dst, &dst);

    liteco_channel_init(&session->module_event_pipeline);

    int i;
    for (i = 0; quic_modules[i]; i++) {
        if (quic_modules[i]->init) {
            quic_modules[i]->init(quic_session_module(void, session, *quic_modules[i]));
        }
    }

    return session;
}
