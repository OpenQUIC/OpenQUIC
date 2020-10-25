/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_SESSION_H__
#define __OPENQUIC_SESSION_H__

#include "def.h"
#include "utils/buf.h"
#include "utils/errno.h"
#include "utils/rbt.h"
#include "format/frame.h"
#include "recovery/flowctrl.h"
#include "module.h"
#include <stdbool.h>
#include <sys/time.h>
#include <pthread.h>

typedef struct quic_session_s quic_session_t;
struct quic_session_s {
    QUIC_RBT_STRING_FIELDS
    quic_buf_t dst;
    uint32_t conn_len;

    bool is_cli;
    bool recv_first;
    uint64_t last_recv_time;

    pthread_t background_thread;

    liteco_channel_t module_event_pipeline;
    uint8_t modules[0];
};

#define quic_session_module(type, session, module) \
    ((type *) ((session)->modules + (module).off))

#define quic_module_of_session(instance, module) \
    ((quic_session_t *) ((((void *) (instance)) - (module).off) - offsetof(quic_session_t, modules)))

#define quic_module_activate(session, module_def) \
    (liteco_channel_send(&(session)->module_event_pipeline, &(module_def)))

quic_session_t *quic_session_create(const quic_buf_t src, const quic_buf_t dst, const bool is_cli);

typedef quic_err_t (*quic_session_handler_t) (quic_session_t *const, const quic_frame_t *const);

#endif
