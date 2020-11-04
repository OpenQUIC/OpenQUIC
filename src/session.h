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
#include "recovery/rtt.h"
#include "recovery/flowctrl.h"
#include "module.h"
#include <stdbool.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pthread.h>

typedef struct quic_config_s quic_config_t;
struct quic_config_s {
    quic_buf_t src;
    union {
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
    } local_addr;
    union {
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
    } remote_addr;
    quic_buf_t dst;

    bool is_cli;
    uint32_t conn_len;

    uint64_t stream_recv_timeout;
};

typedef struct quic_session_s quic_session_t;
struct quic_session_s {
    QUIC_RBT_STRING_FIELDS
    quic_buf_t dst;

    quic_config_t cfg;

    quic_rtt_t rtt;

    pthread_t background_thread;
    liteco_channel_t module_event_pipeline;
    uint64_t loop_deadline;
    uint8_t modules[0];
};

#define quic_session_module(type, session, module) \
    ((type *) ((session)->modules + (module).off))

#define quic_module_of_session(module) \
    ((quic_session_t *) (((void *) (module)) - ((quic_base_module_t *) (module))->module_declare->off - offsetof(quic_session_t, modules)))

#define quic_module_activate(session, module) \
    (liteco_channel_send(&(session)->module_event_pipeline, &(module)))

quic_session_t *quic_session_create(const quic_config_t cfg);

typedef quic_err_t (*quic_session_handler_t) (quic_session_t *const, const quic_frame_t *const);

#endif
