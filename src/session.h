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
#include "rtt.h"
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

    uint64_t mtu;

    bool disable_prr;
    uint64_t initial_cwnd;
    uint64_t max_cwnd;
    uint64_t min_cwnd;
    bool slowstart_large_reduction;

    uint64_t stream_flowctrl_initial_rwnd;
    uint64_t stream_flowctrl_max_rwnd_size;
    uint64_t stream_flowctrl_initial_swnd;

    uint64_t conn_flowctrl_initial_rwnd;
    uint64_t conn_flowctrl_max_rwnd_size;
    uint64_t conn_flowctrl_initial_swnd;

    const char *tls_ciphers;
    const char *tls_curve_groups;

    const char *tls_cert_chain_file;
    const char *tls_key_file;
    const char *tls_verify_client_ca;

    const char **tls_ca;
    const char **tls_capath;

    bool stream_sync_close;
    uint64_t stream_destory_timeout;
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

#define quic_session_reset_loop_deadline(session) \
    (session)->loop_deadline = 0;

#define quic_session_update_loop_deadline(session, deadline)                                       \
    if ((!(session)->loop_deadline || (deadline) < (session)->loop_deadline) && (deadline) != 0) { \
        (session)->loop_deadline = (deadline);                                                     \
    }

quic_session_t *quic_session_create(const quic_config_t cfg);

typedef quic_err_t (*quic_session_handler_t) (quic_session_t *const, const quic_frame_t *const);

#endif
