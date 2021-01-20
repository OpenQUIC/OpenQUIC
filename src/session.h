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
#include "module.h"
#include "lc_eloop.h"
#include "lc_runtime.h"
#include "lc_timer.h"
#include "lc_coroutine.h"
#include "lc_channel.h"
#include <stdbool.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pthread.h>

typedef struct quic_stream_s quic_stream_t;

typedef struct quic_config_s quic_config_t;
struct quic_config_s {
    quic_buf_t src;
    quic_buf_t dst;

    uint32_t co_stack_size;

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

    liteco_eloop_t *eloop;
    liteco_runtime_t *rt;

    liteco_co_t co;
    liteco_chan_t mod_chan;
    liteco_chan_t timer_chan;
    liteco_timer_t timer;

    uint64_t loop_deadline;
    uint8_t modules[0];
};

#define quic_session_module(type, session, module) \
    ((type *) ((session)->modules + (module).off))

#define quic_module_of_session(module) \
    ((quic_session_t *) (((void *) (module)) - ((quic_base_module_t *) (module))->module_declare->off - offsetof(quic_session_t, modules)))

#define quic_module_activate(session, module) \
    (liteco_chan_unenforceable_push(&(session)->mod_chan, &(module)))

#define quic_session_reset_loop_deadline(session) \
    (session)->loop_deadline = 0;

#define quic_session_update_loop_deadline(session, deadline)                                       \
    if ((!(session)->loop_deadline || (deadline) < (session)->loop_deadline) && (deadline) != 0) { \
        (session)->loop_deadline = (deadline);                                                     \
    }

quic_session_t *quic_session_create(const quic_config_t cfg);
quic_err_t quic_session_run(quic_session_t *const session, liteco_eloop_t *const eloop, liteco_runtime_t *const rt, void *const st, const size_t st_len);
typedef quic_err_t (*quic_session_handler_t) (quic_session_t *const, const quic_frame_t *const);

quic_err_t quic_session_accept(quic_session_t *const session, quic_err_t (*accept_cb) (quic_session_t *const, quic_stream_t *const));
quic_err_t quic_session_handshake_done(quic_session_t *const session, quic_err_t (*handshake_done_cb) (quic_session_t *const));
quic_stream_t *quic_session_open(quic_session_t *const session, const bool bidi);

#endif
