/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_SESSION_H__
#define __OPENQUIC_SESSION_H__

#include "def.h"
#include "transmission.h"
#include "utils/buf.h"
#include "utils/errno.h"
#include "utils/rbt.h"
#include "utils/addr.h"
#include "format/frame.h"
#include "format/transport_parameter.h"
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
    bool is_cli;

    uint64_t stream_recv_timeout;

    uint32_t active_connid_count;

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

    uint64_t stream_destory_timeout;

    bool disable_migrate;
};

typedef struct quic_session_s quic_session_t;
struct quic_session_s {
    quic_buf_t src;
    quic_buf_t dst;

    quic_config_t cfg;

    liteco_eloop_t *eloop;
    liteco_runtime_t *rt;

    liteco_co_t co;
    void *st;
    liteco_chan_t mod_chan;
    liteco_chan_t timer_chan;
    liteco_timer_t timer;

    quic_transmission_t *transmission;
    quic_path_t path;

    void (*on_close) (quic_session_t *const);
    void (*replace_close) (quic_session_t *const, const quic_buf_t);
    bool quic_closed;
    bool remote_closed;

    uint64_t loop_deadline;
    uint8_t modules[0];
};

#define quic_session_module(session, module) \
    ((void *) ((session)->modules + (module).off))

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

typedef quic_err_t (*quic_session_handler_t) (quic_session_t *const, const quic_frame_t *const);

quic_session_t *quic_session_create(quic_transmission_t *const transmission, const quic_config_t cfg);
quic_err_t quic_session_init(quic_session_t *const session, liteco_eloop_t *const eloop, liteco_runtime_t *const rt, void *const st, const size_t st_len);
quic_err_t quic_session_finished(quic_session_t *const session, int (*finished_cb) (void *const args), void *const args);

quic_err_t quic_session_close(quic_session_t *const session);
quic_err_t quic_session_on_close(quic_session_t *const session, void (*cb) (quic_session_t *const));

quic_err_t quic_session_cert_file(quic_session_t *const session, const char *const cert_file);
quic_err_t quic_session_key_file(quic_session_t *const session, const char *const key_file);

quic_err_t quic_session_accept(quic_session_t *const session, const size_t extends_size, quic_err_t (*accept_cb) (quic_session_t *const, quic_stream_t *const));
quic_err_t quic_session_handshake_done(quic_session_t *const session, quic_err_t (*handshake_done_cb) (quic_session_t *const));
quic_stream_t *quic_session_open(quic_session_t *const session, const size_t extends_size, const bool bidi);

uint32_t quic_session_path_mtu(quic_session_t *const session);
quic_err_t quic_session_path_use(quic_session_t *const session, const quic_path_t path);
quic_err_t quic_session_path_target_use(quic_session_t *const session, const quic_addr_t remote_addr);
quic_err_t quic_session_send(quic_session_t *const session, const void *const data, const uint32_t len);

quic_transport_parameter_t quic_session_get_transport_parameter(quic_session_t *const session);
quic_err_t quic_session_set_transport_parameter(quic_session_t *const session, const quic_transport_parameter_t params);

typedef struct quic_closed_session_s quic_closed_session_t;
struct quic_closed_session_s {
    QUIC_RBT_STRING_FIELDS

    uint64_t closed_at;
    quic_transmission_t *transmission;
    quic_path_t path;
    quic_buf_t pkt;
};

#define quic_closed_sessions_insert(store, session) \
    quic_rbt_insert((store), (session), quic_rbt_string_comparer)

#define quic_closed_sessions_find(store, key) \
    ((quic_closed_session_t *) quic_rbt_find((store), (key), quic_rbt_string_key_comparer))

quic_err_t quic_closed_session_send_packet(quic_closed_session_t *const session);

#endif
