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

static quic_err_t quic_session_close_procedure(quic_session_t *const session);

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

    session->on_close = NULL;
    session->replace_close = NULL;
    session->quic_closed = true;
    session->remote_closed = false;

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

    quic_session_close_procedure(session);

    return 0;
}

static quic_err_t quic_session_close_procedure(quic_session_t *const session) {
    quic_sender_module_t *const sender = quic_session_module(session, quic_sender_module);
    quic_connid_gen_module_t *const connid_gen = quic_session_module(session, quic_connid_gen_module);
    quic_buf_t reason = {};
    quic_buf_init(&reason);

    if (session->on_close) {
        session->on_close(session);
    }

    quic_send_packet_t *const close_pkt = quic_sender_pack_connection_close(sender, 0, 0, reason);
    quic_buf_t buf = {};
    quic_buf_init(&buf);
    buf.buf = close_pkt->data;
    buf.capa = close_pkt->buf.pos - close_pkt->buf.buf;
    quic_buf_setpl(&buf);

    quic_connid_gen_retire_all(connid_gen);

    if (session->replace_close) {
        session->replace_close(session, buf);
    }

    free(close_pkt);

    int i;
    for (i = 0; quic_modules[i]; i++) {
        void *module = quic_session_module(session, *quic_modules[i]);
        quic_module_destory(module);
    }

    return quic_err_success;
}

quic_err_t quic_session_close(quic_session_t *const session) {
    if (session->mod_chan.closed) {
        return quic_err_success;
    }
    liteco_chan_close(&session->mod_chan);
    session->quic_closed = false;
    session->remote_closed = false;

    return quic_err_success;
}

quic_err_t quic_session_on_close(quic_session_t *const session, void (*cb) (quic_session_t *const)) {
    session->on_close = cb;

    return quic_err_success;
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

quic_err_t quic_closed_session_send_packet(quic_closed_session_t *const session) {
    return quic_transmission_send(session->transmission, session->path, session->pkt.buf, quic_buf_size(&session->pkt));
}

quic_err_t quic_session_handle_connection_close_frame(quic_session_t *const session, const quic_frame_t *const frame) {
    quic_frame_connection_close_t *const c_frame = (quic_frame_connection_close_t *) frame;
    if (session->mod_chan.closed) {
        return quic_err_success;
    }
    liteco_chan_close(&session->mod_chan);
    session->quic_closed = c_frame->first_byte == quic_frame_quic_connection_close_type;
    session->remote_closed = true;

    return quic_err_success;
}
