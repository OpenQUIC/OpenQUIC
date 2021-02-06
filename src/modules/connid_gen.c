/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "modules/connid_gen.h"
#include "modules/framer.h"
#include "format/frame.h"
#include "session.h"
#include "client.h"
#include "server.h"
#include <openssl/rand.h>

static quic_err_t quic_connid_gen_init(void *const module);
static quic_err_t quic_connid_gen_start(void *const module);

static inline quic_err_t quic_connid_gen(quic_buf_t *const connid);

static inline quic_err_t quic_connid_gen(quic_buf_t *const connid) {
    if (connid->capa == 0 || connid->capa > 20) {
        return quic_err_bad_format;
    }

    RAND_bytes(connid->buf, connid->capa);
    quic_buf_setpl(connid);

    return quic_err_success;
}

quic_err_t quic_connid_gen_issue(quic_connid_gen_module_t *const module) {
    quic_buf_t connid;
    quic_frame_new_connection_id_t *frame = NULL;
    quic_session_t *const session = quic_module_of_session(module);
    quic_framer_module_t *const f_module = quic_session_module(quic_framer_module_t, session, quic_framer_module);

    quic_buf_init(&connid);
    connid.buf = malloc(module->connid_len);
    connid.capa = module->connid_len;

    for ( ;; ) {
        if (quic_connid_gen(&connid) != quic_err_success) {
            return quic_err_internal_error;
        }
        if (!session->new_connid) {
            break;
        }
        if (session->new_connid(session, connid)) {
            break;
        }
    }

    // TODO generate TOKEN
    
    quic_connid_gened_t *const gened = malloc(sizeof(quic_connid_gened_t));
    if (!gened) {
        return quic_err_internal_error;
    }
    gened->key = ++module->highest_seq;
    gened->connid = connid;

    if ((frame = malloc(sizeof(quic_frame_new_connection_id_t))) == NULL) {
        return quic_err_internal_error;
    }
    quic_frame_init(frame, quic_frame_new_connection_id_type);
    frame->seq = gened->key;
    frame->retire = 0;
    frame->len = quic_buf_size(&gened->connid);
    memcpy(frame->conn, gened->connid.pos, frame->len);

    quic_framer_ctrl(f_module, (quic_frame_t *) frame);

    return quic_err_success;
}

static quic_err_t quic_connid_gen_init(void *const module) {
    quic_connid_gen_module_t *const c_module = module;
    quic_session_t *const session = quic_module_of_session(c_module);

    if (session->cfg.is_cli) {
        quic_client_t *const client = ((void *) session->transmission) - offsetof(quic_client_t, transmission);

        c_module->connid_len = client->connid_len;
    }
    else {
        quic_server_t *const server = ((void *) session->transmission) - offsetof(quic_server_t, transmission);

        c_module->connid_len = server->connid_len;
    }
    c_module->highest_seq = 0;
    quic_rbt_tree_init(c_module->srcs);

    return quic_err_success;
}

static quic_err_t quic_connid_gen_start(void *const module) {
    quic_connid_gen_module_t *const c_module = module;
    quic_session_t *const session = quic_module_of_session(c_module);

    quic_connid_gened_t *gened = malloc(sizeof(quic_connid_gened_t));
    if (!gened) {
        return quic_err_internal_error;
    }
    quic_rbt_init(gened);
    gened->key = 0;
    quic_buf_init(&gened->connid);
    quic_buf_copy(&gened->connid, &session->src);

    quic_connid_gened_insert(&c_module->srcs, gened);

    return quic_err_success;
}

quic_module_t quic_connid_gen_module = {
    .name        = "connid_gen",
    .module_size = sizeof(quic_connid_gen_module_t),
    .init        = quic_connid_gen_init,
    .start       = quic_connid_gen_start,
    .process     = NULL,
    .loop        = NULL,
    .destory     = NULL
};
