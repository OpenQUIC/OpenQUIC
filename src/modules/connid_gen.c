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

static quic_err_t quic_connid_gen_module_init(void *const module);
static quic_err_t quic_connid_gen_module_start(void *const module);
static quic_err_t quic_connid_gen_module_destory(void *const module);

static quic_err_t quic_connid_gen_retire_src(quic_connid_gen_module_t *const module, const uint64_t seq);

static inline quic_err_t quic_connid_gen(quic_buf_t *const connid);
static inline quic_err_t quic_connid_gen_update_dst(quic_connid_gen_module_t *const module);

static inline quic_err_t quic_connid_gen(quic_buf_t *const connid) {
    if (connid->capa == 0 || connid->capa > 20) {
        return quic_err_bad_format;
    }

    RAND_bytes(connid->buf, connid->capa);
    quic_buf_setpl(connid);

    return quic_err_success;
}

quic_err_t quic_connid_gen_issue_src(quic_connid_gen_module_t *const module) {
    quic_buf_t connid;
    quic_frame_new_connection_id_t *frame = NULL;
    quic_session_t *const session = quic_module_of_session(module);
    quic_framer_module_t *const f_module = quic_session_module(session, quic_framer_module);

    quic_buf_init(&connid);
    connid.buf = malloc(module->connid_len);
    connid.capa = module->connid_len;

    for ( ;; ) {
        if (quic_connid_gen(&connid) != quic_err_success) {
            return quic_err_internal_error;
        }
        if (!module->new_connid) {
            break;
        }
        if (module->new_connid(session, connid)) {
            break;
        }
    }

    // TODO generate TOKEN
    
    quic_connid_gened_t *const gened = malloc(sizeof(quic_connid_gened_t));
    if (!gened) {
        return quic_err_internal_error;
    }
    quic_rbt_init(gened);
    gened->key = ++module->src_hseq;
    gened->connid = connid;
    quic_connid_gened_insert(&module->srcs, gened);

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

static quic_err_t quic_connid_gen_retire_src(quic_connid_gen_module_t *const module, const uint64_t seq) {
    quic_session_t *const session = quic_module_of_session(module);

    if (seq > module->src_hseq) {
        return quic_err_not_implemented;
    }

    quic_connid_gened_t *src_gened = quic_connid_gened_find(module->srcs, &seq);
    if (quic_rbt_is_nil(src_gened)) {
        return quic_err_success;
    }

    if (module->retire_connid) {
        module->retire_connid(session, src_gened->connid);
    }

    quic_rbt_remove(&module->srcs, &src_gened);
    free(src_gened->connid.buf);
    free(src_gened);

    if (seq == 0) {
        return quic_err_success;
    }

    quic_connid_gen_issue_src(module);

    return quic_err_success;
}

static quic_err_t quic_connid_gen_module_init(void *const module) {
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
    c_module->src_hseq = 0;
    c_module->dst_hretire = 0;
    quic_rbt_tree_init(c_module->srcs);
    quic_rbt_tree_init(c_module->dsts);

    c_module->dst_active = 0;

    c_module->new_connid = NULL;
    c_module->retire_connid = NULL;

    return quic_err_success;
}

static quic_err_t quic_connid_gen_module_start(void *const module) {
    quic_connid_gen_module_t *const c_module = module;
    quic_session_t *const session = quic_module_of_session(c_module);

    quic_connid_gened_t *src_gened = malloc(sizeof(quic_connid_gened_t));
    if (!src_gened) {
        return quic_err_internal_error;
    }
    quic_rbt_init(src_gened);
    src_gened->key = 0;
    src_gened->connid = session->src;

    quic_connid_gened_insert(&c_module->srcs, src_gened);

    quic_connid_gened_t *dst_gened = malloc(sizeof(quic_connid_gened_t));
    if (!dst_gened) {
        return quic_err_internal_error;
    }
    quic_rbt_init(dst_gened);
    dst_gened->key = 0;
    dst_gened->connid = session->dst;

    quic_connid_gened_insert(&c_module->dsts, dst_gened);

    return quic_err_success;
}

static quic_err_t quic_connid_gen_module_destory(void *const module) {
    quic_connid_gen_module_t *c_module = module;

    while (!quic_rbt_is_nil(c_module->srcs)) {
        quic_connid_gened_t *gened = c_module->srcs;
        quic_rbt_remove(&c_module->srcs, &gened);

        free(gened->connid.buf);
        free(gened);
    }

    while (!quic_rbt_is_nil(c_module->dsts)) {
        quic_connid_gened_t *gened = c_module->dsts;
        quic_rbt_remove(&c_module->dsts, &gened);

        free(gened->connid.buf);
        free(gened);
    }

    return quic_err_success;
}

quic_err_t quic_connid_gen_retire_all(quic_connid_gen_module_t *const module) {
    quic_session_t *const session = quic_module_of_session(module);
    quic_connid_gened_t *gened = NULL;
    quic_rbt_foreach(gened, module->srcs) {
        if (module->retire_connid) {
            module->retire_connid(session, gened->connid);
        }
    }

    return quic_err_success;
}

quic_err_t quic_connid_gen_foreach_src(quic_connid_gen_module_t *const module, void (*cb) (const quic_buf_t connid, void *args), void *const args) {
    quic_connid_gened_t *gened = NULL;
    quic_rbt_foreach(gened, module->srcs) {
        cb(gened->connid, args);
    }

    return quic_err_success;
}

quic_module_t quic_connid_gen_module = {
    .name        = "connid_gen",
    .module_size = sizeof(quic_connid_gen_module_t),
    .init        = quic_connid_gen_module_init,
    .start       = quic_connid_gen_module_start,
    .process     = NULL,
    .loop        = NULL,
    .destory     = quic_connid_gen_module_destory
};

quic_err_t quic_session_handle_new_connection_id_frame(quic_session_t *const session, const quic_frame_t *const frame) {
    quic_connid_gen_module_t *g_module = quic_session_module(session, quic_connid_gen_module);
    quic_framer_module_t *const f_module = quic_session_module(session, quic_framer_module);
    quic_frame_new_connection_id_t *const n_frame = (quic_frame_new_connection_id_t *) frame;

    if (n_frame->seq < g_module->dst_hretire) {
        quic_frame_retire_connection_id_t *const r_frame = malloc(sizeof(quic_frame_retire_connection_id_t));
        if (!r_frame) {
            return quic_err_internal_error;
        }
        quic_frame_init(r_frame, quic_frame_retire_connection_id_type);
        r_frame->seq = n_frame->seq;
        quic_framer_ctrl(f_module, (quic_frame_t *) r_frame);

        return quic_err_success;
    }

    if (n_frame->retire > g_module->dst_hretire) {
        quic_connid_gened_t *retire_gened = NULL;
        for (retire_gened = quic_rbt_min(g_module->dsts);
             !quic_rbt_is_nil(retire_gened) && retire_gened->key <= n_frame->retire;
             retire_gened = quic_rbt_min(g_module->dsts)) {

            quic_frame_retire_connection_id_t *const r_frame = malloc(sizeof(quic_frame_retire_connection_id_t));
            if (!r_frame) {
                return quic_err_internal_error;
            }
            quic_frame_init(r_frame, quic_frame_retire_connection_id_type);
            r_frame->seq = retire_gened->key;
            quic_framer_ctrl(f_module, (quic_frame_t *) r_frame);

            quic_rbt_remove(&g_module->dsts, &retire_gened);
            free(retire_gened->connid.buf);
            free(retire_gened);
        }
        g_module->dst_hretire = n_frame->retire;
    }

    if (n_frame->seq == g_module->dst_active) {
        return quic_err_success;
    }

    if (quic_rbt_is_nil(quic_connid_gened_find(g_module->dsts, &n_frame->seq))) {
        quic_connid_gened_t *dst_gened = malloc(sizeof(quic_connid_gened_t));
        if (!dst_gened) {
            return quic_err_internal_error;
        }
        quic_rbt_init(dst_gened);

        quic_buf_init(&dst_gened->connid);
        dst_gened->connid.capa = n_frame->len;
        dst_gened->connid.buf = malloc(n_frame->len);
        if (!dst_gened->connid.buf) {
            free(dst_gened);
            return quic_err_internal_error;
        }
        memcpy(dst_gened->connid.buf, n_frame->conn, n_frame->len);
        quic_buf_setpl(&dst_gened->connid);
        dst_gened->key = n_frame->seq;

        quic_connid_gened_insert(&g_module->dsts, dst_gened);
    }

    if (g_module->dst_active <= n_frame->retire) {
        quic_connid_gen_update_dst(g_module);
    }

    return quic_err_success;
}

quic_err_t quic_session_handle_retire_connection_id_frame(quic_session_t *const session, const quic_frame_t *const frame) {
    quic_frame_retire_connection_id_t *r_frame = (quic_frame_retire_connection_id_t *) frame;
    quic_connid_gen_module_t *const g_module = quic_session_module(session, quic_connid_gen_module);

    return quic_connid_gen_retire_src(g_module, r_frame->seq);
}

static inline quic_err_t quic_connid_gen_update_dst(quic_connid_gen_module_t *const module) {
    quic_session_t *const session = quic_module_of_session(module);
    quic_framer_module_t *const f_module = quic_session_module(session, quic_framer_module);

    quic_frame_retire_connection_id_t *const r_frame = malloc(sizeof(quic_frame_retire_connection_id_t));
    if (!r_frame) {
        return quic_err_internal_error;
    }
    quic_frame_init(r_frame, quic_frame_retire_connection_id_type);
    r_frame->seq = module->dst_active;
    quic_framer_ctrl(f_module, (quic_frame_t *) r_frame);

    if (module->dst_hretire < module->dst_active) {
        module->dst_hretire = module->dst_active;
    }

    // TODO retire token
    
    quic_connid_gened_t *gened = quic_connid_gened_find(module->dsts, &module->dst_active);
    if (!quic_rbt_is_nil(gened)) {
        quic_rbt_remove(&module->dsts, &gened);
        free(gened->connid.buf);
        free(gened);
        quic_buf_init(&session->dst);
    }

    gened = quic_rbt_min(module->dsts);
    if (quic_rbt_is_nil(gened)) {
        return quic_err_internal_error;
    }

    session->dst = gened->connid;
    module->dst_active = gened->key;

    // TODO add token

    return quic_err_success;
}
