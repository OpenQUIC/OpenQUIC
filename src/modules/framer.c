/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "modules/framer.h"
#include "modules/stream.h"

static quic_err_t quic_framer_module_init(void *const module);
static quic_err_t quic_framer_module_destory(void *const module);

static quic_err_t quic_framer_stream_frame_on_lost(void *const lost_obj, const quic_frame_t *const frame);

uint64_t quic_framer_append_stream_frame(liteco_linknode_t *const frames, const uint64_t capa, const bool fill, quic_framer_module_t *const module, quic_retransmission_module_t *const retransmission_module) {
    quic_session_t *const session = quic_module_of_session(module);
    quic_stream_module_t *const stream_module = quic_session_module(session, quic_stream_module);

    uint64_t len = 0;
    quic_framer_que_sid_t *que_sid = NULL;
    pthread_mutex_lock(&module->mtx);

    if (liteco_rbt_is_nil(module->active_set)) {
        goto finished;
    }

    que_sid = (quic_framer_que_sid_t *) liteco_link_next(&module->active_queue);
    liteco_link_remove(que_sid);

    quic_stream_t *const stream = quic_stream_module_send_relation_stream(stream_module, que_sid->sid);
    if (stream == NULL || liteco_rbt_is_nil(stream)) {
        goto remove;
    }

    bool empty = false;
    quic_frame_stream_t *frame = quic_send_stream_generate(&stream->send, &empty, capa, fill);
    if (frame == NULL) {
        goto finished;
    }
    frame->lost_obj = retransmission_module;
    frame->on_lost = quic_framer_stream_frame_on_lost;

    len = quic_frame_size(frame);
    liteco_link_insert_before(frames, frame);

    if (empty) {
        goto remove;
    }
    goto finished;

remove:
    {
        liteco_link_remove(que_sid);

        quic_framer_set_sid_t *rm_set_node = liteco_rbt_find(module->active_set, &que_sid->sid);
        liteco_rbt_remove(&module->active_set, &rm_set_node);

        free(que_sid);
        que_sid = NULL;
        free(rm_set_node);
    }

finished:
    if (que_sid != NULL) {
        liteco_link_insert_before(&module->active_queue, que_sid);
    }
    pthread_mutex_unlock(&module->mtx);
    return len;
}

uint64_t quic_framer_append_ctrl_frame(liteco_linknode_t *const frames, const uint64_t capa, quic_framer_module_t *const module) {
    uint64_t len = 0;
    quic_frame_t *frame = NULL;
    pthread_mutex_lock(&module->mtx);
    liteco_link_foreach(frame, &module->ctrls) {
        len = quic_frame_size(frame);
        if (len > capa) {
            len = 0;
            continue;
        }
        liteco_link_remove(frame);
        liteco_link_insert_before(frames, frame);
        break;
    }
    pthread_mutex_unlock(&module->mtx);

    return len;
}

static quic_err_t quic_framer_stream_frame_on_lost(void *const lost_obj, const quic_frame_t *const frame) {
    quic_retransmission_module_t *const r_module = lost_obj;
    quic_retransmission_frame_insert(r_module, (quic_frame_t *) frame);

    return quic_err_success;
}

static quic_err_t quic_framer_module_init(void *const module) {
    quic_framer_module_t *const framer_module = module;

    liteco_link_init(&framer_module->active_queue);
    liteco_rbt_init(framer_module->active_set);
    liteco_link_init(&framer_module->ctrls);
    pthread_mutex_init(&framer_module->mtx, NULL);

    return quic_err_success;
}

static quic_err_t quic_framer_module_destory(void *const module) {
    quic_framer_module_t *const f_module = module;

    pthread_mutex_destroy(&f_module->mtx);

    while (!liteco_link_empty(&f_module->active_queue)) {
        quic_framer_que_sid_t *const que_sid = (quic_framer_que_sid_t *) liteco_link_next(&f_module->active_queue);
        liteco_link_remove(que_sid);
        free(que_sid);
    }

    while (!liteco_link_empty(&f_module->ctrls)) {
        quic_frame_t *frame = (quic_frame_t *) liteco_link_next(&f_module->ctrls);
        liteco_link_remove(frame);
        free(frame);
    }

    while (!liteco_rbt_is_nil(f_module->active_set)) {
        quic_framer_set_sid_t *sid = f_module->active_set;
        liteco_rbt_remove(&f_module->active_set, &sid);
        free(sid);
    }

    return quic_err_success;
}

quic_module_t quic_framer_module = {
    .name        = "framer",
    .module_size = sizeof(quic_framer_module_t),
    .init        = quic_framer_module_init,
    .start       = NULL,
    .process     = NULL,
    .loop        = NULL,
    .destory     = quic_framer_module_destory
};
