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

uint64_t quic_framer_append_stream_frame(quic_link_t *const frames, const uint64_t capa, const bool fill, quic_framer_module_t *const module) {
    quic_session_t *const session = quic_module_of_session(module, quic_framer_module);
    quic_stream_module_t *const stream_module = quic_session_module(quic_stream_module_t, session, quic_stream_module);

    uint64_t len = 0;
    pthread_mutex_lock(&module->mtx);

    if (quic_rbt_is_nil(module->active_set)) {
        goto finished;
    }

    quic_framer_que_sid_t *que_sid = (quic_framer_que_sid_t *) quic_link_next(&module->active_queue);
    quic_link_remove(que_sid);

    quic_stream_t *const stream = quic_stream_module_send_relation_stream(stream_module, que_sid->sid);
    if (stream == NULL) {
        goto remove;
    }

    bool empty = false;
    quic_frame_stream_t *frame = quic_send_stream_generate(&stream->send, &empty, capa, fill);
    if (frame == NULL) {
        goto remove;
    }
    len = frame->len;
    quic_link_insert_before(frames, frame);

    if (empty) {
        goto remove;
    }
    else {
        quic_link_insert_before(&module->active_queue, que_sid);
    }

    goto finished;

remove:
    {
        quic_link_remove(que_sid);

        quic_framer_set_sid_t *rm_set_node = quic_framer_set_sid_find(module->active_set, &que_sid->sid);
        quic_rbt_remove(&module->active_set, &rm_set_node);

        free(que_sid);
        free(rm_set_node);
    }

finished:
    pthread_mutex_unlock(&module->mtx);
    return len;
}

uint64_t quic_framer_append_ctrl_frame(quic_link_t *const frames, const uint64_t capa, quic_framer_module_t *const module) {
    uint64_t len = 0;
    quic_frame_t *frame = NULL;
    pthread_mutex_lock(&module->mtx);
    quic_link_foreach(frame, &module->ctrls) {
        len = quic_frame_size(frame);
        if (len > capa) {
            len = 0;
            continue;
        }
        quic_link_remove(frame);
        quic_link_insert_before(frames, frame);
        break;
    }
    pthread_mutex_unlock(&module->mtx);

    return len;
}

static quic_err_t quic_framer_module_init(void *const module) {
    quic_framer_module_t *const framer_module = module;

    quic_link_init(&framer_module->active_queue);
    quic_rbt_tree_init(framer_module->active_set);
    quic_link_init(&framer_module->ctrls);
    pthread_mutex_init(&framer_module->mtx, NULL);

    return quic_err_success;
}

quic_module_t quic_framer_module = {
    .module_size = sizeof(quic_framer_module_t),
    .init = quic_framer_module_init,
    .process = NULL,
    .destory = NULL
};
