/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_FRAMER_H__
#define __OPENQUIC_FRAMER_H__

#include "module.h"
#include "modules/retransmission.h"
#include "format/frame.h"
#include "utils/rbt.h"
#include "utils/link.h"
#include "session.h"
#include <pthread.h>
#include <malloc.h>

typedef struct quic_framer_set_sid_s quic_framer_set_sid_t;
struct quic_framer_set_sid_s {
    QUIC_RBT_UINT64_FIELDS
};

#define quic_framer_set_sid_find(set, key) \
    ((quic_framer_set_sid_t *) quic_rbt_find((set), (key), quic_rbt_uint64_key_comparer))

#define quic_framer_set_sid_insert(set, sid) {               \
    quic_rbt_insert((set), (sid), quic_rbt_uint64_comparer); \
}

typedef struct quic_framer_que_sid_s quic_framer_que_sid_t;
struct quic_framer_que_sid_s {
    QUIC_LINK_FIELDS
    uint64_t sid;
};

typedef struct quic_framer_module_s quic_framer_module_t;
struct quic_framer_module_s {
    QUIC_MODULE_FIELDS

    quic_framer_set_sid_t *active_set;
    quic_link_t active_queue;

    quic_link_t ctrls;

    pthread_mutex_t mtx;
};


static inline quic_err_t quic_framer_ctrl(quic_framer_module_t *const module, quic_frame_t *const frame) {
    pthread_mutex_lock(&module->mtx);
    quic_link_insert_before(&module->ctrls, frame);
    pthread_mutex_unlock(&module->mtx);
    return quic_err_success;
}

uint64_t quic_framer_append_stream_frame(quic_link_t *const frames, const uint64_t capa, const bool fill, quic_framer_module_t *const module, quic_retransmission_module_t *const retransmission_module);

uint64_t quic_framer_append_ctrl_frame(quic_link_t *const frames, const uint64_t capa, quic_framer_module_t *const module);

extern quic_module_t quic_framer_module;
extern quic_module_t quic_sender_module;

static inline quic_err_t quic_framer_add_active(quic_framer_module_t *const module, const uint64_t sid) {
    quic_session_t *const session = quic_module_of_session(module);

    pthread_mutex_lock(&module->mtx);
    if (quic_rbt_is_nil(quic_framer_set_sid_find(module->active_set, &sid))) {
        quic_framer_set_sid_t *set_node = malloc(sizeof(quic_framer_set_sid_t));
        if (set_node == NULL) {
            pthread_mutex_unlock(&module->mtx);
            return quic_err_internal_error;
        }
        quic_rbt_init(set_node);
        set_node->key = sid;
        quic_framer_set_sid_insert(&module->active_set, set_node);

        quic_framer_que_sid_t *que_node = malloc(sizeof(quic_framer_que_sid_t));
        if (que_node == NULL) {
            pthread_mutex_unlock(&module->mtx);
            return quic_err_internal_error;
        }
        que_node->sid = sid;
        quic_link_insert_before(&module->active_queue, que_node);
    }
    pthread_mutex_unlock(&module->mtx);

    quic_module_activate(session, quic_sender_module);
    return quic_err_success;
}

#endif
