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
#include "modules/sender.h"
#include "format/frame.h"
#include "platform/platform.h"
#include "session.h"
#include "liteco.h"
#include <pthread.h>

typedef struct quic_framer_set_sid_s quic_framer_set_sid_t;
struct quic_framer_set_sid_s { LITECO_RBT_KEY_UINT64_FIELDS };

typedef struct quic_framer_que_sid_s quic_framer_que_sid_t;
struct quic_framer_que_sid_s {
    LITECO_LINKNODE_BASE
    uint64_t sid;
};

typedef struct quic_framer_module_s quic_framer_module_t;
struct quic_framer_module_s {
    QUIC_MODULE_FIELDS

    quic_framer_set_sid_t *active_set;
    liteco_linknode_t active_queue;

    liteco_linknode_t ctrls;

    pthread_mutex_t mtx;
};

extern quic_module_t quic_framer_module;

__quic_header_inline quic_err_t quic_framer_ctrl(quic_framer_module_t *const module, quic_frame_t *const frame) {
    liteco_link_insert_before(&module->ctrls, frame);
    return quic_err_success;
}

uint64_t quic_framer_append_stream_frame(liteco_linknode_t *const frames, const uint64_t capa, const bool fill, quic_framer_module_t *const module, quic_retransmission_module_t *const retransmission_module);
uint64_t quic_framer_append_ctrl_frame(liteco_linknode_t *const frames, const uint64_t capa, quic_framer_module_t *const module);

__quic_header_inline bool quic_framer_empty(quic_framer_module_t *const module) {
    pthread_mutex_lock(&module->mtx);
    bool result = liteco_link_empty(&module->active_queue) && liteco_link_empty(&module->ctrls);
    pthread_mutex_unlock(&module->mtx);
    return result;
}

__quic_header_inline bool quic_framer_ctrl_empty(quic_framer_module_t *const module) {
    pthread_mutex_lock(&module->mtx);
    bool result = liteco_link_empty(&module->ctrls);
    pthread_mutex_unlock(&module->mtx);
    return result;
}

__quic_header_inline quic_err_t quic_framer_add_active(quic_framer_module_t *const module, const uint64_t sid) {
    quic_session_t *const session = quic_module_of_session(module);

    pthread_mutex_lock(&module->mtx);
    if (liteco_rbt_is_nil(liteco_rbt_find(module->active_set, &sid))) {
        quic_framer_set_sid_t *set_node = malloc(sizeof(quic_framer_set_sid_t));
        if (set_node == NULL) {
            pthread_mutex_unlock(&module->mtx);
            return quic_err_internal_error;
        }
        liteco_rbt_node_init(set_node);
        set_node->key = sid;
        liteco_rbt_insert(&module->active_set, set_node);

        quic_framer_que_sid_t *que_node = malloc(sizeof(quic_framer_que_sid_t));
        if (que_node == NULL) {
            pthread_mutex_unlock(&module->mtx);
            return quic_err_internal_error;
        }
        que_node->sid = sid;
        liteco_link_insert_before(&module->active_queue, que_node);
    }
    pthread_mutex_unlock(&module->mtx);

    quic_module_activate(session, quic_sender_module);
    return quic_err_success;
}

#endif
