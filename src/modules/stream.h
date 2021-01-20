/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_STREAM_H__
#define __OPENQUIC_STREAM_H__

#include "def.h"
#include "sorter.h"
#include "session.h"
#include "module.h"
#include "modules/stream_flowctrl.h"
#include "modules/framer.h"
#include "format/frame.h"
#include "utils/errno.h"
#include "utils/rbt.h"
#include "utils/link.h"
#include "utils/time.h"
#include "lc_channel.h"
#include <stdint.h>
#include <pthread.h>

#define QUIC_STREAM_CO_STACK 1024

#define quic_stream_id_transfer(bidi, is_client, key) \
    ((bidi) ? 0 : 2) + ((is_client) ? 0 : 1) + (((key) - 1) << 2)

#define quic_stream_id_is_bidi(id) \
    (((id) % 4) < 2)

#define quic_stream_id_is_cli(id) \
    (((id) % 2) == 0)

#define quic_stream_id_same_principal(id, session) \
    (quic_stream_id_is_cli(id) == (session)->cfg.is_cli)

extern quic_module_t quic_stream_module;

typedef struct quic_send_stream_s quic_send_stream_t;
struct quic_send_stream_s {
    pthread_mutex_t mtx;
    const void *reader_buf;
    uint64_t reader_len;
    uint64_t off;

    liteco_chan_t sent_segment_chan;
    uint64_t deadline;

    bool sent_fin;
    bool closed;
    uint32_t unacked_frames_count;
};

static inline quic_err_t quic_send_stream_init(quic_send_stream_t *const str, liteco_runtime_t *const rt) {
    
    pthread_mutex_init(&str->mtx, NULL);
    str->reader_buf = NULL;
    str->reader_len = 0;
    str->off = 0;

    liteco_chan_create(&str->sent_segment_chan, 0, liteco_runtime_readycb, rt);
    str->deadline = 0;

    str->sent_fin = false;
    str->closed = false;

    str->unacked_frames_count = 0;

    return quic_err_success;
}

static inline quic_err_t quic_send_stream_destory(quic_send_stream_t *const str) {
    liteco_chan_close(&str->sent_segment_chan);
    pthread_mutex_destroy(&str->mtx);

    return quic_err_success;
}

static inline bool quic_send_stream_empty(quic_send_stream_t *const str) {
    pthread_mutex_lock(&str->mtx);
    bool result = str->reader_len == 0;
    pthread_mutex_unlock(&str->mtx);
    return result;
}

static inline quic_err_t quic_send_stream_set_deadline(quic_send_stream_t *const str, const uint64_t deadline) {
    pthread_mutex_lock(&str->mtx);
    str->deadline = deadline;
    pthread_mutex_unlock(&str->mtx);
    liteco_chan_unenforceable_push(&str->sent_segment_chan, NULL);
    return quic_err_success;
}

quic_frame_stream_t *quic_send_stream_generate(quic_send_stream_t *const str, bool *const empty, uint64_t bytes, const bool fill);


typedef struct quic_recv_stream_s quic_recv_stream_t;
struct quic_recv_stream_s {
    pthread_mutex_t mtx;
    liteco_chan_t handled_chan;
    quic_sorter_t sorter;

    uint64_t read_off;
    uint64_t final_off;
    bool fin_flag;

    uint64_t deadline;

    bool closed;
};

static inline quic_err_t quic_recv_stream_init(quic_recv_stream_t *const str, liteco_runtime_t *const rt) {

    pthread_mutex_init(&str->mtx, NULL);
    liteco_chan_create(&str->handled_chan, 0, liteco_runtime_readycb, rt);
    quic_sorter_init(&str->sorter);
    str->read_off = 0;
    str->final_off = QUIC_SORTER_MAX_SIZE;
    str->fin_flag = false;
    str->deadline = 0;
    str->closed = false;

    return quic_err_success;
}

static inline quic_err_t quic_recv_stream_destory(quic_recv_stream_t *const str) {
    liteco_chan_close(&str->handled_chan);
    pthread_mutex_destroy(&str->mtx);
    quic_sorter_destory(&str->sorter);

    return quic_err_success;
}

typedef struct quic_stream_s quic_stream_t;
struct quic_stream_s {
    QUIC_RBT_UINT64_FIELDS

    quic_send_stream_t send;
    quic_recv_stream_t recv;

    liteco_chan_t fin_chan;

    quic_session_t *session;
    quic_stream_flowctrl_module_t *flowctrl_module;
    uint8_t extends[0];
};

#define quic_container_of_send_stream(str) \
    ((quic_stream_t *) (((void *) (str)) - offsetof(quic_stream_t, send)))

#define quic_container_of_recv_stream(str) \
    ((quic_stream_t *) (((void *) (str)) - offsetof(quic_stream_t, recv)))

#define quic_streams_insert(streams, stream) \
    quic_rbt_insert((streams), (stream), quic_rbt_uint64_comparer)

#define quic_streams_find(streams, key) \
    ((quic_stream_t *) quic_rbt_find((streams), (key), quic_rbt_uint64_key_comparer))

#define quic_stream_extends(type, str) \
    ((type *) ((str)->extends + (str)->flowctrl_module->size))

#define quic_stream_extend_flowctrl(str) \
    ((void *) ((str)->extends))

__quic_extends quic_err_t quic_stream_write(liteco_eloop_t *const eloop,
                                            quic_stream_t *const str,
                                            void *const data, const uint64_t len,
                                            quic_err_t (*write_done_cb) (quic_stream_t *const, void *const, const size_t, const size_t));

__quic_extends quic_err_t quic_stream_read(liteco_eloop_t *const eloop,
                                           quic_stream_t *const str,
                                           void *const data, const uint64_t len,
                                           quic_err_t (*read_done_cb) (quic_stream_t *const, void *const, const size_t, const size_t));

typedef struct quic_stream_set_s quic_stream_set_t;
struct quic_stream_set_s {
    pthread_mutex_t mtx;
    quic_stream_t *streams;
    uint32_t streams_count;

    uint64_t next_sid;
};

static inline quic_err_t quic_stream_set_init(quic_stream_set_t *const strset) {
    pthread_mutex_init(&strset->mtx, NULL);
    quic_rbt_tree_init(strset->streams);
    strset->streams_count = 0;
    strset->next_sid = 1;

    return quic_err_success;
}

typedef struct quic_stream_rwnd_updated_sid_s quic_stream_rwnd_updated_sid_t;
struct quic_stream_rwnd_updated_sid_s {
    QUIC_RBT_UINT64_FIELDS
};

#define quic_stream_rwnd_updated_sid_find(set, key) \
    ((quic_stream_rwnd_updated_sid_t *) quic_rbt_find((set), (key), quic_rbt_uint64_key_comparer))

#define quic_stream_rwnd_updated_sid_insert(set, sid) \
    quic_rbt_insert((set), (sid), quic_rbt_uint64_comparer); 

typedef struct quic_stream_destory_sid_s quic_stream_destory_sid_t;
struct quic_stream_destory_sid_s {
    QUIC_RBT_UINT64_FIELDS

    uint64_t destory_time;
    quic_err_t (*closed_cb) (quic_stream_t *const);
};

#define quic_stream_destory_sid_find(set, key) \
    ((quic_stream_destory_sid_t *) quic_rbt_find((set), (key), quic_rbt_uint64_key_comparer))

#define quic_stream_destory_sid_insert(set, sid) \
    quic_rbt_insert((set), (sid), quic_rbt_uint64_comparer); 

typedef struct quic_stream_module_s quic_stream_module_t;
struct quic_stream_module_s {
    QUIC_MODULE_FIELDS

    quic_stream_set_t inuni;
    quic_stream_set_t inbidi;
    quic_stream_set_t outuni;
    quic_stream_set_t outbidi;

    uint32_t extends_size;

    pthread_mutex_t rwnd_updated_mtx;
    quic_stream_rwnd_updated_sid_t *rwnd_updated;

    pthread_mutex_t destory_mtx;
    quic_stream_destory_sid_t *destory_set;

    quic_err_t (*init) (quic_stream_t *const str);
    void (*destory) (quic_stream_t *const str);

    quic_err_t (*accept_cb) (quic_session_t *const, quic_stream_t *const);
};

static inline quic_err_t quic_stream_module_update_rwnd(quic_stream_module_t *const module, const uint64_t sid) {
    pthread_mutex_lock(&module->rwnd_updated_mtx);
    if (quic_rbt_is_nil(quic_stream_rwnd_updated_sid_find(module->rwnd_updated, &sid))) {
        quic_stream_rwnd_updated_sid_t *updated_sid = malloc(sizeof(quic_stream_rwnd_updated_sid_t));
        if (updated_sid) {
            quic_rbt_init(updated_sid);
            updated_sid->key = sid;

            quic_stream_rwnd_updated_sid_insert(&module->rwnd_updated, updated_sid);
        }
    }
    pthread_mutex_unlock(&module->rwnd_updated_mtx);

    return quic_err_success;
}

quic_err_t quic_stream_module_process_rwnd(quic_stream_module_t *const module);

__quic_extends quic_stream_t *quic_stream_open(quic_stream_module_t *const module, const bool bidi);
__quic_extends quic_err_t quic_stream_close(quic_stream_t *const str, quic_err_t (*closed_cb) (quic_stream_t *const));
__quic_extends bool quic_stream_remote_closed(quic_stream_t *const str);

quic_stream_t *quic_stream_module_send_relation_stream(quic_stream_module_t *const module, const uint64_t sid);

static inline quic_err_t quic_stream_accept(quic_stream_module_t *const module, quic_err_t (*accept_cb) (quic_session_t *const, quic_stream_t *const)) {
    module->accept_cb = accept_cb;
    return quic_err_success;
}

#endif
