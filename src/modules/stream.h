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

__quic_extends quic_err_t quic_stream_write(liteco_eloop_t *const eloop, quic_stream_t *const str, void *const data, const uint64_t len);
__quic_extends quic_err_t quic_stream_read(liteco_eloop_t *const eloop, quic_stream_t *const str, void *const data, const uint64_t len);

static inline bool quic_stream_destroable(quic_stream_t *const str) {
    return str->recv.closed && str->recv.fin_flag && str->send.closed && str->send.sent_fin;
}

static inline quic_stream_t *quic_stream_create(quic_session_t *const session, const uint64_t sid, const uint32_t extends_size) {
    quic_stream_flowctrl_module_t *const f_module = quic_session_module(quic_stream_flowctrl_module_t, session, quic_stream_flowctrl_module);

    quic_stream_t *str = malloc(sizeof(quic_stream_t) + f_module->module_size + extends_size);
    if (str == NULL) {
        return NULL;
    }
    quic_rbt_init(str);
    str->key = sid;
    str->session = session;
    str->flowctrl_module = f_module;
    quic_stream_flowctrl_init(str->flowctrl_module, quic_stream_extend_flowctrl(str));

    quic_send_stream_init(&str->send, session->rt);
    quic_recv_stream_init(&str->recv, session->rt);

    liteco_chan_create(&str->fin_chan, 0, liteco_runtime_readycb, session->rt);

    str->recv.deadline = session->cfg.stream_recv_timeout;

    return str;
}

static inline quic_err_t quic_stream_destory(quic_stream_t *const str, quic_session_t *const session) {
    quic_stream_flowctrl_module_t *const flowctrl_module = quic_session_module(quic_stream_flowctrl_module_t, session, quic_stream_flowctrl_module);

    quic_send_stream_destory(&str->send);
    quic_recv_stream_destory(&str->recv);

    quic_stream_flowctrl_destory(flowctrl_module, quic_stream_extend_flowctrl(str));

    free(str);

    return quic_err_success;
}

#define QUIC_STREAMS_FIELDS \
    pthread_mutex_t mtx;    \
    quic_stream_t *streams; \
    uint32_t streams_count; \

#define quic_streams_basic_init(strs) {     \
    pthread_mutex_init(&(strs)->mtx, NULL); \
    quic_rbt_tree_init((strs)->streams);    \
    (strs)->streams_count = 0;              \
}

typedef struct quic_inbidi_streams_s quic_inbidi_streams_t;
struct quic_inbidi_streams_s {
    QUIC_STREAMS_FIELDS
};

static inline quic_err_t quic_inbidi_streams_init(quic_inbidi_streams_t *const strs) {
    quic_streams_basic_init(strs);

    return quic_err_success;
}

typedef struct quic_inuni_streams_s quic_inuni_streams_t;
struct quic_inuni_streams_s {
    QUIC_STREAMS_FIELDS
};

static inline quic_err_t quic_inuni_streams_init(quic_inuni_streams_t *const strs) {
    quic_streams_basic_init(strs);

    return quic_err_success;
}

typedef struct quic_outbidi_streams_s quic_outbidi_streams_t;
struct quic_outbidi_streams_s {
    QUIC_STREAMS_FIELDS

    uint64_t next_sid;
};

static inline quic_err_t quic_outbidi_streams_init(quic_outbidi_streams_t *const strs) {
    quic_streams_basic_init(strs);
    strs->next_sid = 1;

    return quic_err_success;
}

typedef struct quic_outuni_streams_s quic_outuni_streams_t;
struct quic_outuni_streams_s {
    QUIC_STREAMS_FIELDS

    uint64_t next_sid;
};

static inline quic_err_t quic_outuni_streams_init(quic_outuni_streams_t *const strs) {
    quic_streams_basic_init(strs);
    strs->next_sid = 1;

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
};

#define quic_stream_destory_sid_find(set, key) \
    ((quic_stream_destory_sid_t *) quic_rbt_find((set), (key), quic_rbt_uint64_key_comparer))

#define quic_stream_destory_sid_insert(set, sid) \
    quic_rbt_insert((set), (sid), quic_rbt_uint64_comparer); 

typedef struct quic_stream_module_s quic_stream_module_t;
struct quic_stream_module_s {
    QUIC_MODULE_FIELDS

    quic_inuni_streams_t inuni;
    quic_inbidi_streams_t inbidi;
    quic_outuni_streams_t outuni;
    quic_outbidi_streams_t outbidi;

    uint32_t extends_size;

    pthread_mutex_t rwnd_updated_mtx;
    quic_stream_rwnd_updated_sid_t *rwnd_updated;

    pthread_mutex_t destory_mtx;
    quic_stream_destory_sid_t *destory_set;

    quic_err_t (*init) (quic_stream_t *const str);
    void (*destory) (quic_stream_t *const str);
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

static inline quic_err_t quic_stream_destory_push(quic_stream_module_t *const module, const uint64_t sid) {
    pthread_mutex_lock(&module->destory_mtx);
    if (quic_rbt_is_nil(quic_stream_destory_sid_find(module->destory_set, &sid))) {
        quic_stream_destory_sid_t *d_sid = malloc(sizeof(quic_stream_destory_sid_t));
        if (d_sid) {
            quic_rbt_init(d_sid);
            d_sid->key = sid;
            d_sid->destory_time = quic_now();

            quic_stream_destory_sid_insert(&module->destory_set, d_sid);
        }
    }
    pthread_mutex_unlock(&module->destory_mtx);

    return quic_err_success;
}

quic_err_t quic_stream_module_process_rwnd(quic_stream_module_t *const module);

#define quic_stream_inuni_module(str) \
    ((quic_stream_module_t *) (((void *) (str)) - offsetof(quic_stream_module_t, inuni)))

#define quic_stream_inbidi_module(str) \
    ((quic_stream_module_t *) (((void *) (str)) - offsetof(quic_stream_module_t, inbidi)))

#define quic_stream_outuni_module(str) \
    ((quic_stream_module_t *) (((void *) (str)) - offsetof(quic_stream_module_t, outuni)))

#define quic_stream_outbidi_module(str) \
    ((quic_stream_module_t *) (((void *) (str)) - offsetof(quic_stream_module_t, outbidi)))

#define quic_streams_delete(strs, container_of_module, sid) {          \
    quic_stream_module_t *const _module = container_of_module(strs);   \
    pthread_mutex_lock(&(strs)->mtx);                                  \
    quic_stream_t *stream = quic_streams_find((strs)->streams, (sid)); \
    if (!quic_rbt_is_nil(stream)) {                                    \
        quic_rbt_remove(&(strs)->streams, &stream);                    \
        if (_module->destory) {                                        \
            _module->destory(stream);                                  \
        }                                                              \
        quic_stream_destory(stream, quic_module_of_session(_module));  \
    }                                                                  \
    pthread_mutex_unlock(&strs->mtx);                                  \
}

#define quic_stream_outuni_delete(strs, sid) \
    quic_streams_delete((strs), quic_stream_outuni_module, (sid))

#define quic_stream_outbidi_delete(strs, sid) \
    quic_streams_delete((strs), quic_stream_outbidi_module, (sid))

#define quic_stream_inbidi_delete(strs, sid) \
    quic_streams_delete((strs), quic_stream_inbidi_module, (sid))

#define quic_stream_inuni_delete(strs, sid) \
    quic_streams_delete((strs), quic_stream_inuni_module, (sid))

__quic_extends quic_stream_t *quic_session_open_send_stream(quic_session_t *const session, const bool bidi);
__quic_extends quic_err_t quic_stream_close(quic_stream_t *const str);
__quic_extends bool quic_stream_remote_closed(quic_stream_t *const str);

quic_stream_t *quic_stream_module_send_relation_stream(quic_stream_module_t *const module, const uint64_t sid);

static inline quic_err_t quic_recv_stream_handle_frame(quic_recv_stream_t *const str, const quic_frame_stream_t *const frame) {
    quic_err_t err = quic_err_success;
    quic_stream_t *const p_str = quic_container_of_recv_stream(str);
    quic_stream_flowctrl_module_t *const flowctrl_module = p_str->flowctrl_module;

    pthread_mutex_lock(&str->mtx);
    uint64_t t_off = frame->off + frame->len;
    bool fin = (frame->first_byte & quic_frame_stream_type_fin) == quic_frame_stream_type_fin;
    bool newly_fin = false;

    quic_stream_flowctrl_update_rwnd(flowctrl_module, quic_stream_extend_flowctrl(p_str), t_off, fin);

    if (fin) {
        newly_fin = !str->fin_flag;

        str->final_off = t_off;
        str->fin_flag = true;

        liteco_chan_close(&p_str->fin_chan);
    }

    if (str->closed) {
        pthread_mutex_unlock(&str->mtx);
        return quic_err_success;
    }

    if (frame->len == 0) {
        pthread_mutex_unlock(&str->mtx);

        if (fin && newly_fin) {
            liteco_chan_unenforceable_push(&str->handled_chan, NULL);
        }
        return quic_err_success;
    }

    uint64_t readable_size = quic_sorter_readable(&str->sorter);
    if ((err = quic_sorter_write(&str->sorter, frame->off, frame->len, frame->data)) != quic_err_success) {
        pthread_mutex_unlock(&str->mtx);
        return quic_err_success;
    }
    bool notify = readable_size != quic_sorter_readable(&str->sorter);

    pthread_mutex_unlock(&str->mtx);

    if (notify) {
        liteco_chan_unenforceable_push(&str->handled_chan, NULL);
    }
    return quic_err_success;
}

static inline quic_err_t quic_recv_stream_close(quic_recv_stream_t *const str) {
    quic_stream_t *const p_str = quic_container_of_recv_stream(str);
    quic_stream_flowctrl_module_t *const flowctrl_module = p_str->flowctrl_module;
    bool completed = false;

    pthread_mutex_lock(&str->mtx);
    if (str->closed) {
        goto end;
    }
    str->closed = true;
    completed = str->fin_flag;
    quic_sorter_destory(&str->sorter);
end:
    pthread_mutex_unlock(&str->mtx);
    liteco_chan_close(&str->handled_chan);

    if (completed) {
        quic_stream_flowctrl_abandon(flowctrl_module, quic_stream_extend_flowctrl(p_str));
    }
    return quic_err_success;
}

static inline quic_err_t quic_send_stream_close(quic_send_stream_t *const str) {
    quic_stream_t *const p_str = quic_container_of_send_stream(str);
    quic_framer_module_t *const framer_module = quic_session_module(quic_framer_module_t, p_str->session, quic_framer_module);

    pthread_mutex_lock(&str->mtx);
    if (str->closed) {
        pthread_mutex_unlock(&str->mtx);
        return quic_err_closed;
    }
    str->closed = true;
    pthread_mutex_unlock(&str->mtx);
    quic_framer_add_active(framer_module, p_str->key); // send fin flag
    liteco_chan_unenforceable_push(&str->sent_segment_chan, NULL); // notify app writed

    return quic_err_success;
}

static inline quic_err_t quic_send_stream_handle_max_stream_data_frame(quic_send_stream_t *const str, const quic_frame_max_stream_data_t *const frame) {
    quic_stream_t *const p_str = quic_container_of_send_stream(str);
    quic_stream_flowctrl_module_t *const f_module = quic_session_module(quic_stream_flowctrl_module_t, p_str->session, quic_stream_flowctrl_module);
    quic_framer_module_t *const framer_module = quic_session_module(quic_framer_module_t, p_str->session, quic_framer_module);

    pthread_mutex_lock(&str->mtx);
    bool remain = str->reader_len != 0;
    pthread_mutex_unlock(&str->mtx);

    quic_stream_flowctrl_update_swnd(f_module, quic_stream_extend_flowctrl(p_str), frame->max_data);
    if (remain) {
        quic_framer_add_active(framer_module, p_str->key);
    }

    return quic_err_success;
}

#endif
