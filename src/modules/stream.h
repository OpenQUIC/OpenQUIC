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
#include "format/frame.h"
#include "recovery/flowctrl.h"
#include "utils/errno.h"
#include "utils/rbt.h"
#include "utils/link.h"
#include "liteco.h"
#include <stdint.h>
#include <pthread.h>

#define QUIC_SEND_STREAM_FIELDS       \
    uint64_t sid;                     \
                                      \
    pthread_mutex_t mtx;              \
    const void *reader_buf;           \
    uint64_t reader_len;              \
    uint64_t off;                     \
                                      \
    liteco_channel_t writed_notifier; \
    liteco_channel_t *speaker;        \
    uint64_t deadline;                \
                                      \
    bool closed;                      \
                                      \

typedef struct quic_send_stream_s quic_send_stream_t;
struct quic_send_stream_s {
    QUIC_SEND_STREAM_FIELDS
};

static inline quic_err_t quic_send_stream_init(str, sid, speaker)
    quic_send_stream_t *const str;
    const uint64_t sid;
    liteco_channel_t *const speaker; {

    str->sid = sid;
    
    pthread_mutex_init(&str->mtx, NULL);
    str->reader_buf = NULL;
    str->reader_len = 0;
    str->off = 0;

    liteco_channel_init(&str->writed_notifier);
    str->speaker = speaker;
    str->deadline = 0;

    str->closed = false;

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
    liteco_channel_notify(&str->writed_notifier);
    return quic_err_success;
}

static inline quic_err_t quic_send_stream_close(quic_send_stream_t *const str) {
    pthread_mutex_lock(&str->mtx);
    if (str->closed) {
        pthread_mutex_unlock(&str->mtx);
        return quic_err_closed;
    }
    str->closed = true;
    pthread_mutex_unlock(&str->mtx);
    liteco_channel_notify(&str->writed_notifier);
    liteco_channel_send(str->speaker, &str->sid);

    return quic_err_success;
}

uint64_t quic_send_stream_write(quic_send_stream_t *const str, uint64_t len, const void *data);

quic_frame_stream_t *quic_send_stream_generate(quic_send_stream_t *const str, uint64_t bytes, const bool fill);

#define QUIC_RECV_STREAM_FIELDS        \
    uint64_t sid;                      \
                                       \
    pthread_mutex_t mtx;               \
    quic_sorter_t sorter;              \
                                       \
    liteco_channel_t handled_notifier; \
    liteco_channel_t *speaker;         \
                                       \
    uint64_t read_off;                 \
    uint64_t final_off;                \
    bool fin_flag;                     \
                                       \
    uint64_t deadline;                 \
                                       \
    bool closed;                       \

typedef struct quic_recv_stream_s quic_recv_stream_t;
struct quic_recv_stream_s {
    QUIC_RECV_STREAM_FIELDS
};

static inline quic_err_t quic_recv_stream_init(str, sid, speaker)
    quic_recv_stream_t *const str;
    const uint64_t sid;
    liteco_channel_t *const speaker; {
    str->sid = sid;
    pthread_mutex_init(&str->mtx, NULL);
    quic_sorter_init(&str->sorter);
    liteco_channel_init(&str->handled_notifier);
    str->speaker = speaker;
    str->read_off = 0;
    str->final_off = QUIC_SORTER_MAX_SIZE;
    str->fin_flag = false;
    str->deadline = 0;
    str->closed = false;

    return quic_err_success;
}

uint64_t quic_recv_stream_read(quic_recv_stream_t *const str, const uint64_t len, void *const data);

typedef struct quic_stream_s quic_stream_t;
struct quic_stream_s {
    uint64_t sid;

    quic_send_stream_t send;
    quic_recv_stream_t recv;

    quic_stream_flowctrl_module_t *flowctrl_module;
    uint8_t stream_flowctrl[0];
};

#define quic_stream_flowctrl(str) \
    ((quic_stream_flowctrl_t *) (str)->stream_flowctrl)

#define quic_send_stream_flowctrl(str) \
    (((quic_stream_t *) (((void *) (str)) - offsetof(quic_stream_t, send)))->stream_flowctrl)

#define quic_send_stream_flowctrl_module(str) \
    (((quic_stream_t *) (((void *) (str)) - offsetof(quic_stream_t, send)))->flowctrl_module)

#define quic_recv_stream_flowctrl(str) \
    (((quic_stream_t *) (((void *) (str)) - offsetof(quic_stream_t, recv)))->stream_flowctrl)

#define quic_recv_stream_flowctrl_module(str) \
    (((quic_stream_t *) (((void *) (str)) - offsetof(quic_stream_t, recv)))->flowctrl_module)

static inline quic_stream_t *quic_stream_create(sid, sess, sent_speaker, recv_speaker)
    const uint64_t sid;
    quic_session_t *const sess;
    liteco_channel_t *const sent_speaker;
    liteco_channel_t *const recv_speaker; {

    quic_stream_flowctrl_module_t *const flowctrl_module = quic_session_stream_flowctrl(sess);

    quic_stream_t *str = malloc(sizeof(quic_stream_t) + flowctrl_module->size);
    if (str == NULL) {
        return NULL;
    }
    str->sid = sid;
    str->flowctrl_module = flowctrl_module;
    quic_stream_flowctrl_init(str->flowctrl_module, quic_stream_flowctrl(str));

    printf("HERE\n");
    quic_send_stream_init(&str->send, sid, sent_speaker);
    quic_recv_stream_init(&str->recv, sid, recv_speaker);

    return str;
}

static inline quic_err_t quic_recv_stream_handle_frame(quic_recv_stream_t *const str, quic_frame_stream_t *const frame) {
    quic_err_t err = quic_err_success;
    pthread_mutex_lock(&str->mtx);
    uint64_t t_off = frame->off + frame->len;
    bool fin = (frame->first_byte & quic_frame_stream_type_fin) == quic_frame_stream_type_fin;
    bool newly_fin = false;

    quic_recv_stream_flowctrl_module(str)->update_rwnd(quic_recv_stream_flowctrl(str), t_off, fin);

    if (fin) {
        newly_fin = str->final_off == QUIC_SORTER_MAX_SIZE;
        str->final_off = t_off;
        str->fin_flag = true;
    }

    if (str->closed) {
        pthread_mutex_unlock(&str->mtx);
        if (newly_fin) {
            quic_recv_stream_flowctrl_module(str)->abandon(quic_recv_stream_flowctrl(str));
            liteco_channel_send(str->speaker, &str->sid);
        }
        return quic_err_success;
    }

    if ((err = quic_sorter_write(&str->sorter, frame->off, frame->len, frame->data)) != quic_err_success) {
        pthread_mutex_unlock(&str->mtx);
        return quic_err_success;
    }

    pthread_mutex_unlock(&str->mtx);

    liteco_channel_notify(&str->handled_notifier);
    return quic_err_success;
}

#endif
