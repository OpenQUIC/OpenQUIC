/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_STREAM_H__
#define __OPENQUIC_STREAM_H__

#include "sorter.h"
#include "format/frame.h"
#include "flowctrl/flowctrl_base.h"
#include "utils/errno.h"
#include "utils/rbt.h"
#include "utils/link.h"
#include "liteco.h"
#include <stdint.h>
#include <pthread.h>

#define QUIC_SEND_STREAM_FIELDS             \
    uint64_t sid;                           \
                                            \
    pthread_mutex_t mtx;                    \
    const void *reader_buf;                 \
    uint64_t reader_len;                    \
    uint64_t off;                           \
                                            \
    liteco_channel_t writed_notifier;       \
    liteco_channel_t *process_sid;          \
    uint64_t deadline;                      \
                                            \
    bool closed;                            \
                                            \
    quic_flowctrl_t *flowctrl;              \

typedef struct quic_send_stream_s quic_send_stream_t;
struct quic_send_stream_s {
    QUIC_SEND_STREAM_FIELDS
};

uint64_t quic_send_stream_write(quic_send_stream_t *const str, uint64_t len, const void *data);
quic_frame_stream_t *quic_send_stream_generate(quic_send_stream_t *const str, uint64_t bytes, const bool fill);

static inline quic_err_t quic_send_stream_init(str, sid, flowctrl, process_sid)
    quic_send_stream_t *const str;
    const uint64_t sid;
    quic_flowctrl_t *const flowctrl;
    liteco_channel_t *const process_sid; {

    str->sid = sid;
    
    pthread_mutex_init(&str->mtx, NULL);
    str->reader_buf = NULL;
    str->reader_len = 0;
    str->off = 0;

    liteco_channel_init(&str->writed_notifier);
    str->process_sid = process_sid;
    str->deadline = 0;

    str->closed = false;

    str->flowctrl = flowctrl;

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
    liteco_channel_send(str->process_sid, &str->sid);

    return quic_err_success;
}

typedef struct quic_recv_stream_s quic_recv_stream_t;
struct quic_recv_stream_s {
    uint64_t sid;

    pthread_mutex_t mtx;
    quic_sorter_t sorter;

    uint64_t read_off;
    uint64_t final_off;
    bool fin_flag;

    uint64_t deadline;

    bool closed;
};

static inline quic_err_t quic_recv_stream_init(quic_recv_stream_t *const str, const uint64_t sid) {
    str->sid = sid;
    pthread_mutex_init(&str->mtx, NULL);
    quic_sorter_init(&str->sorter);
    str->read_off = 0;
    str->final_off = 0;
    str->fin_flag = false;
    str->deadline = 0;
    str->closed = false;

    return quic_err_success;
}

#endif
