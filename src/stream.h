/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_STREAM_H__
#define __OPENQUIC_STREAM_H__

#include "utils/errno.h"
#include "utils/rbt.h"
#include "liteco.h"
#include <stdint.h>
#include <pthread.h>

typedef struct quic_send_stream_s quic_send_stream_t;
struct quic_send_stream_s {
    uint64_t sid;

    pthread_mutex_t mtx;
    const void *reader_buf;
    uint64_t reader_len;

    liteco_channel_t writed_notifier;
    liteco_channel_t *process_notifier;
    uint64_t deadline;

    bool closed;
};

quic_err_t quic_send_stream_init(quic_send_stream_t *const str, const uint64_t sid);
uint64_t quic_send_stream_write(quic_send_stream_t *const str, uint64_t len, const void *data);
static inline void quic_send_stream_close(quic_send_stream_t *const str) {
    if (str->closed) {
        return;
    }

    pthread_mutex_lock(&str->mtx);
    str->closed = true;
    pthread_mutex_unlock(&str->mtx);

    liteco_channel_notify(&str->writed_notifier);
}

#endif
