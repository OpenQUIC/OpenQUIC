/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "modules/stream.h"
#include "utils/time.h"
#include "utils/varint.h"
#include "module.h"
#include <stdbool.h>

static __thread liteco_runtime_t __stream_runtime;
static __thread bool __stream_runtime_inited = false;

typedef struct quic_send_stream_write_args_s quic_send_stream_write_args_t;
struct quic_send_stream_write_args_s {
    quic_send_stream_t *str;

    uint64_t len;
    const void *data;

    uint64_t writed_len;
};

typedef struct quic_recv_stream_read_args_s quic_recv_stream_read_args_t;
struct quic_recv_stream_read_args_s {
    quic_recv_stream_t *str;

    uint64_t len;
    void *data;

    uint64_t readed_len;
};

static int quic_send_stream_write_co(void *const args);
static int quic_recv_stream_read_co(void *const args);
static inline void __stream_runtime_init();

static inline uint64_t quic_stream_frame_capacity(const uint64_t max_bytes,
                                                  const uint64_t sid, const uint64_t off, const bool fill, const uint64_t payload_size);

uint64_t quic_send_stream_write(quic_send_stream_t *const str, uint64_t len, const void *data) {
    uint8_t co_s[4096];
    liteco_coroutine_t co;
    quic_send_stream_write_args_t args = { .str = str, .len = len, .data = data, .writed_len = 0 };
    __stream_runtime_init();

    if (str->closed) {
        return 0;
    }

    liteco_create(&co, co_s, sizeof(co_s), quic_send_stream_write_co, &args, NULL);
    liteco_runtime_join(&__stream_runtime, &co);

    while (co.status != LITECO_TERMINATE) {
        if (liteco_runtime_execute(&__stream_runtime, &co) != LITECO_SUCCESS) {
            break;
        }
    }

    return args.writed_len;
}

static int quic_send_stream_write_co(void *const args) {
    quic_send_stream_write_args_t *const write_args = args;

    quic_send_stream_t *const str = write_args->str;
    const void *const data = write_args->data;
    uint64_t len = write_args->len;
    bool notified = false;

    pthread_mutex_lock(&str->mtx);

    str->reader_buf = data;
    str->reader_len = len;

    for ( ;; ) {
        if (str->closed) {
            break;
        }
        if (str->deadline != 0 && str->deadline < quic_now()) {
            break;
        }
        if (str->reader_len == 0) {
            break;
        }

        pthread_mutex_unlock(&str->mtx);
        if (!notified) {
            liteco_channel_send(str->speaker, &str->sid);
            notified = true;
        }

        liteco_recv(NULL, NULL, &__stream_runtime, str->deadline, &str->writed_notifier);
        pthread_mutex_lock(&str->mtx);

        write_args->writed_len = len - str->reader_len;
    }

    write_args->str->reader_buf = NULL;
    write_args->str->reader_len = 0;
    pthread_mutex_unlock(&str->mtx);

    return 0;
}

quic_frame_stream_t *quic_send_stream_generate(quic_send_stream_t *const str, uint64_t bytes, const bool fill) {
    pthread_mutex_lock(&str->mtx);
    uint64_t payload_size = quic_send_stream_flowctrl_module(str)->get_swnd(quic_send_stream_flowctrl(str));
    if (str->reader_len < payload_size) {
        payload_size = str->reader_len;
    }
    uint64_t payload_capa = quic_stream_frame_capacity(bytes, str->sid, str->off, fill, payload_size);
    if (payload_capa < payload_size) {
        payload_size = payload_capa;
    }

    quic_frame_stream_t *frame = malloc(sizeof(quic_frame_stream_t) + payload_size);
    if (frame == NULL) {
        pthread_mutex_unlock(&str->mtx);
        return NULL;
    }
    frame->first_byte = quic_frame_stream_type;
    if (str->off != 0) {
        frame->first_byte |= quic_frame_stream_type_off;
    }
    if (!fill) {
        frame->first_byte |= quic_frame_stream_type_len;
    }
    frame->sid = str->sid;
    frame->off = str->off;
    frame->len = payload_size;

    memcpy(frame->data, str->reader_buf, payload_size);
    str->reader_buf += payload_size;
    str->reader_len -= payload_size;

    if (str->reader_len == 0) {
        frame->first_byte |= quic_frame_stream_type_fin;

        liteco_channel_notify(&str->writed_notifier);
    }

    pthread_mutex_unlock(&str->mtx);

    return frame;
}

static inline uint64_t quic_stream_frame_capacity(const uint64_t max_bytes,
                                                  const uint64_t sid, const uint64_t off, const bool fill, const uint64_t payload_size) {

    const uint64_t header_len = 1
        + quic_varint_format_len(sid)
        + (off != 0 ? quic_varint_format_len(off) : 0)
        + (!fill ? quic_varint_format_len(payload_size) : 0);
    if (header_len >= max_bytes) {
        return 0;
    }

    return max_bytes - header_len;
}

static inline void __stream_runtime_init() {
    if (!__stream_runtime_inited) {
        liteco_runtime_init(&__stream_runtime);
        __stream_runtime_inited = true;
    }
}

uint64_t quic_recv_stream_read(quic_recv_stream_t *const str, const uint64_t len, void *const data) {
    uint8_t co_s[4096];
    liteco_coroutine_t co;
    quic_recv_stream_read_args_t args = { .str = str, .len = len, .data = data, .readed_len = 0 };
    __stream_runtime_init();

    if (str->closed) {
        return 0;
    }

    liteco_create(&co, co_s, sizeof(co_s), quic_recv_stream_read_co, &args, NULL);
    liteco_runtime_join(&__stream_runtime, &co);

    while (co.status != LITECO_TERMINATE) {
        if (liteco_runtime_execute(&__stream_runtime, &co) != LITECO_SUCCESS) {
            break;
        }
    }

    return args.readed_len;
}

static int quic_recv_stream_read_co(void *const args) {
    quic_recv_stream_read_args_t *const read_args = args;

    quic_recv_stream_t *const str = read_args->str;
    void *data = read_args->data;
    uint64_t len = read_args->len;
    uint64_t readed_len = 0;

    pthread_mutex_lock(&str->mtx);
    for ( ;; ) {
        if (str->closed) {
            break;
        }
        if (len == 0) {
            break;
        }
        if (str->fin_flag && str->final_off <= readed_len) {
            liteco_channel_send(str->speaker, &str->sid);
            break;
        }
        if (str->deadline != 0 && str->deadline < quic_now()) {
            break;
        }

        pthread_mutex_unlock(&str->mtx);
        liteco_recv(NULL, NULL, &__stream_runtime, str->deadline, &str->handled_notifier);
        pthread_mutex_lock(&str->mtx);

        uint64_t once_readed_len = quic_sorter_read(&str->sorter, len, data);
        if (once_readed_len == 0) {
            break;
        }

        readed_len += once_readed_len;
        len -= once_readed_len;
        data += once_readed_len;
    }
    pthread_mutex_unlock(&str->mtx);
    read_args->readed_len = readed_len;

    return 0;
}

quic_module_t quic_stream_module = {

};
