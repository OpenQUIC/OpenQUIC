/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "stream.h"
#include "utils/time.h"
#include <stdbool.h>

__thread static liteco_runtime_t __stream_runtime;
__thread static bool __stream_runtime_inited = false;

typedef struct quic_send_stream_write_args_s quic_send_stream_write_args_t;
struct quic_send_stream_write_args_s {
    quic_send_stream_t *str;

    uint64_t len;
    const void *data;

    uint64_t writed_len;
};
static int quic_send_stream_write_co(void *const args);

static inline void __stream_runtime_init();

quic_err_t quic_send_stream_init(quic_send_stream_t *const str, const uint64_t sid) {
    str->sid = sid;
    pthread_mutex_init(&str->reader_mtx, NULL);
    str->reader_buf = NULL;
    str->reader_len = 0;
    liteco_channel_init(&str->writed_notifier);

    return quic_err_success;
}

uint64_t quic_send_stream_write(quic_send_stream_t *const str, uint64_t len, const void *data) {
    uint8_t co_s[4096];
    liteco_coroutine_t co;
    quic_send_stream_write_args_t args = { .str = str, .len = len, .data = data, .writed_len = 0 };
    __stream_runtime_init();

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

    pthread_mutex_lock(&write_args->str->reader_mtx);

    str->reader_buf = data;
    str->reader_len = len;

    for ( ;; ) {
        if (str->deadline != 0 && str->deadline < quic_now()) {
            break;
        }
        if (str->reader_len == 0) {
            break;
        }

        if (!notified) {
            liteco_channel_send(str->process_notifier, &str->sid);
            notified = true;
        }

        // TODO
    }

    write_args->str->reader_buf = NULL;
    write_args->str->reader_len = 0;
    pthread_mutex_unlock(&write_args->str->reader_mtx);
    return 0;
}

static inline void __stream_runtime_init() {
    if (!__stream_runtime_inited) {
        liteco_runtime_init(&__stream_runtime);
        __stream_runtime_inited = true;
    }
}
