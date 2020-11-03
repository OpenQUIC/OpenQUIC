/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "format/frame.h"
#include "modules/stream.h"
#include "modules/framer.h"
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

uint64_t quic_send_stream_write(quic_send_stream_t *const str, const void *data, const uint64_t len) {
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
    quic_stream_t *const p_str = quic_container_of_send_stream(str);
    quic_framer_module_t *framer_module = quic_session_module(quic_framer_module_t, p_str->session, quic_framer_module);

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
            quic_framer_add_active(framer_module, p_str->key);
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

quic_frame_stream_t *quic_send_stream_generate(quic_send_stream_t *const str, bool *const empty, uint64_t bytes, const bool fill) {
    quic_stream_t *const p_str = quic_container_of_send_stream(str);
    quic_stream_flowctrl_module_t *const flowctrl_module = p_str->flowctrl_module;
    *empty = false;

    pthread_mutex_lock(&str->mtx);
    uint64_t payload_size = flowctrl_module->get_swnd(quic_stream_extend_flowctrl(p_str));
    if (str->reader_len < payload_size) {
        payload_size = str->reader_len;
    }
    uint64_t payload_capa = quic_stream_frame_capacity(bytes, p_str->key, str->off, fill, payload_size);
    if (payload_capa < payload_size) {
        payload_size = payload_capa;
    }

    quic_frame_stream_t *frame = malloc(sizeof(quic_frame_stream_t) + payload_size);
    if (frame == NULL) {
        pthread_mutex_unlock(&str->mtx);
        return NULL;
    }
    quic_frame_init(frame, quic_frame_stream_type);

    if (str->off != 0) {
        frame->first_byte |= quic_frame_stream_type_off;
    }
    if (!fill) {
        frame->first_byte |= quic_frame_stream_type_len;
    }
    frame->sid = p_str->key;
    frame->off = str->off;
    frame->len = payload_size;

    if (str->reader_len == 0) {
        *empty = true;
        if (str->closed && !str->sent_fin) {
            frame->first_byte |= quic_frame_stream_type_fin;
            str->sent_fin = true;
        }
    }
    else {
        memcpy(frame->data, str->reader_buf, payload_size);
        str->reader_buf += payload_size;
        str->reader_len -= payload_size;

        flowctrl_module->sent(quic_stream_extend_flowctrl(p_str), payload_size);

        if (str->reader_len == 0) {
            *empty = true;
            pthread_mutex_unlock(&str->mtx);
            liteco_channel_notify(&str->writed_notifier);
            pthread_mutex_lock(&str->mtx);
        }
        if (str->closed && str->reader_len != 0 && !str->sent_fin) {
            *empty = true;
            frame->first_byte |= quic_frame_stream_type_fin;
            str->sent_fin = true;
        }
    }

    str->unacked_frames_count++;
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

uint64_t quic_recv_stream_read(quic_recv_stream_t *const str, void *const data, const uint64_t len) {
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
    quic_stream_t *const p_str = quic_container_of_recv_stream(str);
    quic_stream_module_t *module = quic_session_module(quic_stream_module_t, p_str->session, quic_stream_module);
    void *data = read_args->data;
    uint64_t len = read_args->len;
    uint64_t readed_len = 0;

    uint64_t timeout = str->deadline == 0 ? 0 : str->deadline + quic_now();

    pthread_mutex_lock(&str->mtx);
    for ( ;; ) {
        if (str->closed) {
            break;
        }
        if (len == 0) {
            break;
        }
        if (str->fin_flag && str->final_off <= str->sorter.readed_size) {
            liteco_channel_send(&module->completed_speaker, &p_str->key);

            quic_module_activate(p_str->session, quic_stream_module);
            break;
        }
        if (timeout != 0 && timeout < quic_now()) {
            break;
        }

        pthread_mutex_unlock(&str->mtx);
        liteco_recv(NULL, NULL, &__stream_runtime, timeout, &str->handled_notifier);
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

static __thread liteco_runtime_t __accept_runtime;
static __thread bool __streams_runtime_inited = false;
static inline void __streams_runtime_init();

static int quic_stream_inuni_streams_accept_co(void *const args);
static int quic_stream_inbidi_streams_accept_co(void *const args);

static inline void __streams_runtime_init() {
    if (!__streams_runtime_inited) {
        liteco_runtime_init(&__accept_runtime);
        __streams_runtime_inited = true;
    }
}

typedef struct quic_inuni_streams_accept_s quic_inuni_streams_accept_t;
struct quic_inuni_streams_accept_s {
    quic_inuni_streams_t *strs;
    quic_stream_t *str;
};

typedef struct quic_inbidi_streams_accept_s quic_inbidi_streams_accept_t;
struct quic_inbidi_streams_accept_s {
    quic_inbidi_streams_t *strs;
    quic_stream_t *str;
};

quic_stream_t *quic_stream_inuni_accept(quic_inuni_streams_t *const strs) {
    uint8_t co_s[4096];
    liteco_coroutine_t co;
    quic_inuni_streams_accept_t args = { .strs = strs, .str = NULL };
    __streams_runtime_init();

    liteco_create(&co, co_s, sizeof(co_s), quic_stream_inuni_streams_accept_co, &args, NULL);
    liteco_runtime_join(&__accept_runtime, &co);

    while (co.status != LITECO_TERMINATE) {
        if (liteco_runtime_execute(&__accept_runtime, &co) != LITECO_SUCCESS) {
            break;
        }
    }

    return args.str;
}

static int quic_stream_inuni_streams_accept_co(void *const args) {
    quic_inuni_streams_accept_t *const accept_args = args;
    quic_inuni_streams_t *const strs = accept_args->strs;
    const uint64_t *key = NULL;

    liteco_recv((const void **) &key, NULL, &__accept_runtime, 0, &strs->accept_speaker);
    accept_args->str = quic_streams_find(strs->streams, key);

    return 0;
}

quic_stream_t *quic_stream_inbidi_accept(quic_inbidi_streams_t *const strs) {
    uint8_t co_s[4096];
    liteco_coroutine_t co;
    quic_inbidi_streams_accept_t args = { .strs = strs, .str = NULL };
    __streams_runtime_init();

    liteco_create(&co, co_s, sizeof(co_s), quic_stream_inbidi_streams_accept_co, &args, NULL);
    liteco_runtime_join(&__accept_runtime, &co);

    while (co.status != LITECO_TERMINATE) {
        if (liteco_runtime_execute(&__accept_runtime, &co) != LITECO_SUCCESS) {
            break;
        }
    }

    return args.str;
}

static int quic_stream_inbidi_streams_accept_co(void *const args) {
    quic_inuni_streams_accept_t *const accept_args = args;
    quic_inuni_streams_t *const strs = accept_args->strs;
    const uint64_t *key = NULL;

    liteco_recv((const void **) &key, NULL, &__accept_runtime, 0, &strs->accept_speaker);
    accept_args->str = quic_streams_find(strs->streams, key);

    return 0;
}

static quic_err_t quic_stream_module_init(void *const module) {
    quic_stream_module_t *const stream_module = module;

    quic_inuni_streams_init(&stream_module->inuni);
    quic_inbidi_streams_init(&stream_module->inbidi);
    quic_outuni_streams_init(&stream_module->outuni);
    quic_outbidi_streams_init(&stream_module->outbidi);

    liteco_channel_init(&stream_module->completed_speaker);

    stream_module->extends_size = 0;

    stream_module->init = NULL;
    stream_module->destory = NULL;

    return quic_err_success;
}

uint64_t quic_stream_write(quic_stream_t *const str, const void *const data, const uint64_t len) {
    return quic_send_stream_write(&str->send, data, len);
}

uint64_t quic_stream_read(quic_stream_t *const str, void *const data, const uint64_t len) {
    return quic_recv_stream_read(&str->recv, data, len);
}

quic_stream_t *quic_session_open_stream(quic_session_t *const session, const bool bidi) {
    quic_stream_module_t *module = quic_session_module(quic_stream_module_t, session, quic_stream_module);

    return bidi ? quic_stream_outbidi_open(&module->outbidi) : quic_stream_outuni_open(&module->outuni);
}

quic_stream_t *quic_session_accept_stream(quic_session_t *const session, const bool bidi) {
    quic_stream_module_t *module = quic_session_module(quic_stream_module_t, session, quic_stream_module);

    return bidi ? quic_stream_inbidi_accept(&module->inbidi) : quic_stream_inuni_accept(&module->inuni);
}

static inline quic_err_t quic_streams_release_spec(quic_stream_module_t *const module, const uint64_t sid) {
    quic_session_t *const session = quic_module_of_session(module, quic_stream_module);

    if (quic_stream_id_is_bidi(sid)) {
        if (quic_stream_id_same_principal(sid, session)) {
            quic_stream_outbidi_delete(&module->outbidi, &sid);
        }
        else {
            quic_stream_inbidi_delete(&module->inbidi, &sid);
        }
    }
    else {
        if (quic_stream_id_same_principal(sid, session)) {
            quic_stream_outuni_delete(&module->outuni, &sid);
        }
        else {
            quic_stream_inuni_delete(&module->inuni, &sid);
        }
    }

    return quic_err_success;
}

static quic_err_t quic_session_stream_module_process(void *const module) {
    quic_stream_module_t *const stream_module = module;
    const uint64_t *sid = NULL;
    const liteco_channel_t *recv_channel = NULL;

    liteco_recv((const void **) &sid, &recv_channel, __CURR_CO__->runtime, 0,
                &stream_module->completed_speaker, &__CLOSED_CHAN__);

    if (recv_channel == &__CLOSED_CHAN__) {
        return quic_err_success;
    }
    else if (recv_channel == &stream_module->completed_speaker) {
        quic_streams_release_spec(stream_module, *sid);
    }

    return quic_err_success;
}

quic_module_t quic_stream_module = {
    .module_size = sizeof(quic_stream_module_t),
    .init = quic_stream_module_init,
    .process = quic_session_stream_module_process,
    .destory = NULL,
};

quic_err_t quic_session_handle_stream_frame(quic_session_t *const session, const quic_frame_t *const frame) {
    quic_stream_module_t *module = quic_session_module(quic_stream_module_t, session, quic_stream_module);
    const quic_frame_stream_t *const stream_frame = (const quic_frame_stream_t *) frame;

    quic_stream_t *stream = quic_stream_module_recv_relation_stream(module, stream_frame->sid);
    if (stream == NULL || quic_rbt_is_nil(stream)) {
        return quic_err_success;
    }

    quic_recv_stream_handle_frame(&stream->recv, stream_frame);

    return quic_err_success;
}
