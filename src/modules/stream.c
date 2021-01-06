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
#include "modules/stream_flowctrl.h"
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

typedef struct quic_stream_destoryed_s quic_stream_destoryed_t;
struct quic_stream_destoryed_s {
    QUIC_LINK_FIELDS

    uint64_t sid;
};

static int quic_send_stream_write_co(void *const args);
static int quic_recv_stream_read_co(void *const args);
static int quic_stream_close_sync_co(void *const args);
static inline void __stream_runtime_init();

static quic_err_t quic_send_stream_on_acked(void *const str_, const quic_frame_t *const frame_);

static inline uint64_t quic_stream_frame_capacity(const uint64_t max_bytes,
                                                  const uint64_t sid, const uint64_t off, const bool fill, const uint64_t payload_size);

uint64_t quic_send_stream_write(quic_send_stream_t *const str, const void *data, const uint64_t len) {
    uint8_t co_s[LITECO_DEFAULT_STACK_SIZE] = { 0 };
    liteco_coroutine_t co;
    quic_send_stream_write_args_t args = { .str = str, .len = len, .data = data, .writed_len = 0 };
    __stream_runtime_init();

    if (str->closed) {
        return 0;
    }

    liteco_create(&co, co_s, sizeof(co_s), quic_send_stream_write_co, &args, NULL);
    liteco_runtime_join(&__stream_runtime, &co);

    while (co.status != LITECO_TERMINATE) {
        if (liteco_runtime_execute(NULL, &__stream_runtime, &co) != LITECO_SUCCESS) {
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

        liteco_recv(NULL, NULL, &__stream_runtime, str->deadline, &str->sent_segment_notifier);

        pthread_mutex_lock(&str->mtx);

        write_args->writed_len = len - str->reader_len;
    }

    write_args->str->reader_buf = NULL;
    write_args->str->reader_len = 0;
    pthread_mutex_unlock(&str->mtx);

    return 0;
}

quic_frame_stream_t *quic_send_stream_generate(quic_send_stream_t *const str, bool *const empty, uint64_t bytes, const bool fill) {
#define this_functor_check_should_send_fin (str->closed && !str->sent_fin)

    quic_stream_t *const p_str = quic_container_of_send_stream(str);
    quic_stream_flowctrl_module_t *const flowctrl_module = p_str->flowctrl_module;
    quic_framer_module_t *const framer = quic_session_module(quic_framer_module_t, p_str->session, quic_framer_module);
    *empty = false;

    pthread_mutex_lock(&str->mtx);

    uint64_t payload_size = quic_stream_flowctrl_get_swnd(flowctrl_module, quic_stream_extend_flowctrl(p_str));
    if (str->reader_len < payload_size) {
        payload_size = str->reader_len;
    }
    if (payload_size > str->reader_len) {
        payload_size = str->reader_len;
    }

    uint64_t payload_capa = quic_stream_frame_capacity(bytes, p_str->key, str->off, fill, payload_size);
    if (payload_capa < payload_size) {
        payload_size = payload_capa;
    }

    if (payload_size == 0 && !str->closed) {
        uint64_t max_data = 0;
        if (quic_stream_flowctrl_newly_blocked(flowctrl_module, &max_data, quic_stream_extend_flowctrl(p_str))) {
            quic_frame_stream_data_blocked_t *blocked_frame = malloc(sizeof(quic_frame_stream_data_blocked_t));
            if (blocked_frame) {
                quic_frame_init(blocked_frame, quic_frame_stream_data_blocked_type);
                blocked_frame->sid = p_str->key;
                blocked_frame->max_data = max_data;

                quic_framer_ctrl(framer, (quic_frame_t *) blocked_frame);
            }
        }

        pthread_mutex_unlock(&str->mtx);
        return NULL;
    }

    quic_frame_stream_t *frame = malloc(sizeof(quic_frame_stream_t) + payload_size);
    if (frame == NULL) {
        pthread_mutex_unlock(&str->mtx);
        return NULL;
    }
    quic_frame_init(frame, quic_frame_stream_type);
    frame->on_acked = quic_send_stream_on_acked;
    frame->acked_obj = str;

    if (str->off != 0) {
        frame->first_byte |= quic_frame_stream_type_off;
    }
    if (!fill) {
        frame->first_byte |= quic_frame_stream_type_len;
    }
    frame->sid = p_str->key;
    frame->off = str->off;
    frame->len = payload_size;
    str->off += payload_size;

    if (str->reader_len == 0) {
        *empty = true;
        if (this_functor_check_should_send_fin) {
            frame->first_byte |= quic_frame_stream_type_fin;
            str->sent_fin = true;
        }
    }
    else {
        memcpy(frame->data, str->reader_buf, payload_size);
        str->reader_buf += payload_size;
        str->reader_len -= payload_size;

        quic_stream_flowctrl_sent(flowctrl_module, quic_stream_extend_flowctrl(p_str), payload_size);

        if (str->reader_len == 0) {
            *empty = true;
            pthread_mutex_unlock(&str->mtx);
            liteco_channel_notify(&str->sent_segment_notifier);
            pthread_mutex_lock(&str->mtx);
        }
        if (str->reader_len != 0 && this_functor_check_should_send_fin) {
            *empty = true;
            frame->first_byte |= quic_frame_stream_type_fin;
            str->sent_fin = true;
        }
    }

    str->unacked_frames_count++;
    pthread_mutex_unlock(&str->mtx);

    return frame;

#undef this_functor_check_should_send_fin
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
    uint8_t co_s[LITECO_DEFAULT_STACK_SIZE] = { 0 };
    liteco_coroutine_t co;
    quic_recv_stream_read_args_t args = { .str = str, .len = len, .data = data, .readed_len = 0 };
    __stream_runtime_init();

    if (str->closed) {
        return 0;
    }

    liteco_create(&co, co_s, sizeof(co_s), quic_recv_stream_read_co, &args, NULL);
    liteco_runtime_join(&__stream_runtime, &co);

    while (co.status != LITECO_TERMINATE) {
        if (liteco_runtime_execute(NULL, &__stream_runtime, &co) != LITECO_SUCCESS) {
            break;
        }
    }

    return args.readed_len;
}


static int quic_recv_stream_read_co(void *const args) {
    quic_recv_stream_read_args_t *const read_args = args;

    quic_recv_stream_t *const str = read_args->str;
    quic_stream_t *const p_str = quic_container_of_recv_stream(str);
    quic_stream_flowctrl_module_t *sf_module = quic_session_module(quic_stream_flowctrl_module_t, p_str->session, quic_stream_flowctrl_module);
    void *data = read_args->data;
    uint64_t len = read_args->len;
    uint64_t readed_len = 0;
    bool readed = false;

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
            break;
        }
        if (timeout != 0 && timeout < quic_now()) {
            break;
        }

        if (quic_sorter_readable(&str->sorter) == 0) {
            if (readed) {
                break;
            }
            pthread_mutex_unlock(&str->mtx);
            liteco_recv(NULL, NULL, &__stream_runtime, timeout, &str->handled_notifier);
            pthread_mutex_lock(&str->mtx);
        }
        uint64_t once_readed_len = quic_sorter_read(&str->sorter, len, data);
        if (once_readed_len == 0) {
            break;
        }

        readed_len += once_readed_len;
        len -= once_readed_len;
        data += once_readed_len;

        quic_stream_flowctrl_read(sf_module, quic_stream_extend_flowctrl(p_str), p_str->key, once_readed_len);
        readed = true;
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
    uint8_t co_s[LITECO_DEFAULT_STACK_SIZE] = { 0 };
    liteco_coroutine_t co;
    quic_inuni_streams_accept_t args = { .strs = strs, .str = NULL };
    __streams_runtime_init();

    liteco_create(&co, co_s, sizeof(co_s), quic_stream_inuni_streams_accept_co, &args, NULL);
    liteco_runtime_join(&__accept_runtime, &co);

    while (co.status != LITECO_TERMINATE) {
        if (liteco_runtime_execute(NULL, &__accept_runtime, &co) != LITECO_SUCCESS) {
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
    uint8_t co_s[LITECO_DEFAULT_STACK_SIZE] = { 0 };
    liteco_coroutine_t co;
    quic_inbidi_streams_accept_t args = { .strs = strs, .str = NULL };
    __streams_runtime_init();

    liteco_create(&co, co_s, sizeof(co_s), quic_stream_inbidi_streams_accept_co, &args, NULL);
    liteco_runtime_join(&__accept_runtime, &co);

    while (co.status != LITECO_TERMINATE) {
        if (liteco_runtime_execute(NULL, &__accept_runtime, &co) != LITECO_SUCCESS) {
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

    stream_module->extends_size = 0;

    pthread_mutex_init(&stream_module->rwnd_updated_mtx, NULL);
    quic_rbt_tree_init(stream_module->rwnd_updated);

    pthread_mutex_init(&stream_module->destory_mtx, NULL);
    quic_rbt_tree_init(stream_module->destory_set);

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

static int quic_stream_close_sync_co(void *const args) {
    liteco_channel_t *const channel = args;

    liteco_recv(NULL, NULL, &__stream_runtime, 0, channel);

    return 0;
}

quic_err_t quic_stream_close(quic_stream_t *const str) {
    quic_stream_module_t *const s_module = quic_session_module(quic_stream_module_t, str->session, quic_stream_module);
    uint8_t co_s[1024] = { 0 };
    liteco_coroutine_t co;
    liteco_channel_t destoryed_notifier;
    
    __stream_runtime_init();
    liteco_channel_init(&destoryed_notifier);

    quic_send_stream_close(&str->send);
    quic_recv_stream_close(&str->recv);

    quic_stream_destory_push(s_module, &destoryed_notifier, str->key);

    if (str->session->cfg.stream_sync_close) {
        liteco_create(&co, co_s, sizeof(co_s), quic_stream_close_sync_co, &destoryed_notifier, NULL);
        liteco_runtime_join(&__stream_runtime, &co);
        while (co.status != LITECO_TERMINATE) {
            if (liteco_runtime_execute(NULL, &__stream_runtime, &co) != LITECO_SUCCESS) {
                break;
            }
        }
    }

    return quic_err_success;
}

bool quic_stream_remote_closed(quic_stream_t *const str) {
    return str->recv.fin_flag;
}

static inline quic_err_t quic_streams_destory(quic_stream_module_t *const module, quic_session_t *const session, const uint64_t sid) {
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

static quic_err_t quic_send_stream_on_acked(void *const str_, const quic_frame_t *const frame_) {
    free((void *) frame_);

    quic_send_stream_t *const str = (quic_send_stream_t *) str_;

    pthread_mutex_lock(&str->mtx);
    str->unacked_frames_count--;
    pthread_mutex_unlock(&str->mtx);

    return quic_err_success;
}

static quic_err_t quic_session_stream_module_loop(void *const module, const uint64_t now) {
    quic_stream_module_t *const stream_module = module;
    quic_session_t *const session = quic_module_of_session(module);
    quic_stream_destory_sid_t *d_sid = NULL;
    quic_link_t destoryed_list;

    quic_link_init(&destoryed_list);

    pthread_mutex_lock(&stream_module->destory_mtx);
    {
        quic_rbt_foreach(d_sid, stream_module->destory_set) {
            quic_stream_t *str = (quic_stream_t *) quic_rbt_nil;
            if (quic_stream_id_is_bidi(d_sid->key)) {
                if (quic_stream_id_same_principal(d_sid->key, session)) {
                    str = quic_streams_find(stream_module->outbidi.streams, &d_sid->key);
                }
                else {
                    str = quic_streams_find(stream_module->inbidi.streams, &d_sid->key);
                }
            }
            else {
                if (quic_stream_id_same_principal(d_sid->key, session)) {
                    str = quic_streams_find(stream_module->outuni.streams, &d_sid->key);
                }
                else {
                    str = quic_streams_find(stream_module->inuni.streams, &d_sid->key);
                }
            }
            if (quic_rbt_is_nil(str) || !(quic_stream_destroable(str)
                                          || (session->cfg.stream_destory_timeout != 0
                                              && session->cfg.stream_destory_timeout + d_sid->destory_time >= now))) {
                continue;
            }

            quic_streams_destory(stream_module, session, d_sid->key);

            quic_stream_destoryed_t *destoryed = malloc(sizeof(quic_stream_destoryed_t));
            if (destoryed) {
                quic_link_init(destoryed);
                destoryed->sid = d_sid->key;

                quic_link_insert_after(&destoryed_list, destoryed);
            }
        }
    }

    while (!quic_link_empty(&destoryed_list)) {
        quic_stream_destoryed_t *destoryed = (quic_stream_destoryed_t *) quic_link_next(&destoryed_list);
        quic_link_remove(destoryed);

        d_sid = quic_stream_destory_sid_find(stream_module->destory_set, &destoryed->sid);
        if (!quic_rbt_is_nil(d_sid)) {
            quic_rbt_remove(&stream_module->destory_set, &d_sid);
            liteco_channel_close(d_sid->destoryed_notifier);

            free(d_sid);
        }

        free(destoryed);
    }
    pthread_mutex_unlock(&stream_module->destory_mtx);

    return quic_err_success;
}

quic_err_t quic_stream_module_process_rwnd(quic_stream_module_t *const module) {
    quic_session_t *const session = quic_module_of_session(module);
    quic_framer_module_t *const framer = quic_session_module(quic_framer_module_t, session, quic_framer_module);

    quic_stream_rwnd_updated_sid_t *sid = NULL;

    pthread_mutex_lock(&module->rwnd_updated_mtx);
    while (!quic_rbt_is_nil(module->rwnd_updated)) {
        sid = module->rwnd_updated;
        quic_stream_t *const str = quic_stream_module_recv_relation_stream(module, sid->key);
        quic_rbt_remove(&module->rwnd_updated, &sid);
        free(sid);

        if (str && !quic_rbt_is_nil(str)) {
            quic_stream_flowctrl_t *const flowctrl = quic_stream_extend_flowctrl(str);

            quic_frame_max_stream_data_t *frame = malloc(sizeof(quic_frame_max_stream_data_t));
            if (frame) {
                quic_frame_init(frame, quic_frame_max_stream_data_type);
                frame->sid = str->key;
                frame->max_data = flowctrl->rwnd;

                quic_framer_ctrl(framer, (quic_frame_t *) frame);
            }
        }
    }
    pthread_mutex_unlock(&module->rwnd_updated_mtx);

    return quic_err_success;
}

quic_module_t quic_stream_module = {
    .name        = "stream",
    .module_size = sizeof(quic_stream_module_t),
    .init        = quic_stream_module_init,
    .process     = NULL,
    .loop        = quic_session_stream_module_loop,
    .destory     = NULL,
};

quic_err_t quic_session_handle_stream_frame(quic_session_t *const session, const quic_frame_t *const frame) {
    quic_stream_module_t *module = quic_session_module(quic_stream_module_t, session, quic_stream_module);
    const quic_frame_stream_t *const s_frame = (const quic_frame_stream_t *) frame;

    quic_stream_t *const stream = quic_stream_module_recv_relation_stream(module, s_frame->sid);
    if (stream == NULL || quic_rbt_is_nil(stream)) {
        return quic_err_success;
    }

    quic_recv_stream_handle_frame(&stream->recv, s_frame);

    return quic_err_success;
}

quic_err_t quic_session_handle_max_stream_data_frame(quic_session_t *const session, const quic_frame_t *const frame) {
    quic_stream_module_t *module = quic_session_module(quic_stream_module_t, session, quic_stream_module);
    const quic_frame_max_stream_data_t *const md_frame = (const quic_frame_max_stream_data_t *) frame;

    quic_stream_t *const stream = quic_stream_module_send_relation_stream(module, md_frame->sid);
    if (stream == NULL || quic_rbt_is_nil(stream)) {
        return quic_err_success;
    }

    quic_send_stream_handle_max_stream_data_frame(&stream->send, md_frame);

    return quic_err_success;
}
