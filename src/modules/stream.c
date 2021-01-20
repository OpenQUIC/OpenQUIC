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

static inline quic_stream_t *quic_session_open_recv_stream(quic_stream_module_t *const module, const uint64_t sid);
static inline quic_stream_t *quic_stream_module_recv_relation_stream(quic_stream_module_t *const module, const uint64_t sid);

static inline quic_err_t quic_send_stream_close(quic_send_stream_t *const str);
static inline quic_err_t quic_recv_stream_close(quic_recv_stream_t *const str);
static inline quic_err_t quic_stream_destory_push(quic_stream_module_t *const module, const uint64_t sid);
static inline quic_err_t quic_recv_stream_handle_frame(quic_recv_stream_t *const str, const quic_frame_stream_t *const frame);
static inline quic_err_t quic_send_stream_handle_max_stream_data_frame(quic_send_stream_t *const str, const quic_frame_max_stream_data_t *const frame);
static inline bool quic_stream_destroable(quic_stream_t *const str);

static inline quic_stream_t *quic_stream_create(quic_session_t *const session, const uint64_t sid, const uint32_t extends_size);
static inline quic_err_t quic_stream_destory(quic_stream_t *const str);

typedef struct quic_stream_io_s quic_stream_io_t;
struct quic_stream_io_s {
    quic_stream_t *str;

    liteco_co_t co;
    liteco_chan_t timer_chan;
    liteco_timer_t timer;

    uint64_t len;
    void *data;

    uint64_t pos;

    quic_err_t (*done_cb) (quic_stream_t *const, void *const, const size_t, const size_t);

    uint8_t st[0];
};

typedef struct quic_stream_destoryed_s quic_stream_destoryed_t;
struct quic_stream_destoryed_s {
    QUIC_LINK_FIELDS

    uint64_t sid;
};

static int quic_stream_write_co(void *const args);
static int quic_stream_write_done(liteco_co_t *const co);
static int quic_stream_read_co(void *const args);
static int quic_stream_read_done(liteco_co_t *const co);

static inline quic_err_t quic_stream_set_delete(quic_stream_module_t *const, quic_stream_set_t *const , const uint64_t);

static quic_err_t quic_send_stream_on_acked(void *const str_, const quic_frame_t *const frame_);

static inline uint64_t quic_stream_frame_capacity(const uint64_t max_bytes,
                                                  const uint64_t sid, const uint64_t off, const bool fill, const uint64_t payload_size);

static int quic_stream_write_co(void *const args) {
    quic_stream_io_t *const io = args;

    quic_send_stream_t *const str = &io->str->send;
    const void *const data = io->data;
    uint64_t len = io->len;
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

        if (str->deadline) {
            liteco_timer_expire(&io->timer, str->deadline, 0);
            liteco_case_t cases[] = {
                { .chan = &io->timer_chan, .type = liteco_casetype_pop, .ele = NULL },
                { .chan = &str->sent_segment_chan, .type = liteco_casetype_pop, .ele = NULL }
            };
            liteco_select(cases, 2, true);
        }
        else {
            liteco_chan_pop(&str->sent_segment_chan, true);
        }

        pthread_mutex_lock(&str->mtx);

        io->pos = len - str->reader_len;
    }

    str->reader_buf = NULL;
    str->reader_len = 0;
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
            liteco_chan_unenforceable_push(&str->sent_segment_chan, NULL);
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

static int quic_stream_read_co(void *const args) {
    quic_stream_io_t *const io = args;

    quic_recv_stream_t *const str = &io->str->recv;
    quic_stream_t *const p_str = quic_container_of_recv_stream(str);
    quic_stream_flowctrl_module_t *sf_module = quic_session_module(quic_stream_flowctrl_module_t, p_str->session, quic_stream_flowctrl_module);
    void *data = io->data;
    uint64_t len = io->len;
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
            if (str->deadline) {
                liteco_timer_expire(&io->timer, str->deadline, 0);
                liteco_case_t cases[] = {
                    { .chan = &io->timer_chan, .type = liteco_casetype_pop, .ele = NULL },
                    { .chan = &str->handled_chan, .type = liteco_casetype_pop, .ele = NULL }
                };
                liteco_select(cases, 2, true);
            }
            else {
                liteco_chan_pop(&str->handled_chan, true);
            }
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
    io->pos = readed_len;

    return 0;
}

static quic_err_t quic_stream_module_init(void *const module) {
    quic_stream_module_t *const stream_module = module;

    quic_stream_set_init(&stream_module->inuni);
    quic_stream_set_init(&stream_module->inbidi);
    quic_stream_set_init(&stream_module->outuni);
    quic_stream_set_init(&stream_module->outbidi);

    stream_module->extends_size = 0;

    pthread_mutex_init(&stream_module->rwnd_updated_mtx, NULL);
    quic_rbt_tree_init(stream_module->rwnd_updated);

    pthread_mutex_init(&stream_module->destory_mtx, NULL);
    quic_rbt_tree_init(stream_module->destory_set);

    stream_module->init = NULL;
    stream_module->destory = NULL;
    stream_module->accept_cb = NULL;

    return quic_err_success;
}

quic_err_t quic_stream_write(liteco_eloop_t *const eloop,
                             quic_stream_t *const str,
                             void *const data, const uint64_t len,
                             quic_err_t (*write_done_cb) (quic_stream_t *const, void *const, const size_t, const size_t)) {
    if (str->send.closed) {
        return quic_err_closed;
    }

    quic_stream_io_t *const io = malloc(sizeof(quic_stream_io_t) + QUIC_STREAM_CO_STACK);
    if (!io) {
        return quic_err_internal_error;
    }

    io->done_cb = write_done_cb;
    io->pos = 0;
    io->str = str;
    io->data = data;
    io->len = len;
    liteco_chan_create(&io->timer_chan, 0, liteco_runtime_readycb, str->session->rt);
    liteco_timer_init(eloop, &io->timer, &io->timer_chan);

    liteco_create(&io->co, quic_stream_write_co, io, quic_stream_write_done, io->st, QUIC_STREAM_CO_STACK);
    liteco_runtime_join(str->session->rt, &io->co, true);

    return quic_err_success;
}

static int quic_stream_write_done(liteco_co_t *const co) {
    quic_stream_io_t *const io = ((void *) co) - offsetof(quic_stream_io_t, co);

    liteco_timer_close(&io->timer);
    liteco_chan_close(&io->timer_chan);
    liteco_chan_destory(&io->timer_chan);

    if (io->done_cb) {
        io->done_cb(io->str, io->data, io->len, io->pos);
    }

    free(io);
    return 0;
}

quic_err_t quic_stream_read(liteco_eloop_t *const eloop,
                            quic_stream_t *const str,
                            void *const data, const uint64_t len,
                            quic_err_t (*read_done_cb) (quic_stream_t *const, void *const, const size_t, const size_t)) {
    if (str->recv.closed) {
        return quic_err_closed;
    }

    quic_stream_io_t *const io = malloc(sizeof(quic_stream_io_t) + QUIC_STREAM_CO_STACK);
    if (!io) {
        return quic_err_internal_error;
    }

    io->done_cb = read_done_cb;
    io->pos = 0;
    io->str = str;
    io->data = data;
    io->len = len;
    liteco_chan_create(&io->timer_chan, 0, liteco_runtime_readycb, str->session->rt);
    liteco_timer_init(eloop, &io->timer, &io->timer_chan);

    liteco_create(&io->co, quic_stream_read_co, io, quic_stream_read_done, io->st, QUIC_STREAM_CO_STACK);
    liteco_runtime_join(str->session->rt, &io->co, true);

    return quic_err_success;
}

static int quic_stream_read_done(liteco_co_t *const co) {
    quic_stream_io_t *const io = ((void *) co) - offsetof(quic_stream_io_t, co);

    liteco_timer_close(&io->timer);
    liteco_chan_close(&io->timer_chan);
    liteco_chan_destory(&io->timer_chan);

    if (io->done_cb) {
        io->done_cb(io->str, io->data, io->len, io->pos);
    }

    free(io);
    return 0;
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

static inline quic_err_t quic_stream_destory(quic_stream_t *const str) {
    quic_stream_flowctrl_module_t *const flowctrl_module = quic_session_module(quic_stream_flowctrl_module_t, str->session, quic_stream_flowctrl_module);

    quic_send_stream_destory(&str->send);
    quic_recv_stream_destory(&str->recv);

    quic_stream_flowctrl_destory(flowctrl_module, quic_stream_extend_flowctrl(str));

    free(str);

    return quic_err_success;
}

quic_stream_t *quic_stream_open(quic_stream_module_t *const module, const bool bidi) {
    quic_session_t *const session = quic_module_of_session(module);
    
    pthread_mutex_t *const mtx = bidi ? &module->outbidi.mtx : &module->outuni.mtx;
    uint64_t *const next_sid = bidi ? &module->outbidi.next_sid : &module->outuni.next_sid;
    quic_stream_t **const streams = bidi ? &module->outbidi.streams : &module->outuni.streams;

    pthread_mutex_lock(mtx);
    const uint64_t sid = quic_stream_id_transfer(true, session->cfg.is_cli, *next_sid);
    (*next_sid)++;
    quic_stream_t *stream = quic_streams_find(*streams, &sid);
    if (!quic_rbt_is_nil(stream)) {
        quic_rbt_remove(streams, &stream);
        if (module->destory) {
            module->destory(stream);
        }
        quic_stream_destory(stream);
    }
    stream = quic_stream_create(session, sid, module->extends_size);
    if (module->init) {
        module->init(stream);
    }
    quic_streams_insert(streams, stream);
    pthread_mutex_unlock(mtx);

    return stream;
}

static inline quic_stream_t *quic_session_open_recv_stream(quic_stream_module_t *const module, const uint64_t sid) {
    quic_session_t *const session = quic_module_of_session(module);
    const bool bidi = quic_stream_id_is_bidi(sid);

    quic_stream_t **const strs = bidi ? &module->inbidi.streams : &module->inuni.streams;
    pthread_mutex_t *const mtx = bidi ? &module->inbidi.mtx : &module->inuni.mtx;

    quic_stream_t *stream = quic_streams_find(*strs, &sid);
    if (!quic_rbt_is_nil(stream)) {
        return stream;
    }

    pthread_mutex_lock(mtx);
    stream = quic_stream_create(session, sid, module->extends_size);
    if (module->init) {
        module->init(stream);
    }
    quic_streams_insert(strs, stream);
    pthread_mutex_unlock(mtx);

    if (module->accept_cb) {
        module->accept_cb(session, stream);
    }

    return stream;
}

static inline quic_stream_t *quic_stream_module_recv_relation_stream(quic_stream_module_t *const module, const uint64_t sid) {
    quic_session_t *const session = quic_module_of_session(module);
    quic_stream_t *const strs = quic_stream_id_is_bidi(sid) ? module->outbidi.streams : (quic_stream_t *) quic_rbt_nil;

    return quic_stream_id_same_principal(sid, session)
        ? quic_streams_find(strs, &sid) : quic_session_open_recv_stream(module, sid);
}

quic_stream_t *quic_stream_module_send_relation_stream(quic_stream_module_t *const module, const uint64_t sid) {
    quic_session_t *const session = quic_module_of_session(module);

    if (quic_stream_id_same_principal(sid, session)) {
        quic_stream_t *const strs = quic_stream_id_is_bidi(sid) ? module->outbidi.streams : module->outuni.streams;
        return quic_streams_find(strs, &sid);
    }

    if (quic_stream_id_is_bidi(sid)) {
        return quic_session_open_recv_stream(module, sid);
    }

    return (quic_stream_t *) quic_rbt_nil;
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

quic_err_t quic_stream_close(quic_stream_t *const str) {
    quic_stream_module_t *const s_module = quic_session_module(quic_stream_module_t, str->session, quic_stream_module);

    quic_send_stream_close(&str->send);
    quic_recv_stream_close(&str->recv);

    quic_stream_destory_push(s_module, str->key);

    return quic_err_success;
}

bool quic_stream_remote_closed(quic_stream_t *const str) {
    return str->recv.fin_flag;
}

static inline quic_err_t quic_streams_destory(quic_stream_module_t *const module, quic_session_t *const session, const uint64_t sid) {
    if (quic_stream_id_is_bidi(sid)) {
        if (quic_stream_id_same_principal(sid, session)) {
            quic_stream_set_delete(module, &module->outbidi, sid);
        }
        else {
            quic_stream_set_delete(module, &module->inbidi, sid);
        }
    }
    else {
        if (quic_stream_id_same_principal(sid, session)) {
            quic_stream_set_delete(module, &module->outuni, sid);
        }
        else {
            quic_stream_set_delete(module, &module->inuni, sid);
        }
    }

    return quic_err_success;
}

static inline quic_err_t quic_stream_set_delete(quic_stream_module_t *const module, quic_stream_set_t *const strset, const uint64_t sid) {
    pthread_mutex_lock(&strset->mtx);
    quic_stream_t *const str = quic_streams_find(strset->streams, &sid);
    if (!quic_rbt_is_nil(str)) {
        quic_rbt_remove(&strset->streams, &str);
        if (module->destory) {
            module->destory(str);
        }
        quic_stream_destory(str);
    }
    pthread_mutex_unlock(&strset->mtx);
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

static inline bool quic_stream_destroable(quic_stream_t *const str) {
    return str->recv.closed && str->recv.fin_flag && str->send.closed && str->send.sent_fin;
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
            /*liteco_channel_close(d_sid->destoryed_notifier);*/

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

quic_err_t quic_session_handle_stream_frame(quic_session_t *const session, const quic_frame_t *const frame) {
    quic_stream_module_t *module = quic_session_module(quic_stream_module_t, session, quic_stream_module);
    const quic_frame_stream_t *const s_frame = (const quic_frame_stream_t *) frame;

    quic_stream_t *const stream = quic_stream_module_recv_relation_stream(module, s_frame->sid);
    if (quic_rbt_is_nil(stream)) {
        return quic_err_success;
    }

    quic_recv_stream_handle_frame(&stream->recv, s_frame);

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

quic_err_t quic_session_handle_max_stream_data_frame(quic_session_t *const session, const quic_frame_t *const frame) {
    quic_stream_module_t *module = quic_session_module(quic_stream_module_t, session, quic_stream_module);
    const quic_frame_max_stream_data_t *const md_frame = (const quic_frame_max_stream_data_t *) frame;

    quic_stream_t *const stream = quic_stream_module_send_relation_stream(module, md_frame->sid);
    if (quic_rbt_is_nil(stream)) {
        return quic_err_success;
    }

    quic_send_stream_handle_max_stream_data_frame(&stream->send, md_frame);

    return quic_err_success;
}

