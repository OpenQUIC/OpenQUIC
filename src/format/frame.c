/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "format/frame.h"
#include "utils/errno.h"
#include "utils/buf.h"
#include "utils/varint.h"

#define quic_frame_alloc(frame, _first_byte, size) \
    if ((*(frame) = malloc((size))) == NULL) {     \
        return quic_err_internal_error;            \
    }                                              \
    (**(frame)).first_byte = (_first_byte);        \
    (**(frame)).ref_count = 1;                     \
    (**(frame)).next = NULL

#define quic_first_byte(buf) \
    *((uint8_t *) ((buf)->pos++))

#define quic_varint(target, buf)                                  \
    if ((buf)->pos + quic_varint_len((buf)->pos) > (buf)->last) { \
        return quic_err_bad_format;                               \
    }                                                             \
    (target) = quic_varint_r((buf)->pos);                         \
    (buf)->pos += quic_varint_len((buf)->pos)
    
#define quic_extend_data(frame, len, buf)    \
    if ((buf)->pos + (len) > (buf)->last) {  \
        return quic_err_bad_format;          \
    }                                        \
    memcpy((frame).data, (buf)->pos, (len)); \
    (buf)->pos += (len)

#define quic_frame_init { \
    .ref_count = 1,       \
}


#define quic_put_byte(buf, byte)           \
    if ((buf)->pos + 1 > (buf)->last) {    \
        return quic_err_bad_format;        \
    }                                      \
    *((uint8_t *) ((buf)->pos++)) = (byte) \

#define quic_put_varint(buf, varint)                                 \
    if ((buf)->pos + quic_varint_format_len(varint) > (buf)->last) { \
        return quic_err_bad_format;                                  \
    }                                                                \
    quic_varint_format_r(buf, varint)

#define quic_put_data(buf, len, data)     \
    if ((buf)->pos + len > (buf)->last) { \
        return quic_err_bad_format;       \
    }                                     \
    memcpy((buf)->pos, (data), (len));    \
    (buf)->pos += (len)

quic_err_t quic_ping_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    uint8_t first;

    first = quic_first_byte(buf);

    quic_frame_alloc(frame, first, sizeof(quic_frame_ping_t));

    return quic_err_success;
}

quic_err_t quic_ack_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_ack_t ref = quic_frame_init;

    ref.first_byte = quic_first_byte(buf);

    quic_varint(ref.largest_ack, buf);
    quic_varint(ref.delay, buf);
    quic_varint(ref.ranges.count, buf);
    quic_varint(ref.first_range, buf);

    quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_ack_t) + ref.ranges.count * sizeof(quic_ack_range_t));
    *(quic_frame_ack_t *) *frame = ref;
    (*(quic_frame_ack_t *) *frame).ranges.size = sizeof(quic_ack_range_t);

    uint64_t i;
    quic_arr_t *ranges = &(*(quic_frame_ack_t *) *frame).ranges;
    for (i = 0; i < ref.ranges.count; i++) {
        quic_varint(quic_arr(ranges, i, quic_ack_range_t)->gap, buf);
        quic_varint(quic_arr(ranges, i, quic_ack_range_t)->len, buf);
    }

    if (ref.first_byte == quic_frame_ack_ecn_type) {
        quic_varint((*(quic_frame_ack_t *) *frame).ect0, buf);
        quic_varint((*(quic_frame_ack_t *) *frame).ect1, buf);
        quic_varint((*(quic_frame_ack_t *) *frame).ect_ce, buf);
    }

    return quic_err_success;
}

quic_err_t quic_reset_stream_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_reset_stream_t ref = quic_frame_init;

    ref.first_byte = quic_first_byte(buf);
    quic_varint(ref.sid, buf);
    quic_varint(ref.app_err, buf);
    quic_varint(ref.final_size, buf);

    quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_reset_stream_t));
    *(quic_frame_reset_stream_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_stop_sending_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_stop_sending_t ref = quic_frame_init;

    ref.first_byte = quic_first_byte(buf);
    quic_varint(ref.sid, buf);
    quic_varint(ref.app_err, buf);

    quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_stop_sending_t));
    *(quic_frame_stop_sending_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_crypto_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_crypto_t ref = quic_frame_init;

    ref.first_byte = quic_first_byte(buf);
    quic_varint(ref.off, buf);
    quic_varint(ref.len, buf);

    quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_crypto_t) + ref.len);
    *(quic_frame_crypto_t *) *frame = ref;

    quic_extend_data(*(quic_frame_crypto_t *) *frame, ref.len, buf);

    return quic_err_success;
}

quic_err_t quic_new_token_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_new_token_t ref = quic_frame_init;

    ref.first_byte = quic_first_byte(buf);
    quic_varint(ref.len, buf);

    quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_new_token_t) + ref.len);
    *(quic_frame_new_token_t *) *frame = ref;

    quic_extend_data(*(quic_frame_new_token_t *) *frame, ref.len, buf);

    return quic_err_success;
}

quic_err_t quic_stream_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_stream_t ref = quic_frame_init;

    ref.first_byte = quic_first_byte(buf);
    quic_varint(ref.sid, buf);

    if ((ref.first_byte & quic_frame_stream_type_off) == quic_frame_stream_type_off) {
        quic_varint(ref.off, buf);
    }
    else {
        ref.off = 0;
    }

    if ((ref.first_byte & quic_frame_stream_type_len) == quic_frame_stream_type_len) {
        quic_varint(ref.len, buf);
    }
    else {
        ref.len = buf->last - buf->pos;
    }

    quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_stream_t) + ref.len);
    *(quic_frame_stream_t *) *frame = ref;

    quic_extend_data(*(quic_frame_stream_t *) *frame, ref.len, buf);

    return quic_err_success;
}

quic_err_t quic_max_data_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_max_data_t ref = quic_frame_init;

    ref.first_byte = quic_first_byte(buf);
    quic_varint(ref.max_data, buf);

    quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_max_data_t));
    *(quic_frame_max_data_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_max_stream_data_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_max_stream_data_t ref = quic_frame_init;

    ref.first_byte = quic_first_byte(buf);
    quic_varint(ref.sid, buf);
    quic_varint(ref.max_data, buf);

    quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_max_stream_data_t));
    *(quic_frame_max_stream_data_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_max_streams_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_max_streams_t ref = quic_frame_init;

    ref.first_byte = quic_first_byte(buf);
    quic_varint(ref.max_streams, buf);

    quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_max_streams_t));
    *(quic_frame_max_streams_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_data_blocked_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_data_blocked_t ref = quic_frame_init;

    ref.first_byte = quic_first_byte(buf);
    quic_varint(ref.max_data, buf);

    quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_data_blocked_t));
    *(quic_frame_data_blocked_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_stream_data_blocked_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_stream_data_blocked_t ref = quic_frame_init;

    ref.first_byte = quic_first_byte(buf);
    quic_varint(ref.sid, buf);
    quic_varint(ref.max_data, buf);

    quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_data_blocked_t));
    *(quic_frame_stream_data_blocked_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_streams_blocked_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_streams_blocked_t ref = quic_frame_init;

    ref.first_byte = quic_first_byte(buf);
    quic_varint(ref.max_streams, buf);

    quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_streams_blocked_t));
    *(quic_frame_streams_blocked_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_new_connection_id_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_new_connection_id_t ref = quic_frame_init;

    ref.first_byte = quic_first_byte(buf);
    quic_varint(ref.seq, buf);
    quic_varint(ref.retire, buf);
    ref.len = quic_first_byte(buf);
    if (ref.len < 1 || ref.len > 20) {
        return quic_err_bad_format;
    }
    if (buf->pos + ref.len + 16> buf->last) {
        return quic_err_bad_format;
    }
    memcpy(ref.conn, buf->pos, ref.len);
    buf->pos += ref.len;
    memcpy(ref.token, buf->pos, 16);
    buf->pos += 16;

    quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_new_connection_id_t));
    *(quic_frame_new_connection_id_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_retire_connection_id_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_retire_connection_id_t ref = quic_frame_init;

    ref.first_byte = quic_first_byte(buf);
    quic_varint(ref.seq, buf);

    quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_retire_connection_id_t));
    *(quic_frame_retire_connection_id_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_path_challenge_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_path_challenge_t ref = quic_frame_init;

    ref.first_byte = quic_first_byte(buf);
    if (buf->pos + 8 > buf->last) {
        return quic_err_bad_format;
    }
    memcpy(ref.data, buf->pos, 8);
    buf->pos += 8;

    quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_path_challenge_t));
    *(quic_frame_path_challenge_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_path_response_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_path_response_t ref = quic_frame_init;

    ref.first_byte = quic_first_byte(buf);
    if (buf->pos + 8 > buf->last) {
        return quic_err_bad_format;
    }
    memcpy(ref.data, buf->pos, 8);
    buf->pos += 8;

    quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_path_response_t));
    *(quic_frame_path_response_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_connection_close_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_connection_close_t ref = quic_frame_init;

    ref.first_byte = quic_first_byte(buf);
    quic_varint(ref.err, buf);
    if (ref.first_byte == 0x1c) {
        quic_varint(ref.type, buf);
    }
    quic_varint(ref.len, buf);

    quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_connection_close_t));
    *(quic_frame_connection_close_t *) *frame = ref;

    quic_extend_data(*(quic_frame_connection_close_t *) *frame, ref.len, buf);

    return quic_err_success;
}

quic_err_t quic_handshake_done_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    uint8_t first;
    
    first = quic_first_byte(buf);

    quic_frame_alloc(frame, first, sizeof(quic_frame_handshake_done_t));

    return quic_err_success;
}

quic_err_t quic_ping_format(quic_buf_t *const buf, const quic_frame_t *const frame) {
    quic_put_byte(buf, frame->first_byte);

    return quic_err_success;
}

quic_err_t quic_ack_format(quic_buf_t *const buf, const quic_frame_t *const frame) {
    const quic_frame_ack_t *const ref = (quic_frame_ack_t *) frame;
    quic_put_byte(buf, frame->first_byte);

    quic_put_varint(buf, ref->largest_ack);
    quic_put_varint(buf, ref->delay);
    quic_put_varint(buf, (uint64_t) ref->ranges.count);
    quic_put_varint(buf, ref->first_range);

    uint64_t i;
    const quic_arr_t *ranges = &ref->ranges;
    for (i = 0; i < ranges->count; i++) {
        quic_put_varint(buf, quic_arr(ranges, i, quic_ack_range_t)->gap);
        quic_put_varint(buf, quic_arr(ranges, i, quic_ack_range_t)->len);
    }

    if (ref->first_byte == quic_frame_ack_ecn_type) {
        quic_put_varint(buf, ref->ect0);
        quic_put_varint(buf, ref->ect1);
        quic_put_varint(buf, ref->ect_ce);
    }

    return quic_err_success;
}

quic_err_t quic_reset_stream_format(quic_buf_t *const buf, const quic_frame_t *const frame) {
    const quic_frame_reset_stream_t *const ref = (quic_frame_reset_stream_t *) frame;
    quic_put_byte(buf, ref->first_byte);

    quic_put_varint(buf, ref->sid);
    quic_put_varint(buf, ref->app_err);
    quic_put_varint(buf, ref->final_size);

    return quic_err_success;
}

quic_err_t quic_stop_sending_format(quic_buf_t *const buf, const quic_frame_t *const frame) {
    const quic_frame_stop_sending_t *const ref = (quic_frame_stop_sending_t *) frame;
    quic_put_byte(buf, ref->first_byte);

    quic_put_varint(buf, ref->sid);
    quic_put_varint(buf, ref->app_err);

    return quic_err_success;
}

quic_err_t quic_crypto_format(quic_buf_t *const buf, const quic_frame_t *const frame) {
    const quic_frame_crypto_t *const ref = (quic_frame_crypto_t *) frame;
    quic_put_byte(buf, ref->first_byte);

    quic_put_varint(buf, ref->off);
    quic_put_varint(buf, ref->len);
    quic_put_data(buf, ref->len, ref->data);


    return quic_err_success;
}

quic_err_t quic_new_token_format(quic_buf_t *const buf, const quic_frame_t *const frame) {
    const quic_frame_new_token_t *const ref = (quic_frame_new_token_t *) frame;
    quic_put_byte(buf, ref->first_byte);

    quic_put_varint(buf, ref->len);
    quic_put_data(buf, ref->len, ref->data);

    return quic_err_success;
}

quic_err_t quic_stream_format(quic_buf_t *const buf, const quic_frame_t *const frame) {
    const quic_frame_stream_t *const ref = (quic_frame_stream_t *) frame;
    quic_put_byte(buf, ref->first_byte);

    quic_put_varint(buf, ref->sid);
    if ((ref->first_byte & quic_frame_stream_type_off) == quic_frame_stream_type_off) {
        quic_put_varint(buf, ref->off);
    }
    if ((ref->first_byte & quic_frame_stream_type_len) == quic_frame_stream_type_len) {
        quic_put_varint(buf, ref->len);
    }
    quic_put_data(buf, ref->len, ref->data);

    return quic_err_success;
}

quic_err_t quic_max_data_format(quic_buf_t *const buf, const quic_frame_t *const frame) {
    const quic_frame_max_data_t *const ref = (quic_frame_max_data_t *) frame;
    quic_put_byte(buf, ref->first_byte);

    quic_put_varint(buf, ref->max_data);

    return quic_err_success;
}

quic_err_t quic_max_stream_data_format(quic_buf_t *const buf, const quic_frame_t *const frame) {
    const quic_frame_max_stream_data_t *const ref = (quic_frame_max_stream_data_t *) frame;
    quic_put_byte(buf, ref->first_byte);

    quic_put_varint(buf, ref->sid);
    quic_put_varint(buf, ref->max_data);

    return quic_err_success;
}

quic_err_t quic_max_streams_format(quic_buf_t *const buf, const quic_frame_t *const frame) {
    const quic_frame_max_streams_t *const ref = (quic_frame_max_streams_t *) frame;
    quic_put_byte(buf, ref->first_byte);

    quic_put_varint(buf, ref->max_streams);

    return quic_err_success;
}

quic_err_t quic_data_blocked_format(quic_buf_t *const buf, const quic_frame_t *const frame) {
    const quic_frame_data_blocked_t *const ref = (quic_frame_data_blocked_t *) frame;
    quic_put_byte(buf, ref->first_byte);

    quic_put_varint(buf, ref->max_data);

    return quic_err_success;
}

quic_err_t quic_stream_data_blocked_format(quic_buf_t *const buf, const quic_frame_t *const frame) {
    const quic_frame_stream_data_blocked_t *const ref = (quic_frame_stream_data_blocked_t *) frame;
    quic_put_byte(buf, ref->first_byte);

    quic_put_varint(buf, ref->sid);
    quic_put_varint(buf, ref->max_data);

    return quic_err_success;
}

quic_err_t quic_streams_blocked_format(quic_buf_t *const buf, const quic_frame_t *const frame) {
    const quic_frame_streams_blocked_t *const ref = (quic_frame_streams_blocked_t *) frame;
    quic_put_byte(buf, ref->first_byte);

    quic_put_varint(buf, ref->max_streams);

    return quic_err_success;
}

quic_err_t quic_new_connection_id_format(quic_buf_t *const buf, const quic_frame_t *const frame) {
    const quic_frame_new_connection_id_t *const ref = (quic_frame_new_connection_id_t *) frame;
    quic_put_byte(buf, ref->first_byte);

    quic_put_varint(buf, ref->seq);
    quic_put_varint(buf, ref->retire);
    quic_put_byte(buf, ref->len);
    quic_put_data(buf, ref->len, ref->conn);
    quic_put_data(buf, 16, ref->token);

    return quic_err_success;
}

quic_err_t quic_retire_connection_id_format(quic_buf_t *const buf, const quic_frame_t *const frame) {
    const quic_frame_retire_connection_id_t *const ref = (quic_frame_retire_connection_id_t *) frame;
    quic_put_byte(buf, ref->first_byte);

    quic_put_varint(buf, ref->seq);

    return quic_err_success;
}

quic_err_t quic_path_challenge_format(quic_buf_t *const buf, const quic_frame_t *const frame) {
    const quic_frame_path_challenge_t *const ref = (quic_frame_path_challenge_t *) frame;
    quic_put_byte(buf, ref->first_byte);

    quic_put_data(buf, 8, ref->data);

    return quic_err_success;
}

quic_err_t quic_path_response_format(quic_buf_t *const buf, const quic_frame_t *const frame) {
    const quic_frame_path_response_t *const ref = (quic_frame_path_response_t *) frame;
    quic_put_byte(buf, ref->first_byte);

    quic_put_data(buf, 8, ref->data);

    return quic_err_success;
}

quic_err_t quic_connection_close_format(quic_buf_t *const buf, const quic_frame_t *const frame) {
    const quic_frame_connection_close_t *const ref = (quic_frame_connection_close_t *) frame;
    quic_put_byte(buf, ref->first_byte);

    quic_put_varint(buf, ref->err);
    if (ref->first_byte == 0x1c) {
        quic_put_varint(buf, ref->type);
    }
    quic_put_varint(buf, ref->len);
    quic_put_data(buf, ref->len, ref->data);

    return quic_err_success;
}

quic_err_t quic_handshake_done_format(quic_buf_t *const buf, const quic_frame_t *const frame) {
    const quic_frame_handshake_done_t *const ref = (quic_frame_handshake_done_t *) frame;
    quic_put_byte(buf, ref->first_byte);

    return quic_err_success;
}

uint64_t quic_ping_size(const quic_frame_t *const frame) {
    (void) frame;
    return 1;
}

uint64_t quic_ack_size(const quic_frame_t *const frame) {
    const quic_frame_ack_t *const ref = (quic_frame_ack_t *) frame;

    uint64_t len = 1
        + quic_varint_format_len(ref->largest_ack)
        + quic_varint_format_len(ref->delay)
        + quic_varint_format_len((uint64_t) ref->ranges.count)
        + quic_varint_format_len(ref->first_range);

    uint64_t i;
    const quic_arr_t *ranges = &ref->ranges;
    for (i = 0; i < ranges->count; i++) {
        len += quic_varint_format_len(quic_arr(ranges, i, quic_ack_range_t)->gap)
            + quic_varint_format_len(quic_arr(ranges, i, quic_ack_range_t)->len);
    }

    if (ref->first_byte == quic_frame_ack_ecn_type) {
        len += quic_varint_format_len(ref->ect0)
            + quic_varint_format_len(ref->ect1)
            + quic_varint_format_len(ref->ect_ce);
    }

    return len;
}

uint64_t quic_reset_stream_size(const quic_frame_t *const frame) {
    const quic_frame_reset_stream_t *const ref = (quic_frame_reset_stream_t *) frame;

    return 1
        + quic_varint_format_len(ref->sid)
        + quic_varint_format_len(ref->app_err)
        + quic_varint_format_len(ref->final_size);
}

uint64_t quic_stop_sending_size(const quic_frame_t *const frame) {
    const quic_frame_stop_sending_t *const ref = (quic_frame_stop_sending_t *) frame;

    return 1
        + quic_varint_format_len(ref->sid)
        + quic_varint_format_len(ref->app_err);
}

uint64_t quic_crypto_size(const quic_frame_t *const frame) {
    const quic_frame_crypto_t *const ref = (quic_frame_crypto_t *) frame;

    return 1
        + quic_varint_format_len(ref->off)
        + quic_varint_format_len(ref->len)
        + ref->len;
}

uint64_t quic_new_token_size(const quic_frame_t *const frame) {
    const quic_frame_new_token_t *const ref = (quic_frame_new_token_t *) frame;

    return 1
        + quic_varint_format_len(ref->len)
        + ref->len;
}

uint64_t quic_stream_size(const quic_frame_t *const frame) {
    const quic_frame_stream_t *const ref = (quic_frame_stream_t *) frame;
    return 1
        + quic_varint_format_len(ref->sid)
        + ((ref->first_byte & quic_frame_stream_type_off) == quic_frame_stream_type_off ? quic_varint_format_len(ref->off) : 0)
        + ((ref->first_byte & quic_frame_stream_type_len) == quic_frame_stream_type_len ? quic_varint_format_len(ref->len) : 0)
        + ref->len;
}

uint64_t quic_max_data_size(const quic_frame_t *const frame) {
    const quic_frame_max_data_t *const ref = (quic_frame_max_data_t *) frame;

    return 1 + quic_varint_format_len(ref->max_data);
}

uint64_t quic_max_stream_data_size(const quic_frame_t *const frame) {
    const quic_frame_max_stream_data_t *const ref = (quic_frame_max_stream_data_t *) frame;

    return 1
        + quic_varint_format_len(ref->sid)
        + quic_varint_format_len(ref->max_data);
}

uint64_t quic_max_streams_size(const quic_frame_t *const frame) {
    const quic_frame_max_streams_t *const ref = (quic_frame_max_streams_t *) frame;

    return 1 + quic_varint_format_len(ref->max_streams);
}

uint64_t quic_data_blocked_size(const quic_frame_t *const frame) {
    const quic_frame_data_blocked_t *const ref = (quic_frame_data_blocked_t *) frame;

    return 1 + quic_varint_format_len(ref->max_data);
}

uint64_t quic_stream_data_blocked_size(const quic_frame_t *const frame) {
    const quic_frame_stream_data_blocked_t *const ref = (quic_frame_stream_data_blocked_t *) frame;

    return 1 + quic_varint_format_len(ref->sid) + quic_varint_format_len(ref->max_data);
}

uint64_t quic_streams_blocked_size(const quic_frame_t *const frame) {
    const quic_frame_streams_blocked_t *const ref = (quic_frame_streams_blocked_t *) frame;

    return 1 + quic_varint_format_len(ref->max_streams);
}

uint64_t quic_new_connection_id_size(const quic_frame_t *const frame) {
    const quic_frame_new_connection_id_t *const ref = (quic_frame_new_connection_id_t *) frame;

    return 1
        + quic_varint_format_len(ref->seq)
        + quic_varint_format_len(ref->retire)
        + 1
        + ref->len
        + 16;
}

uint64_t quic_retire_connection_id_size(const quic_frame_t *const frame) {
    const quic_frame_retire_connection_id_t *const ref = (quic_frame_retire_connection_id_t *) frame;

    return 1 + quic_varint_format_len(ref->seq);
}

uint64_t quic_path_challenge_size(const quic_frame_t *const frame) {
    (void) frame;

    return 1 + 8;
}

uint64_t quic_path_response_size(const quic_frame_t *const frame) {
    (void) frame;

    return 1 + 8;
}

uint64_t quic_connection_close_size(const quic_frame_t *const frame) {
    const quic_frame_connection_close_t *const ref = (quic_frame_connection_close_t *) frame;

    return 1
        + quic_varint_format_len(ref->err)
        + (ref->first_byte == 0x1c ? quic_varint_format_len(ref->type) : 0)
        + quic_varint_format_len(ref->len)
        + ref->len;
}

uint64_t quic_handshake_done_size(const quic_frame_t *const frame) {
    (void) frame;
    return 1;
}
