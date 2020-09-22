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

#define quic_quic_frame_alloc(frame, _first_byte, size)     \
    if ((*(frame) = malloc((size))) == NULL) {              \
        return quic_err_internal_error;                     \
    }                                                       \
    (**(frame)).first_byte = (_first_byte);                 \
    (**(frame)).ref_count = 1;                              \
    (**(frame)).next = NULL

#define quic_quic_first_byte(buf)                                   \
    *((uint8_t *) ((buf)->pos++))

#define quic_quic_varint(target, buf)                               \
    if ((buf)->pos + quic_varint_len((buf)->pos) > (buf)->last) {   \
        return quic_err_bad_format;                                 \
    }                                                               \
    (target) = quic_varint_r((buf)->pos);                           \
    (buf)->pos += quic_varint_len((buf)->pos)
    
#define quic_quic_extend_data(frame, len, buf)                      \
    if ((buf)->pos + (len) > (buf)->last) {                         \
        return quic_err_bad_format;                                 \
    }                                                               \
    memcpy((frame).data, (buf)->pos, (len));                        \
    (buf)->pos += (len)

#define quic_quic_frame_init { \
    .ref_count = 1,         \
}


#define quic_quic_put_byte(buf, byte)       \
    if ((buf)->pos + 1 > (buf)->last) {     \
        return quic_err_bad_format;         \
    }                                       \
    *((uint8_t *) ((buf)->pos++)) = (byte)  \

#define quic_quic_put_varint(buf, varint)                               \
    if ((buf)->pos + quic_varint_format_len(varint) > (buf)->last) {    \
        return quic_err_bad_format;                                     \
    }                                                                   \
    quic_varint_format_r(buf, varint)

#define quic_quic_put_data(buf, len, data)                              \
    if ((buf)->pos + len > (buf)->last) {                               \
        return quic_err_bad_format;                                     \
    }                                                                   \
    memcpy((buf)->pos, (data), (len));                                  \
    (buf)->pos += (len)

quic_err_t quic_ping_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    uint8_t first;

    first = quic_quic_first_byte(buf);

    quic_quic_frame_alloc(frame, first, sizeof(quic_frame_ping_t));

    return quic_err_success;
}

quic_err_t quic_ack_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_ack_t ref = quic_quic_frame_init;

    ref.first_byte = quic_quic_first_byte(buf);

    quic_quic_varint(ref.largest_ack, buf);
    quic_quic_varint(ref.delay, buf);
    quic_quic_varint(ref.ranges.count, buf);
    quic_quic_varint(ref.first_range, buf);

    quic_quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_ack_t) + ref.ranges.count * sizeof(quic_ack_range_t));
    *(quic_frame_ack_t *) *frame = ref;
    (*(quic_frame_ack_t *) *frame).ranges.size = sizeof(quic_ack_range_t);

    uint64_t i;
    quic_arr_t *ranges = &(*(quic_frame_ack_t *) *frame).ranges;
    for (i = 0; i < ref.ranges.count; i++) {
        quic_quic_varint(quic_arr(ranges, i, quic_ack_range_t)->gap, buf);
        quic_quic_varint(quic_arr(ranges, i, quic_ack_range_t)->len, buf);
    }

    if (ref.first_byte == quic_frame_ack_ecn_type) {
        quic_quic_varint((*(quic_frame_ack_t *) *frame).ect0, buf);
        quic_quic_varint((*(quic_frame_ack_t *) *frame).ect1, buf);
        quic_quic_varint((*(quic_frame_ack_t *) *frame).ect_ce, buf);
    }

    return quic_err_success;
}

quic_err_t quic_reset_stream_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_reset_stream_t ref = quic_quic_frame_init;

    ref.first_byte = quic_quic_first_byte(buf);
    quic_quic_varint(ref.sid, buf);
    quic_quic_varint(ref.app_err, buf);
    quic_quic_varint(ref.final_size, buf);

    quic_quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_reset_stream_t));
    *(quic_frame_reset_stream_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_stop_sending_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_stop_sending_t ref = quic_quic_frame_init;

    ref.first_byte = quic_quic_first_byte(buf);
    quic_quic_varint(ref.sid, buf);
    quic_quic_varint(ref.app_err, buf);

    quic_quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_stop_sending_t));
    *(quic_frame_stop_sending_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_crypto_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_crypto_t ref = quic_quic_frame_init;

    ref.first_byte = quic_quic_first_byte(buf);
    quic_quic_varint(ref.off, buf);
    quic_quic_varint(ref.len, buf);

    quic_quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_crypto_t) + ref.len);
    *(quic_frame_crypto_t *) *frame = ref;

    quic_quic_extend_data(*(quic_frame_crypto_t *) *frame, ref.len, buf);

    return quic_err_success;
}

quic_err_t quic_new_token_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_new_token_t ref = quic_quic_frame_init;

    ref.first_byte = quic_quic_first_byte(buf);
    quic_quic_varint(ref.len, buf);

    quic_quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_new_token_t) + ref.len);
    *(quic_frame_new_token_t *) *frame = ref;

    quic_quic_extend_data(*(quic_frame_new_token_t *) *frame, ref.len, buf);

    return quic_err_success;
}

quic_err_t quic_stream_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_stream_t ref = quic_quic_frame_init;

    ref.first_byte = quic_quic_first_byte(buf);
    quic_quic_varint(ref.sid, buf);

    if (ref.first_byte & 0x04) {
        quic_quic_varint(ref.off, buf);
    }
    if (ref.first_byte & 0x02) {
        quic_quic_varint(ref.len, buf);
    }
    else {
        ref.len = buf->last - buf->pos;
    }

    quic_quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_stream_t) + ref.len);
    *(quic_frame_stream_t *) *frame = ref;

    quic_quic_extend_data(*(quic_frame_stream_t *) *frame, ref.len, buf);

    return quic_err_success;
}

quic_err_t quic_max_data_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_max_data_t ref = quic_quic_frame_init;

    ref.first_byte = quic_quic_first_byte(buf);
    quic_quic_varint(ref.max_data, buf);

    quic_quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_max_data_t));
    *(quic_frame_max_data_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_max_stream_data_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_max_stream_data_t ref = quic_quic_frame_init;

    ref.first_byte = quic_quic_first_byte(buf);
    quic_quic_varint(ref.sid, buf);
    quic_quic_varint(ref.max_data, buf);

    quic_quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_max_stream_data_t));
    *(quic_frame_max_stream_data_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_max_streams_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_max_streams_t ref = quic_quic_frame_init;

    ref.first_byte = quic_quic_first_byte(buf);
    quic_quic_varint(ref.max_streams, buf);

    quic_quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_max_streams_t));
    *(quic_frame_max_streams_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_data_blocked_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_data_blocked_t ref = quic_quic_frame_init;

    ref.first_byte = quic_quic_first_byte(buf);
    quic_quic_varint(ref.max_data, buf);

    quic_quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_data_blocked_t));
    *(quic_frame_data_blocked_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_stream_data_blocked_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_stream_data_blocked_t ref = quic_quic_frame_init;

    ref.first_byte = quic_quic_first_byte(buf);
    quic_quic_varint(ref.sid, buf);
    quic_quic_varint(ref.max_data, buf);

    quic_quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_data_blocked_t));
    *(quic_frame_stream_data_blocked_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_streams_blocked_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_streams_blocked_t ref = quic_quic_frame_init;

    ref.first_byte = quic_quic_first_byte(buf);
    quic_quic_varint(ref.max_streams, buf);

    quic_quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_streams_blocked_t));
    *(quic_frame_streams_blocked_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_new_connection_id_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_new_connection_id_t ref = quic_quic_frame_init;

    ref.first_byte = quic_quic_first_byte(buf);
    quic_quic_varint(ref.seq, buf);
    quic_quic_varint(ref.retire, buf);
    ref.len = quic_quic_first_byte(buf);
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

    quic_quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_new_connection_id_t));
    *(quic_frame_new_connection_id_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_retire_connection_id_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_retire_connection_id_t ref = quic_quic_frame_init;

    ref.first_byte = quic_quic_first_byte(buf);
    quic_quic_varint(ref.seq, buf);

    quic_quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_retire_connection_id_t));
    *(quic_frame_retire_connection_id_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_path_challenge_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_path_challenge_t ref = quic_quic_frame_init;

    ref.first_byte = quic_quic_first_byte(buf);
    if (buf->pos + 8 > buf->last) {
        return quic_err_bad_format;
    }
    memcpy(ref.data, buf->pos, 8);
    buf->pos += 8;

    quic_quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_path_challenge_t));
    *(quic_frame_path_challenge_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_path_response_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_path_response_t ref = quic_quic_frame_init;

    ref.first_byte = quic_quic_first_byte(buf);
    if (buf->pos + 8 > buf->last) {
        return quic_err_bad_format;
    }
    memcpy(ref.data, buf->pos, 8);
    buf->pos += 8;

    quic_quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_path_response_t));
    *(quic_frame_path_response_t *) *frame = ref;

    return quic_err_success;
}

quic_err_t quic_connection_close_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_connection_close_t ref = quic_quic_frame_init;

    ref.first_byte = quic_quic_first_byte(buf);
    quic_quic_varint(ref.err, buf);
    if (ref.first_byte == 0x1c) {
        quic_quic_varint(ref.type, buf);
    }
    quic_quic_varint(ref.len, buf);

    quic_quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_connection_close_t));
    *(quic_frame_connection_close_t *) *frame = ref;

    quic_quic_extend_data(*(quic_frame_connection_close_t *) *frame, ref.len, buf);

    return quic_err_success;
}

quic_err_t quic_handshake_done_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    uint8_t first;
    
    first = quic_quic_first_byte(buf);

    quic_quic_frame_alloc(frame, first, sizeof(quic_frame_handshake_done_t));

    return quic_err_success;
}

quic_err_t quic_ping_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_quic_put_byte(buf, frame->first_byte);

    return quic_err_success;
}

quic_err_t quic_ack_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_ack_t *const ref = (quic_frame_ack_t *) frame;
    quic_quic_put_byte(buf, frame->first_byte);

    quic_quic_put_varint(buf, ref->largest_ack);
    quic_quic_put_varint(buf, ref->delay);
    quic_quic_put_varint(buf, (uint64_t) ref->ranges.count);
    quic_quic_put_varint(buf, ref->first_range);

    uint64_t i;
    quic_arr_t *ranges = &ref->ranges;
    for (i = 0; i < ranges->count; i++) {
        quic_quic_put_varint(buf, quic_arr(ranges, i, quic_ack_range_t)->gap);
        quic_quic_put_varint(buf, quic_arr(ranges, i, quic_ack_range_t)->len);
    }

    if (ref->first_byte == quic_frame_ack_ecn_type) {
        quic_quic_put_varint(buf, ref->ect0);
        quic_quic_put_varint(buf, ref->ect1);
        quic_quic_put_varint(buf, ref->ect_ce);
    }

    return quic_err_success;
}

quic_err_t quic_reset_stream_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_reset_stream_t *const ref = (quic_frame_reset_stream_t *) frame;
    quic_quic_put_byte(buf, ref->first_byte);

    quic_quic_put_varint(buf, ref->sid);
    quic_quic_put_varint(buf, ref->app_err);
    quic_quic_put_varint(buf, ref->final_size);

    return quic_err_success;
}

quic_err_t quic_stop_sending_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_stop_sending_t *const ref = (quic_frame_stop_sending_t *) frame;
    quic_quic_put_byte(buf, ref->first_byte);

    quic_quic_put_varint(buf, ref->sid);
    quic_quic_put_varint(buf, ref->app_err);

    return quic_err_success;
}

quic_err_t quic_crypto_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_crypto_t *const ref = (quic_frame_crypto_t *) frame;
    quic_quic_put_byte(buf, ref->first_byte);
    quic_quic_put_varint(buf, ref->off);
    quic_quic_put_varint(buf, ref->len);
    quic_quic_put_data(buf, ref->len, ref->data);


    return quic_err_success;
}

quic_err_t quic_new_token_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_new_token_t *const ref = (quic_frame_new_token_t *) frame;
    quic_quic_put_byte(buf, ref->first_byte);
    quic_quic_put_varint(buf, ref->len);
    quic_quic_put_data(buf, ref->len, ref->data);

    return quic_err_success;
}

quic_err_t quic_stream_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_stream_t *const ref = (quic_frame_stream_t *) frame;
    quic_quic_put_byte(buf, ref->first_byte);
    quic_quic_put_varint(buf, ref->sid);

    if (ref->first_byte & 0x04) {
        quic_quic_put_varint(buf, ref->off);
    }
    if (ref->first_byte & 0x02) {
        quic_quic_put_varint(buf, ref->len);
    }
    quic_quic_put_data(buf, ref->len, ref->data);

    return quic_err_success;
}

quic_err_t quic_max_data_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_max_data_t *const ref = (quic_frame_max_data_t *) frame;
    quic_quic_put_byte(buf, ref->first_byte);
    quic_quic_put_varint(buf, ref->max_data);

    return quic_err_success;
}

quic_err_t quic_max_stream_data_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_max_stream_data_t *const ref = (quic_frame_max_stream_data_t *) frame;
    quic_quic_put_byte(buf, ref->first_byte);
    quic_quic_put_varint(buf, ref->sid);
    quic_quic_put_varint(buf, ref->max_data);

    return quic_err_success;
}

quic_err_t quic_max_streams_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_max_streams_t *const ref = (quic_frame_max_streams_t *) frame;
    quic_quic_put_byte(buf, ref->first_byte);
    quic_quic_put_varint(buf, ref->max_streams);

    return quic_err_success;
}

quic_err_t quic_data_blocked_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_data_blocked_t *const ref = (quic_frame_data_blocked_t *) frame;
    quic_quic_put_byte(buf, ref->first_byte);
    quic_quic_put_varint(buf, ref->max_data);

    return quic_err_success;
}

quic_err_t quic_stream_data_blocked_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_stream_data_blocked_t *const ref = (quic_frame_stream_data_blocked_t *) frame;
    quic_quic_put_byte(buf, ref->first_byte);
    quic_quic_put_varint(buf, ref->sid);
    quic_quic_put_varint(buf, ref->max_data);

    return quic_err_success;
}

quic_err_t quic_streams_blocked_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_streams_blocked_t *const ref = (quic_frame_streams_blocked_t *) frame;
    quic_quic_put_byte(buf, ref->first_byte);
    quic_quic_put_varint(buf, ref->max_streams);

    return quic_err_success;
}

quic_err_t quic_new_connection_id_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_new_connection_id_t *const ref = (quic_frame_new_connection_id_t *) frame;
    quic_quic_put_byte(buf, ref->first_byte);
    quic_quic_put_varint(buf, ref->seq);
    quic_quic_put_varint(buf, ref->retire);
    quic_quic_put_byte(buf, ref->len);
    quic_quic_put_data(buf, ref->len, ref->conn);
    quic_quic_put_data(buf, 16, ref->token);

    return quic_err_success;
}

quic_err_t quic_retire_connection_id_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_retire_connection_id_t *const ref = (quic_frame_retire_connection_id_t *) frame;
    quic_quic_put_byte(buf, ref->first_byte);
    quic_quic_put_varint(buf, ref->seq);

    return quic_err_success;
}

quic_err_t quic_path_challenge_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_path_challenge_t *const ref = (quic_frame_path_challenge_t *) frame;
    quic_quic_put_byte(buf, ref->first_byte);
    quic_quic_put_data(buf, 8, ref->data);

    return quic_err_success;
}

quic_err_t quic_path_response_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_path_response_t *const ref = (quic_frame_path_response_t *) frame;
    quic_quic_put_byte(buf, ref->first_byte);
    quic_quic_put_data(buf, 8, ref->data);

    return quic_err_success;
}

quic_err_t quic_connection_close_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_connection_close_t *const ref = (quic_frame_connection_close_t *) frame;
    quic_quic_put_byte(buf, ref->first_byte);
    quic_quic_put_varint(buf, ref->err);
    if (ref->first_byte == 0x1c) {
        quic_quic_put_varint(buf, ref->type);
    }
    quic_quic_put_varint(buf, ref->len);
    quic_quic_put_data(buf, ref->len, ref->data);

    return quic_err_success;
}

quic_err_t quic_handshake_done_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_handshake_done_t *const ref = (quic_frame_handshake_done_t *) frame;
    quic_quic_put_byte(buf, ref->first_byte);

    return quic_err_success;
}

