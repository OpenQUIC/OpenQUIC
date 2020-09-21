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

static quic_err_t __ping_parse(quic_frame_t **const frame, quic_buf_t *const buf);
static quic_err_t __ack_parse(quic_frame_t **const frame, quic_buf_t *const buf);
static quic_err_t __reset_stream_parse(quic_frame_t **const frame, quic_buf_t *const buf);
static quic_err_t __stop_sending_parse(quic_frame_t **const frame, quic_buf_t *const buf);
static quic_err_t __crypto_parse(quic_frame_t **const frame, quic_buf_t *const buf);
static quic_err_t __new_token_parse(quic_frame_t **const frame, quic_buf_t *const buf);
static quic_err_t __stream_parse(quic_frame_t **const frame, quic_buf_t *const buf);
static quic_err_t __max_data_parse(quic_frame_t **const frame, quic_buf_t *const buf);
static quic_err_t __max_stream_data_parse(quic_frame_t **const frame, quic_buf_t *const buf);
static quic_err_t __max_streams_parse(quic_frame_t **const frame, quic_buf_t *const buf);
static quic_err_t __data_blocked_parse(quic_frame_t **const frame, quic_buf_t *const buf);
static quic_err_t __stream_data_blocked_parse(quic_frame_t **const frame, quic_buf_t *const buf);
static quic_err_t __streams_blocked_parse(quic_frame_t **const frame, quic_buf_t *const buf);
static quic_err_t __new_connection_id_parse(quic_frame_t **const frame, quic_buf_t *const buf);
static quic_err_t __retire_connection_id_parse(quic_frame_t **const frame, quic_buf_t *const buf);
static quic_err_t __path_challenge_parse(quic_frame_t **const frame, quic_buf_t *const buf);
static quic_err_t __path_response_parse(quic_frame_t **const frame, quic_buf_t *const buf);
static quic_err_t __connection_close_parse(quic_frame_t **const frame, quic_buf_t *const buf);
static quic_err_t __handshake_done_parse(quic_frame_t **const frame, quic_buf_t *const buf);

static quic_err_t __ping_format(quic_buf_t *const buf, quic_frame_t *const frame);
static quic_err_t __ack_format(quic_buf_t *const buf, quic_frame_t *const frame);
static quic_err_t __reset_straam_format(quic_buf_t *const buf, quic_frame_t *const frame);
static quic_err_t __stop_sending_format(quic_buf_t *const buf, quic_frame_t *const frame);
static quic_err_t __crypto_format(quic_buf_t *const buf, quic_frame_t *const frame);
static quic_err_t __new_token_format(quic_buf_t *const buf, quic_frame_t *const frame);
static quic_err_t __stream_format(quic_buf_t *const buf, quic_frame_t *const frame);

#define __quic_frame_alloc(frame, _first_byte, size)        \
    if ((*(frame) = malloc((size))) == NULL) {              \
        return quic_err_internal_error;                     \
    }                                                       \
    (**(frame)).first_byte = (_first_byte);                 \
    (**(frame)).ref_count = 1;                              \
    (**(frame)).next = NULL

#define __quic_first_byte(buf)                              \
    *((uint8_t *) ((buf)->pos++))

#define __quic_varint(target, buf)                                  \
    if ((buf)->pos + quic_varint_len((buf)->pos) > (buf)->last) {   \
        return quic_err_bad_format;                                 \
    }                                                               \
    (target) = quic_varint_r((buf)->pos);                           \
    (buf)->pos += quic_varint_len((buf)->pos)
    
#define __quic_extend_data(frame, len, buf)                         \
    if ((buf)->pos + (len) > (buf)->last) {                         \
        return quic_err_bad_format;                                 \
    }                                                               \
    memcpy((frame).data, (buf)->pos, (len));                        \
    (buf)->pos += (len)

#define __quic_frame_init { \
    .ref_count = 1,         \
}

const quic_frame_parser_t quic_frame_parser[256] = {
    NULL,                         // 0x00
    __ping_parse,                 // 0x01
    __ack_parse,                  // 0x02
    __ack_parse,                  // 0x03
    __reset_stream_parse,         // 0x04
    __stop_sending_parse,         // 0x05
    __crypto_parse,               // 0x06
    __new_token_parse,            // 0x07
    __stream_parse,               // 0x08
    __stream_parse,               // 0x09
    __stream_parse,               // 0x0a
    __stream_parse,               // 0x0b
    __stream_parse,               // 0x0c
    __stream_parse,               // 0x0d
    __stream_parse,               // 0x0e
    __stream_parse,               // 0x0f
    __max_data_parse,             // 0x10
    __max_stream_data_parse,      // 0x11
    __max_streams_parse,          // 0x12
    __max_streams_parse,          // 0x13
    __data_blocked_parse,         // 0x14
    __data_blocked_parse,         // 0x15
    __stream_data_blocked_parse,  // 0x16
    __stream_data_blocked_parse,  // 0x17
    __new_connection_id_parse,    // 0x18
    __retire_connection_id_parse, // 0x19
    __path_challenge_parse,       // 0x1a
    __path_response_parse,        // 0x1b
    __connection_close_parse,     // 0x1c
    __connection_close_parse,     // 0x1d
    __handshake_done_parse,       // 0x1e
};

#define __quic_put_byte(buf, byte)          \
    if ((buf)->pos + 1 > (buf)->last) {     \
        return quic_err_bad_format;         \
    }                                       \
    *((uint8_t *) ((buf)->pos++)) = (byte)  \

#define __quic_put_varint(buf, varint)                                  \
    if ((buf)->pos + quic_varint_format_len(varint) > (buf)->last) {    \
        return quic_err_bad_format;                                     \
    }                                                                   \
    quic_varint_format_r(buf, varint)

#define __quic_put_data(buf, len, data)                                 \
    if ((buf)->pos + len > (buf)->last) {                               \
        return quic_err_bad_format;                                     \
    }                                                                   \
    memcpy((buf)->pos, (data), (len));                                  \
    (buf)->pos += (len)

static quic_err_t __ping_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    uint8_t first;

    first = __quic_first_byte(buf);

    __quic_frame_alloc(frame, first, sizeof(quic_frame_ping_t));

    return quic_err_success;
}

static quic_err_t __ack_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_ack_t ref = __quic_frame_init;

    ref.first_byte = __quic_first_byte(buf);

    __quic_varint(ref.largest_ack, buf);
    __quic_varint(ref.delay, buf);
    __quic_varint(ref.ranges.count, buf);
    __quic_varint(ref.first_range, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_ack_t) + ref.ranges.count * sizeof(quic_ack_range_t));
    *(quic_frame_ack_t *) *frame = ref;
    (*(quic_frame_ack_t *) *frame).ranges.size = sizeof(quic_ack_range_t);

    uint64_t i;
    quic_arr_t *ranges = &(*(quic_frame_ack_t *) *frame).ranges;
    for (i = 0; i < ref.ranges.count; i++) {
        __quic_varint(quic_arr(ranges, i, quic_ack_range_t)->gap, buf);
        __quic_varint(quic_arr(ranges, i, quic_ack_range_t)->len, buf);
    }

    if (ref.first_byte == quic_frame_ack_ecn_type) {
        __quic_varint((*(quic_frame_ack_t *) *frame).ect0, buf);
        __quic_varint((*(quic_frame_ack_t *) *frame).ect1, buf);
        __quic_varint((*(quic_frame_ack_t *) *frame).ect_ce, buf);
    }

    return quic_err_success;
}

static quic_err_t __reset_stream_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_reset_stream_t ref = __quic_frame_init;

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.sid, buf);
    __quic_varint(ref.app_err, buf);
    __quic_varint(ref.final_size, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_reset_stream_t));
    *(quic_frame_reset_stream_t *) *frame = ref;

    return quic_err_success;
}

static quic_err_t __stop_sending_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_stop_sending_t ref = __quic_frame_init;

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.sid, buf);
    __quic_varint(ref.app_err, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_stop_sending_t));
    *(quic_frame_stop_sending_t *) *frame = ref;

    return quic_err_success;
}

static quic_err_t __crypto_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_crypto_t ref = __quic_frame_init;

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.off, buf);
    __quic_varint(ref.len, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_crypto_t) + ref.len);
    *(quic_frame_crypto_t *) *frame = ref;

    __quic_extend_data(*(quic_frame_crypto_t *) *frame, ref.len, buf);

    return quic_err_success;
}

static quic_err_t __new_token_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_new_token_t ref = __quic_frame_init;

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.len, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_new_token_t) + ref.len);
    *(quic_frame_new_token_t *) *frame = ref;

    __quic_extend_data(*(quic_frame_new_token_t *) *frame, ref.len, buf);

    return quic_err_success;
}

static quic_err_t __stream_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_stream_t ref = __quic_frame_init;

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.sid, buf);

    if (ref.first_byte & 0x04) {
        __quic_varint(ref.off, buf);
    }
    if (ref.first_byte & 0x02) {
        __quic_varint(ref.len, buf);
    }
    else {
        ref.len = buf->last - buf->pos;
    }

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_stream_t) + ref.len);
    *(quic_frame_stream_t *) *frame = ref;

    __quic_extend_data(*(quic_frame_stream_t *) *frame, ref.len, buf);

    return quic_err_success;
}

static quic_err_t __max_data_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_max_data_t ref = __quic_frame_init;

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.max_data, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_max_data_t));
    *(quic_frame_max_data_t *) *frame = ref;

    return quic_err_success;
}

static quic_err_t __max_stream_data_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_max_stream_data_t ref = __quic_frame_init;

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.sid, buf);
    __quic_varint(ref.max_data, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_max_stream_data_t));
    *(quic_frame_max_stream_data_t *) *frame = ref;

    return quic_err_success;
}

static quic_err_t __max_streams_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_max_streams_t ref = __quic_frame_init;

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.max_streams, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_max_streams_t));
    *(quic_frame_max_streams_t *) *frame = ref;

    return quic_err_success;
}

static quic_err_t __data_blocked_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_data_blocked_t ref = __quic_frame_init;

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.max_data, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_data_blocked_t));
    *(quic_frame_data_blocked_t *) *frame = ref;

    return quic_err_success;
}

static quic_err_t __stream_data_blocked_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_stream_data_blocked_t ref = __quic_frame_init;

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.sid, buf);
    __quic_varint(ref.max_data, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_data_blocked_t));
    *(quic_frame_stream_data_blocked_t *) *frame = ref;

    return quic_err_success;
}

static quic_err_t __streams_blocked_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_streams_blocked_t ref = __quic_frame_init;

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.max_streams, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_streams_blocked_t));
    *(quic_frame_streams_blocked_t *) *frame = ref;

    return quic_err_success;
}

static quic_err_t __new_connection_id_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_new_connection_id_t ref = __quic_frame_init;

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.seq, buf);
    __quic_varint(ref.retire, buf);
    ref.len = __quic_first_byte(buf);
    if (ref.len < 1 || ref.len > 20) {
        return quic_err_bad_format;
    }
    if (buf->pos + ref.len + 128 > buf->last) {
        return quic_err_bad_format;
    }
    memcpy(ref.conn, buf->pos, ref.len);
    buf->pos += ref.len;
    memcpy(ref.token, buf->pos, 128);
    buf->pos += 128;

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_new_connection_id_t));
    *(quic_frame_new_connection_id_t *) *frame = ref;

    return quic_err_success;
}

static quic_err_t __retire_connection_id_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_retire_connection_id_t ref = __quic_frame_init;

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.seq, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_retire_connection_id_t));
    *(quic_frame_retire_connection_id_t *) *frame = ref;

    return quic_err_success;
}

static quic_err_t __path_challenge_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_path_challenge_t ref = __quic_frame_init;

    ref.first_byte = __quic_first_byte(buf);
    if (buf->pos + 8 > buf->last) {
        return quic_err_bad_format;
    }
    memcpy(ref.data, buf->pos, 8);
    buf->pos += 8;

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_path_challenge_t));
    *(quic_frame_path_challenge_t *) *frame = ref;

    return quic_err_success;
}

static quic_err_t __path_response_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_path_response_t ref = __quic_frame_init;

    ref.first_byte = __quic_first_byte(buf);
    if (buf->pos + 8 > buf->last) {
        return quic_err_bad_format;
    }
    memcpy(ref.data, buf->pos, 8);
    buf->pos += 8;

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_path_response_t));
    *(quic_frame_path_response_t *) *frame = ref;

    return quic_err_success;
}

static quic_err_t __connection_close_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_connection_close_t ref = __quic_frame_init;

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.err, buf);
    if (ref.first_byte == 0x1c) {
        __quic_varint(ref.type, buf);
    }
    __quic_varint(ref.len, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_connection_close_t));
    *(quic_frame_connection_close_t *) *frame = ref;

    __quic_extend_data(*(quic_frame_connection_close_t *) *frame, ref.len, buf);

    return quic_err_success;
}

static quic_err_t __handshake_done_parse(quic_frame_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    uint8_t first;
    
    first = __quic_first_byte(buf);

    __quic_frame_alloc(frame, first, sizeof(quic_frame_handshake_done_t));

    return quic_err_success;
}

static quic_err_t __ping_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    __quic_put_byte(buf, frame->first_byte);

    return quic_err_success;
}

static quic_err_t __ack_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_ack_t *const ref = (quic_frame_ack_t *) frame;
    __quic_put_byte(buf, frame->first_byte);

    __quic_put_varint(buf, ref->largest_ack);
    __quic_put_varint(buf, ref->delay);
    __quic_put_varint(buf, (uint64_t) ref->ranges.count);
    __quic_put_varint(buf, ref->first_range);

    uint64_t i;
    quic_arr_t *ranges = &ref->ranges;
    for (i = 0; i < ranges->count; i++) {
        __quic_put_varint(buf, quic_arr(ranges, i, quic_ack_range_t)->gap);
        __quic_put_varint(buf, quic_arr(ranges, i, quic_ack_range_t)->len);
    }

    if (ref->first_byte == quic_frame_ack_ecn_type) {
        __quic_put_varint(buf, ref->ect0);
        __quic_put_varint(buf, ref->ect1);
        __quic_put_varint(buf, ref->ect_ce);
    }

    return quic_err_success;
}

static quic_err_t __reset_straam_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_reset_stream_t *const ref = (quic_frame_reset_stream_t *) frame;
    __quic_put_byte(buf, ref->first_byte);

    __quic_put_varint(buf, ref->sid);
    __quic_put_varint(buf, ref->app_err);
    __quic_put_varint(buf, ref->final_size);

    return quic_err_success;
}

static quic_err_t __stop_sending_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_stop_sending_t *const ref = (quic_frame_stop_sending_t *) frame;
    __quic_put_byte(buf, ref->first_byte);

    __quic_put_varint(buf, ref->sid);
    __quic_put_varint(buf, ref->app_err);

    return quic_err_success;
}

static quic_err_t __crypto_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_crypto_t *const ref = (quic_frame_crypto_t *) frame;
    __quic_put_byte(buf, ref->first_byte);
    __quic_put_varint(buf, ref->off);
    __quic_put_varint(buf, ref->len);
    __quic_put_data(buf, ref->len, ref->data);

    return quic_err_success;
}

static quic_err_t __new_token_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_new_token_t *const ref = (quic_frame_new_token_t *) frame;
    __quic_put_byte(buf, ref->first_byte);
    __quic_put_varint(buf, ref->len);
    __quic_put_data(buf, ref->len, ref->data);

    return quic_err_success;
}

static quic_err_t __stream_format(quic_buf_t *const buf, quic_frame_t *const frame) {
    quic_frame_stream_t *const ref = (quic_frame_stream_t *) frame;
    __quic_put_byte(buf, ref->first_byte);
    __quic_put_varint(buf, ref->sid);

    if (ref->first_byte & 0x04) {
        __quic_put_varint(buf, ref->off);
    }
    if (ref->first_byte & 0x02) {
        __quic_put_varint(buf, ref->len);
    }
    __quic_put_data(buf, ref->len, ref->data);

    return quic_err_success;
}
