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

static quic_err_t __ping_parse(quic_frame_ping_t **const frame, quic_buf_t *const buf);
static quic_err_t __ack_parse(quic_frame_ack_t **const frame, quic_buf_t *const buf);
static quic_err_t __reset_stream_parse(quic_frame_reset_stream_t **const frame, quic_buf_t *const buf);
static quic_err_t __stop_sending_parse(quic_frame_stop_sending_t **const frame, quic_buf_t *const buf);
static quic_err_t __crypto_parse(quic_frame_crypto_t **const frame, quic_buf_t *const buf);
static quic_err_t __new_token_parse(quic_frame_new_token_t **const frame, quic_buf_t *const buf);
static quic_err_t __stream_parse(quic_frame_stream_t **const frame, quic_buf_t *const buf);
static quic_err_t __max_data_parse(quic_frame_max_data_t **const frame, quic_buf_t *const buf);
static quic_err_t __max_stream_data_parse(quic_frame_max_stream_data_t **const frame, quic_buf_t *const buf);
static quic_err_t __max_streams_parse(quic_frame_max_streams_t **const frame, quic_buf_t *const buf);
static quic_err_t __data_blocked_parse(quic_frame_data_blocked_t **const frame, quic_buf_t *const buf);
static quic_err_t __stream_data_blocked_parse(quic_frame_stream_data_blocked_t **const frame, quic_buf_t *const buf);
static quic_err_t __streams_blocked_parse(quic_frame_streams_blocked_t **const frame, quic_buf_t *const buf);
static quic_err_t __new_connection_id_parse(quic_frame_new_connection_id_t **const frame, quic_buf_t *const buf);
static quic_err_t __retire_connection_id_parse(quic_frame_retire_connection_id_t **const frame, quic_buf_t *const buf);
static quic_err_t __path_challenge_parse(quic_frame_path_challenge_t **const frame, quic_buf_t *const buf);
static quic_err_t __path_response_parse(quic_frame_path_response_t **const frame, quic_buf_t *const buf);
static quic_err_t __connection_close_parse(quic_frame_connection_close_t **const frame, quic_buf_t *const buf);
static quic_err_t __handshake_done_parse(quic_frame_handshake_done_t **const frame, quic_buf_t *const buf);

#define __quic_frame_alloc(frame, _first_byte, size)        \
    if ((*(frame) = malloc((size))) == NULL) {              \
        return quic_err_internal_error;                     \
    }                                                       \
    (**(frame)).first_byte = (_first_byte);                 \
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

static quic_err_t __ping_parse(quic_frame_ping_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    uint8_t first;

    first = __quic_first_byte(buf);

    __quic_frame_alloc(frame, first, sizeof(quic_frame_ping_t));

    return quic_err_success;
}

static quic_err_t __ack_parse(quic_frame_ack_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_ack_t ref = {};

    ref.first_byte = __quic_first_byte(buf);

    __quic_varint(ref.largest_ack, buf);
    __quic_varint(ref.delay, buf);
    __quic_varint(ref.ranges.count, buf);
    __quic_varint(ref.first_range, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_ack_t) + ref.ranges.count * sizeof(quic_ack_range_t));
    **frame = ref;
    (**frame).ranges.size = sizeof(quic_ack_range_t);

    uint64_t i;
    for (i = 0; i < ref.ranges.count; i++) {
        __quic_varint(quic_arr(&(**frame).ranges, i, quic_ack_range_t)->gap, buf);
        __quic_varint(quic_arr(&(**frame).ranges, i, quic_ack_range_t)->len, buf);
    }

    if (ref.first_byte == quic_frame_ack_ecn_type) {
        __quic_varint((**frame).ect0, buf);
        __quic_varint((**frame).ect1, buf);
        __quic_varint((**frame).ect_ce, buf);
    }

    return quic_err_success;
}

static quic_err_t __reset_stream_parse(quic_frame_reset_stream_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_reset_stream_t ref = { };

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.sid, buf);
    __quic_varint(ref.app_err, buf);
    __quic_varint(ref.final_size, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_reset_stream_t));
    **frame = ref;

    return quic_err_success;
}

static quic_err_t __stop_sending_parse(quic_frame_stop_sending_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_stop_sending_t ref = { };

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.sid, buf);
    __quic_varint(ref.app_err, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_stop_sending_t));
    **frame = ref;

    return quic_err_success;
}

static quic_err_t __crypto_parse(quic_frame_crypto_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_crypto_t ref = { };

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.off, buf);
    __quic_varint(ref.len, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_crypto_t) + ref.len);
    **frame = ref;

    __quic_extend_data(**frame, ref.len, buf);

    return quic_err_success;
}

static quic_err_t __new_token_parse(quic_frame_new_token_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_new_token_t ref = { };

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.len, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_new_token_t) + ref.len);
    **frame = ref;

    __quic_extend_data(**frame, ref.len, buf);

    return quic_err_success;
}

static quic_err_t __stream_parse(quic_frame_stream_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_stream_t ref = { };

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
    **frame = ref;

    __quic_extend_data(**frame, ref.len, buf);

    return quic_err_success;
}

static quic_err_t __max_data_parse(quic_frame_max_data_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_max_data_t ref = { };

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.max_data, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_max_data_t));
    **frame = ref;

    return quic_err_success;
}

static quic_err_t __max_stream_data_parse(quic_frame_max_stream_data_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_max_stream_data_t ref = { };

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.sid, buf);
    __quic_varint(ref.max_data, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_max_stream_data_t));
    **frame = ref;

    return quic_err_success;
}

static quic_err_t __max_streams_parse(quic_frame_max_streams_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_max_streams_t ref = { };

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.max_streams, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_max_streams_t));
    **frame = ref;

    return quic_err_success;
}

static quic_err_t __data_blocked_parse(quic_frame_data_blocked_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_data_blocked_t ref = { };

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.max_data, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_data_blocked_t));
    **frame = ref;

    return quic_err_success;
}

static quic_err_t __stream_data_blocked_parse(quic_frame_stream_data_blocked_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_stream_data_blocked_t ref = { };

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.sid, buf);
    __quic_varint(ref.max_data, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_data_blocked_t));
    **frame = ref;

    return quic_err_success;
}

static quic_err_t __streams_blocked_parse(quic_frame_streams_blocked_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_streams_blocked_t ref = { };

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.max_streams, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_streams_blocked_t));
    **frame = ref;

    return quic_err_success;
}

static quic_err_t __new_connection_id_parse(quic_frame_new_connection_id_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_new_connection_id_t ref = { };

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
    **frame = ref;

    return quic_err_success;
}

static quic_err_t __retire_connection_id_parse(quic_frame_retire_connection_id_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_retire_connection_id_t ref = { };

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.seq, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_retire_connection_id_t));
    **frame = ref;

    return quic_err_success;
}

static quic_err_t __path_challenge_parse(quic_frame_path_challenge_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_path_challenge_t ref = { };

    ref.first_byte = __quic_first_byte(buf);
    if (buf->pos + 8 > buf->last) {
        return quic_err_bad_format;
    }
    memcpy(ref.data, buf->pos, 8);
    buf->pos += 8;

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_path_challenge_t));
    **frame = ref;

    return quic_err_success;
}

static quic_err_t __path_response_parse(quic_frame_path_response_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_path_response_t ref = { };

    ref.first_byte = __quic_first_byte(buf);
    if (buf->pos + 8 > buf->last) {
        return quic_err_bad_format;
    }
    memcpy(ref.data, buf->pos, 8);
    buf->pos += 8;

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_path_response_t));
    **frame = ref;

    return quic_err_success;
}

static quic_err_t __connection_close_parse(quic_frame_connection_close_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    quic_frame_connection_close_t ref = { };

    ref.first_byte = __quic_first_byte(buf);
    __quic_varint(ref.err, buf);
    if (ref.first_byte == 0x1c) {
        __quic_varint(ref.type, buf);
    }
    __quic_varint(ref.len, buf);

    __quic_frame_alloc(frame, ref.first_byte, sizeof(quic_frame_connection_close_t));
    **frame = ref;

    __quic_extend_data(**frame, ref.len, buf);

    return quic_err_success;
}

static quic_err_t __handshake_done_parse(quic_frame_handshake_done_t **const frame, quic_buf_t *const buf) {
    *frame = NULL;
    uint8_t first;
    
    first = __quic_first_byte(buf);

    __quic_frame_alloc(frame, first, sizeof(quic_frame_handshake_done_t));

    return quic_err_success;
}
