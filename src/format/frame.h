/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_FRAME_H__
#define __OPENQUIC_FRAME_H__

#include "liteco/lc_link.h"
#include "platform/platform.h"
#include "utils/arr.h"
#include "utils/errno.h"
#include "utils/buf.h"
#include "liteco.h"
#include <stdint.h>

#define quic_frame_padding_type               0x00
#define quic_frame_ping_type                  0x01
#define quic_frame_ack_type                   0x02
#define quic_frame_ack_ecn_type               0x03
#define quic_frame_reset_stream_type          0x04
#define quic_frame_stop_sending_type          0x05
#define quic_frame_crypto_type                0x06
#define quic_frame_new_token_type             0x07
#define quic_frame_stream_type                0x08
#define quic_frame_stream_type_fin            0x09
#define quic_frame_stream_type_len            0x0a
#define quic_frame_stream_type_off            0x0c
#define quic_frame_max_data_type              0x10
#define quic_frame_max_stream_data_type       0x11
#define quic_frame_max_bidi_streams_type      0x12
#define quic_frame_max_uni_streams_type       0x13
#define quic_frame_data_blocked_type          0x14
#define quic_frame_stream_data_blocked_type   0x15
#define quic_frame_bidi_streams_blocked_type  0x16
#define quic_frame_uni_streams_blocked_type   0x17
#define quic_frame_new_connection_id_type     0x18
#define quic_frame_retire_connection_id_type  0x19
#define quic_frame_path_challenge_type        0x1a
#define quic_frame_path_response_type         0x1b
#define quic_frame_quic_connection_close_type 0x1c
#define quic_frame_app_connection_close_type  0x1d
#define quic_frame_handshake_done_type        0x1e

#define QUIC_FRAME_FIELDS                                                            \
    LITECO_LINKNODE_BASE                                                             \
    uint8_t first_byte;                                                              \
    uint8_t ref_count;                                                               \
    void *acked_obj;                                                                 \
    quic_err_t (*on_acked) (void *const acked_obj, const quic_frame_t *const frame); \
    void *lost_obj;                                                                  \
    quic_err_t (*on_lost) (void *const lost_obj, const quic_frame_t *const frame);   \

#define quic_frame_init(frame, type) { \
    liteco_link_init((frame));           \
    (frame)->first_byte = (type);      \
    (frame)->acked_obj = NULL;         \
    (frame)->on_acked = NULL;          \
    (frame)->lost_obj = NULL;          \
    (frame)->on_lost = NULL;           \
}

#define quic_frame_on_acked(frame)                        \
    if ((frame)->on_acked) {                              \
        ((frame)->on_acked((frame)->acked_obj, (frame))); \
    }

#define quic_frame_on_lost(frame)                       \
    if ((frame)->on_lost) {                             \
        ((frame)->on_lost((frame)->lost_obj, (frame))); \
    }

typedef struct quic_frame_s quic_frame_t;
struct quic_frame_s {
    QUIC_FRAME_FIELDS
};

typedef struct quic_frame_ping_s quic_frame_ping_t;
struct quic_frame_ping_s {
    QUIC_FRAME_FIELDS
};

typedef struct quic_ack_range_s quic_ack_range_t;
struct quic_ack_range_s {
    uint64_t gap;
    uint64_t len;
};

typedef struct quic_frame_ack_s quic_frame_ack_t;
struct quic_frame_ack_s {
    QUIC_FRAME_FIELDS

    uint8_t packet_type; /* only used for session handle ACK frame (find retransmission module) */
    uint64_t recv_time; /* only used for session handle ACK frame (congestion control) */

    uint64_t largest_ack;
    uint64_t delay;
    uint64_t first_range;

    uint64_t ect0;
    uint64_t ect1;
    uint64_t ect_ce;

    quic_arr_t ranges;
};

typedef struct quic_frame_reset_stream_s quic_frame_reset_stream_t;
struct quic_frame_reset_stream_s {
    QUIC_FRAME_FIELDS

    uint64_t sid;
    uint64_t app_err;
    uint64_t final_size;
};

typedef struct quic_frame_stop_sending_s quic_frame_stop_sending_t;
struct quic_frame_stop_sending_s {
    QUIC_FRAME_FIELDS

    uint64_t sid;
    uint64_t app_err;
};

typedef struct quic_frame_crypto_s quic_frame_crypto_t;
struct quic_frame_crypto_s {
    QUIC_FRAME_FIELDS

    uint8_t packet_type; /* only used for session handle CRYPTO frame */

    uint64_t off;
    uint64_t len;

    uint8_t data[0];
};

typedef struct quic_frame_new_token_s quic_frame_new_token_t;
struct quic_frame_new_token_s {
    QUIC_FRAME_FIELDS

    uint64_t len;

    uint8_t data[0];
};

typedef struct quic_frame_stream_s quic_frame_stream_t;
struct quic_frame_stream_s {
    QUIC_FRAME_FIELDS

    uint64_t sid;
    uint64_t off;
    uint64_t len;

    uint8_t data[0];
};

typedef struct quic_frame_max_data_s quic_frame_max_data_t;
struct quic_frame_max_data_s {
    QUIC_FRAME_FIELDS

    uint64_t max_data;
};

typedef struct quic_frame_max_stream_data_s quic_frame_max_stream_data_t;
struct quic_frame_max_stream_data_s {
    QUIC_FRAME_FIELDS

    uint64_t sid;
    uint64_t max_data;
};

typedef struct quic_frame_max_streams_s quic_frame_max_streams_t;
struct quic_frame_max_streams_s {
    QUIC_FRAME_FIELDS

    uint64_t max_streams;
};

typedef struct quic_frame_data_blocked_s quic_frame_data_blocked_t;
struct quic_frame_data_blocked_s {
    QUIC_FRAME_FIELDS

    uint64_t max_data;
};

typedef struct quic_frame_stream_data_blocked_s quic_frame_stream_data_blocked_t;
struct quic_frame_stream_data_blocked_s {
    QUIC_FRAME_FIELDS

    uint64_t sid;
    uint64_t max_data;
};

typedef struct quic_frame_streams_blocked_s quic_frame_streams_blocked_t;
struct quic_frame_streams_blocked_s {
    QUIC_FRAME_FIELDS

    uint64_t max_streams;
};

typedef struct quic_frame_new_connection_id_s quic_frame_new_connection_id_t;
struct quic_frame_new_connection_id_s {
    QUIC_FRAME_FIELDS

    uint64_t seq;
    uint64_t retire;
    uint8_t len;
    uint8_t conn[20];
    uint8_t token[16];
};

typedef struct quic_frame_retire_connection_id_s quic_frame_retire_connection_id_t;
struct quic_frame_retire_connection_id_s {
    QUIC_FRAME_FIELDS

    uint64_t seq;
};

typedef struct quic_frame_path_challenge_s quic_frame_path_challenge_t;
struct quic_frame_path_challenge_s {
    QUIC_FRAME_FIELDS

    uint8_t data[8];
};

typedef struct quic_frame_path_response_s quic_frame_path_response_t;
struct quic_frame_path_response_s {
    QUIC_FRAME_FIELDS

    uint8_t data[8];
};

typedef struct quic_frame_connection_close_s quic_frame_connection_close_t;
struct quic_frame_connection_close_s {
    QUIC_FRAME_FIELDS

    uint64_t err;
    uint64_t type;
    uint64_t len;
    uint8_t data[0];
};

typedef struct quic_frame_handshake_done_s quic_frame_handshake_done_t;
struct quic_frame_handshake_done_s {
    QUIC_FRAME_FIELDS;
};

typedef quic_err_t (*quic_frame_parser_t)(quic_frame_t **const frame, quic_buf_t *const buf);
typedef quic_err_t (*quic_frame_formatter_t)(quic_buf_t *const buf, const quic_frame_t *const frame);
typedef uint64_t (*quic_frame_sizer_t)(const quic_frame_t *const frame);

extern const quic_frame_formatter_t quic_frame_formatter[256];
extern const quic_frame_parser_t quic_frame_parser[256];
extern const quic_frame_sizer_t quic_frame_sizer[256];

#define quic_frame_format(buf, frame) \
    quic_frame_format_inner((buf), (quic_frame_t *) (frame))

__quic_header_inline quic_err_t quic_frame_format_inner(quic_buf_t *const buf, quic_frame_t *const frame) {
    if (!quic_frame_formatter[frame->first_byte]) {
        return quic_err_not_implemented;
    }

    return quic_frame_formatter[frame->first_byte](buf, frame);
}

#define quic_frame_parse(frame, buf) \
    quic_frame_parse_inner((quic_frame_t **) &frame, (buf))

__quic_header_inline quic_err_t quic_frame_parse_inner(quic_frame_t **const frame, quic_buf_t *const buf) {
    if (!quic_frame_parser[*(uint8_t *) buf->pos]) {
        return quic_err_not_implemented;
    }

    return quic_frame_parser[*(uint8_t *) buf->pos](frame, buf);
}

#define quic_frame_size(frame) \
    quic_frame_size_inner((const quic_frame_t *) (frame))

__quic_header_inline uint64_t quic_frame_size_inner(const quic_frame_t *const frame) {
    if (!quic_frame_sizer[frame->first_byte]) {
        return 0;
    }

    return quic_frame_sizer[frame->first_byte](frame);
}

#endif
