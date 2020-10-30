/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_HEADER_H__
#define __OPENQUIC_HEADER_H__

#include "utils/buf.h"
#include "utils/varint.h"
#include <stdint.h>
#include <stddef.h>
#include <byteswap.h>

typedef uint32_t quic_version_t;
typedef uint32_t quic_packet_number_t;

#define QUIC_HEADER_FIELDS       \
    uint8_t first_byte;

#define QUIC_LONG_HEADER_FIELDS  \
    quic_version_t version;      \
    uint8_t conn_area[512];      \

#define QUIC_SHORT_HEADER_FIELDS \
    uint8_t conn_area[255];

typedef struct quic_header_s quic_header_t;
struct quic_header_s {
    QUIC_HEADER_FIELDS
} __attribute__((__packed__));

#define quic_header_is_long(header) \
    ((header)->first_byte & 0x80)

#define quic_packet_type(header)    \
    (((header)->first_byte & 0x30))

#define quic_packet_initial_type    0x00
#define quic_packet_0rtt_type       0x10
#define quic_packet_handshake_type  0x20
#define quic_packet_retry_type      0x30
#define quic_packet_short_type      0x00

typedef struct quic_long_header_s quic_long_header_t;
struct quic_long_header_s {
    QUIC_HEADER_FIELDS
    QUIC_LONG_HEADER_FIELDS
} __attribute__((__packed__));

#define quic_long_header_dst_conn_len_off(header)  \
    (((uint8_t *) (((void *) (header)) + 1 + 4)))

#define quic_long_header_dst_conn_len(header)      \
    (*quic_long_header_dst_conn_len_off(header))

#define quic_long_header_dst_conn_off(header)      \
    ((void *) (quic_long_header_dst_conn_len_off(header) + 1))

#define quic_long_header_src_conn_len_off(header)  \
    ((uint8_t *) (quic_long_header_dst_conn_off(header) + quic_long_header_dst_conn_len(header)))

#define quic_long_header_src_conn_len(header)      \
    (*quic_long_header_src_conn_len_off(header))

#define quic_long_header_src_conn_off(header)      \
    ((void *) (quic_long_header_src_conn_len_off(header) + 1))

#define quic_long_header_payload(header)           \
    (quic_long_header_src_conn_off(header) + quic_long_header_src_conn_len(header))

#define quic_long_header_len(header)               \
    ((size_t) ((void *) quic_long_header_payload(header) - ((void *) (header))))

#define quic_long_header_dst_conn(header) {        \
    .ref = true,                                   \
    .capa = quic_long_header_dst_conn_len(header), \
    .buf = quic_long_header_dst_conn_off(header),  \
}

#define quic_long_header_src_conn(header) {        \
    .ref = true,                                   \
    .capa = quic_long_header_src_conn_len(header), \
    .buf = quic_long_header_src_conn_off(header),  \
}

#define quic_packet_number_r1(field, payload) \
    (field) == 0 ? (*(uint8_t *) (payload)) :

#define quic_packet_number_r2(field, payload) \
    (field) == 1 ? bswap_16(*(uint16_t *) (payload)) :

#define quic_packet_number_r3(field, payload) \
    (field) == 2 ? (bswap_32(*(uint32_t *) (payload)) >> 8) :

#define quic_packet_number_r4(field, payload) \
    (field) == 3 ? bswap_32(*(uint32_t *) (payload)) : 0

#define quic_packet_number_r(field, payload) \
    (quic_packet_number_r1(field & 0x03, payload) (quic_packet_number_r2(field & 0x03, payload) (quic_packet_number_r3(field & 0x03, payload) (quic_packet_number_r4(field & 0x03, payload)))))

#define quic_packet_number_format_len(num) \
    ((num) < 0x100 ? 1 : ((num) < 0x10000 ? 2 : (num) < 1000000 ? 3 : 4))

#define quic_packet_number_format(off, num, len) {               \
    if ((len) == 1) {                                            \
        *(uint8_t *) (off) = (num);                              \
    }                                                            \
    else if ((len) == 2) {                                       \
        *(uint16_t *) (off) = bswap_16((uint16_t) (num));        \
    }                                                            \
    else if ((len) == 3) {                                       \
        *(uint16_t *) (off) = bswap_16((uint16_t) ((num) >> 8)); \
        *(uint8_t *) ((off) + 2) = (uint8_t) (num);              \
    }                                                            \
    else if ((len) == 4) {                                       \
        *(uint32_t *) (off) = bswap_32((uint32_t) (num));        \
    }                                                            \
}

#define QUIC_PAYLOAD_FIELDS     \
    uint8_t type;               \
    quic_packet_number_t p_num; \
    uint64_t payload_len;       \
    void *payload;

typedef struct quic_payload_s quic_payload_t;
struct quic_payload_s {
    QUIC_PAYLOAD_FIELDS
};

typedef struct quic_initial_header_s quic_initial_header_t;
struct quic_initial_header_s {
    QUIC_PAYLOAD_FIELDS

    quic_buf_t token;
};

#define token_capa token.capa
#define token_pos token.pos
#define token_last token.last

static inline quic_initial_header_t quic_initial_header(quic_header_t *const header) {
    void *ptr = quic_long_header_payload(header);
    quic_initial_header_t initial = { .token = { .ref = true } };

    initial.token_capa = quic_varint_r(ptr);
    initial.token_pos = ptr + quic_varint_len(ptr);
    initial.token_last = initial.token_pos + initial.token_capa;
    ptr = initial.token_last;

    initial.payload_len = quic_varint_r(ptr);
    ptr += quic_varint_len(ptr);

    initial.p_num = quic_packet_number_r(header->first_byte, ptr);
    initial.type = quic_packet_initial_type;

    initial.payload = ptr + (header->first_byte & 0x03) + 1;

    return initial;
}

typedef struct quic_0rtt_header_s quic_0rtt_header_t;
struct quic_0rtt_header_s {
    QUIC_PAYLOAD_FIELDS
};

static inline quic_0rtt_header_t quic_0rtt_header(quic_header_t *const header) {
    void *ptr = quic_long_header_payload(header);
    quic_0rtt_header_t zero_rtt = { };

    zero_rtt.payload_len = quic_varint_r(ptr);
    ptr += quic_varint_len(ptr);

    zero_rtt.p_num = quic_packet_number_r(header->first_byte, ptr);
    zero_rtt.type = quic_packet_0rtt_type;

    zero_rtt.payload = ptr + (header->first_byte & 0x03) + 1;

    return zero_rtt;
}

typedef struct quic_handshake_header_s quic_handshake_header_t;
struct quic_handshake_header_s {
    QUIC_PAYLOAD_FIELDS
};

static inline quic_handshake_header_t quic_handshake_header(quic_header_t *const header) {
    void *ptr = quic_long_header_payload(header);
    quic_handshake_header_t handshake = { };

    handshake.payload_len = quic_varint_r(ptr);
    ptr += quic_varint_len(ptr);

    handshake.p_num = quic_packet_number_r(header->first_byte, ptr);
    handshake.type = quic_packet_handshake_type;

    handshake.payload = ptr + (header->first_byte & 0x03) + 1;

    return handshake;
}

typedef struct quic_short_header_s quic_short_header_t;
struct quic_short_header_s {
    QUIC_HEADER_FIELDS
    QUIC_SHORT_HEADER_FIELDS
} __attribute__((__packed__));

#define quic_short_header_dst_conn_off(header) \
    (((void *) (header)) + 1)

#define quic_short_header_payload(header, len) \
    (quic_short_header_dst_conn_off(header) + len)

#define quic_short_header_len(header, len)     \
    ((size_t) (quic_short_header_payload(header, len) - (header)))

static inline quic_payload_t quic_short_header(quic_header_t *const header, size_t len) {
    void *ptr = quic_short_header_payload(header, len);

    quic_payload_t payload = {};

    payload.p_num = quic_packet_number_r(header->first_byte, ptr);
    payload.type = quic_packet_short_type;
    payload.payload = ptr + (header->first_byte & 0x03) + 1;

    return payload;
}

#endif
