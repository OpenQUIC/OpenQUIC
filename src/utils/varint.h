/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_VARINT_H__
#define __OPENQUIC_VARINT_H__

#include <stdint.h>
#include <byteswap.h>

#define quic_varint_len(payload)                                                                                                    \
    (1 << (((*(uint8_t *) (payload)) & 0xc0) >> 6))

#define quic_varint_r1(payload)                                                                                                     \
    quic_varint_len(payload) == 1 ? (*(uint8_t *) (payload)) :

#define quic_varint_r2(payload)                                                                                                     \
    quic_varint_len(payload) == 2 ? (bswap_16((*(uint16_t *) (payload)) & ~0xC0)) :

#define quic_varint_r4(payload)                                                                                                     \
    quic_varint_len(payload) == 4 ? (bswap_32((*(uint32_t *) (payload)) & ~0xC0)) :

#define quic_varint_r8(payload)                                                                                                     \
    quic_varint_len(payload) == 8 ? (bswap_64((*(uint64_t *) (payload)) & ~0xC0)) : 0

#define quic_varint_r(payload)                                                                                                      \
    (quic_varint_r1(payload) (quic_varint_r2(payload) (quic_varint_r4(payload) (quic_varint_r8(payload)))))

#define quic_varint_format_len(payload)                                                                                             \
    ((payload) <= 63 ? 1 : ((payload) <= 16383 ? 2 : ((payload) <= 1073741823 ? 4 : ((payload) <= 4611686018427387903UL) ? 8 : 0)))

#define quic_varint_format_r(buf, payload) {                                                                                    \
    uint8_t len = quic_varint_format_len(payload);                                                                              \
    if (len == 1) {                                                                                                             \
        *(uint8_t *) (buf)->pos = (uint8_t) (payload);                                                                          \
    }                                                                                                                           \
    else if (len == 2) {                                                                                                        \
        *(uint16_t *) (buf)->pos = bswap_16((uint16_t) (payload)) | 0x40;                                                       \
    }                                                                                                                           \
    else if (len == 4) {                                                                                                        \
        *(uint32_t *) (buf)->pos = bswap_32((uint32_t) (payload)) | 0x80;                                                       \
    }                                                                                                                           \
    else if (len == 8) {                                                                                                        \
        *(uint64_t *) (buf)->pos = bswap_64((payload)) | 0xC0;                                                                  \
    }                                                                                                                           \
    (buf)->pos += len;                                                                                                          \
}

#endif
