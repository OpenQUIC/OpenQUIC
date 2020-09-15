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

#define quic_varint_len(payload)                                                                                    \
    (1 << (((*(uint8_t *) (payload)) & 0xc0) >> 6))

#define quic_varint_r1(payload)                                                                                     \
    quic_varint_len(payload) == 1 ? (*(uint8_t *) (payload)) :

#define quic_varint_r2(payload)                                                                                     \
    quic_varint_len(payload) == 2 ? (bswap_16((*(uint16_t *) (payload))) & 0x3FFF) :

#define quic_varint_r4(payload)                                                                                     \
    quic_varint_len(payload) == 4 ? (bswap_32((*(uint32_t *) (payload))) & 0x3FFFFFFF) :

#define quic_varint_r8(payload)                                                                                     \
    quic_varint_len(payload) == 8 ? (bswap_64((*(uint64_t *) (payload))) & 0x3FFFFFFFFFFFFFFF) : 0

#define quic_varint_r(payload)                                                                                      \
    (quic_varint_r1(payload) (quic_varint_r2(payload) (quic_varint_r4(payload) (quic_varint_r8(payload)))))


#endif
