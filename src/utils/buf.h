/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_BUF_H__
#define __OPENQUIC_BUF_H__

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <malloc.h>

typedef struct quic_buf_s quic_buf_t;
struct quic_buf_s {
    bool ref;

    uint64_t capa;
    void *buf;

    void *pos;
    void *last;
};

#define quic_buf_setpl(b) {                                                                     \
    (b)->pos = (b)->buf;                                                                        \
    (b)->last = (b)->pos + (b)->capa;                                                           \
}

#define quic_buf_size(a) ((a)->last - (a)->pos)

#define quic_buf_empty(a) (quic_buf_size(a) == 0)

#define quic_buf_cmp(a, b)                                                                      \
    (((a)->capa - (b)->capa) || memcmp((a)->buf, (b)->buf, (a)->capa))

#define quic_buf_copy(target, exp) {                                                            \
    if (!(target)->ref && (target)->buf) {                                                      \
        free((target)->buf);                                                                    \
    }                                                                                           \
    (target)->ref = false;                                                                      \
    (target)->capa = quic_buf_size(exp);                                                        \
    (target)->buf = malloc((target)->capa);                                                     \
    memcpy((target)->buf, (exp)->pos, (target)->capa);                                          \
    quic_buf_setpl(target);                                                                     \
}

#endif
