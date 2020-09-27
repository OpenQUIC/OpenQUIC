/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_RBTREE_H__
#define __OPENQUIC_RBTREE_H__

#include "utils/errno.h"
#include <stdint.h>

#define QUIC_RBT_BLACK  0
#define QUIC_RBT_RED    1

#define QUIC_RBT_FIELDS \
    quic_rbt_t *rb_p;   \
    quic_rbt_t *rb_r;   \
    quic_rbt_t *rb_l;   \
    uint8_t rb_color;

#define QUIC_RBT_EQ 0
#define QUIC_RBT_LS 1
#define QUIC_RBT_GT 2

typedef struct quic_rbt_s quic_rbt_t;
struct quic_rbt_s {
    QUIC_RBT_FIELDS
};

typedef int (*quic_rbt_comparer_t) (const quic_rbt_t *const lf, const quic_rbt_t *const rt);
typedef int (*quic_rbt_key_comparer_t) (const void *const key, const quic_rbt_t *const node);

quic_err_t quic_rbt_insert(quic_rbt_t **const root, quic_rbt_t *const node, quic_rbt_comparer_t comparer);
quic_err_t quic_rbt_remove(quic_rbt_t **const root, quic_rbt_t **const node);
quic_rbt_t *quic_rbt_find(quic_rbt_t *const root, const void *const key, quic_rbt_key_comparer_t comparer);

extern const quic_rbt_t rbt_nil;
#define quic_rbt_nil ((quic_rbt_t *) &rbt_nil)

#endif
