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

#define quic_rbt_init(node) {           \
    (node)->rb_p = quic_rbt_nil;        \
    (node)->rb_r = quic_rbt_nil;        \
    (node)->rb_l = quic_rbt_nil;        \
    (node)->rb_color = QUIC_RBT_RED;    \
}

#define quic_rbt_tree_init(root)            \
    (root) = (typeof(root)) quic_rbt_nil

typedef int (*quic_rbt_comparer_t) (const quic_rbt_t *const lf, const quic_rbt_t *const rt);
typedef int (*quic_rbt_key_comparer_t) (const void *const key, const quic_rbt_t *const node);

#define quic_rbt_insert(root, node, comparer)                                           \
    quic_rbt_insert_inner((quic_rbt_t **) (root), (quic_rbt_t *) (node), (comparer))
quic_err_t quic_rbt_insert_inner(quic_rbt_t **const root, quic_rbt_t *const node, quic_rbt_comparer_t comparer);
#define quic_rbt_remove(root, node)                                                     \
    quic_rbt_remove_inner((quic_rbt_t **) (root), (quic_rbt_t **) (node))
quic_err_t quic_rbt_remove_inner(quic_rbt_t **const root, quic_rbt_t **const node);
#define quic_rbt_find(root, key, comparer)                                              \
    quic_rbt_find_inner((quic_rbt_t *) (root), (const void *) (key), (comparer))
quic_rbt_t *quic_rbt_find_inner(quic_rbt_t *const root, const void *const key, quic_rbt_key_comparer_t comparer);

extern const quic_rbt_t rbt_nil;
#define quic_rbt_nil ((quic_rbt_t *) &rbt_nil)

#define quic_rbt_is_nil(node)                   \
    (((quic_rbt_t *) (node)) == quic_rbt_nil)

#define QUIC_RBT_UINT64_FIELDS  \
    QUIC_RBT_FIELDS             \
    uint64_t key;

int quic_rbt_uint64_key_comparer(const void *const key, const quic_rbt_t *const node);
int quic_rbt_uint64_comparer(const quic_rbt_t *const lf, const quic_rbt_t *const rt);

typedef struct quic_rbt_string_key_field_s quic_rbt_string_key_field_t;
struct quic_rbt_string_key_field_s {
    uint32_t len;
    uint8_t *data;
};

#define QUIC_RBT_STRING_FIELDS \
    QUIC_RBT_FIELDS            \
    quic_rbt_string_key_field_t key;

int quic_rbt_string_key_comparer(const void *const key, const quic_rbt_t *const node);
int quic_rbt_string_comparer(const quic_rbt_t *const lf, const quic_rbt_t *const rt);

#endif
