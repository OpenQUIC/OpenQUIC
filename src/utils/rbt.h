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
#include "utils/buf.h"
#include "utils/link.h"
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

typedef struct quic_rbt_foreach_qnode_s quic_rbt_foreach_qnode_t;
struct quic_rbt_foreach_qnode_s {
    QUIC_LINK_FIELDS

    quic_rbt_t *node;
};

// TODO 第一次循环时，重复获取根节点
#define quic_rbt_foreach(node_, root)                                                                              \
    quic_link_t _rbt_foreach_queue;                                                                                \
    quic_link_init(&_rbt_foreach_queue);                                                                           \
    for (({ \
            (node_) = (typeof((node_))) (root); \
          }); \
          !quic_rbt_is_nil((node_)); \
         ({ \
            if (!quic_rbt_is_nil((node_)->rb_r)) { \
                quic_rbt_foreach_qnode_t *newly_node = malloc(sizeof(quic_rbt_foreach_qnode_t)); \
                quic_link_init(newly_node); \
                newly_node->node = (node_)->rb_r; \
                quic_link_insert_after(&_rbt_foreach_queue, newly_node); \
            } \
            if (!quic_rbt_is_nil((node_)->rb_l)) { \
                quic_rbt_foreach_qnode_t *newly_node = malloc(sizeof(quic_rbt_foreach_qnode_t)); \
                quic_link_init(newly_node); \
                newly_node->node = (node_)->rb_l; \
                quic_link_insert_after(&_rbt_foreach_queue, newly_node); \
            } \
            if (quic_link_empty(&_rbt_foreach_queue)) { \
                (node_) = (typeof((node_))) quic_rbt_nil; \
            } \
            else { \
                quic_rbt_foreach_qnode_t *cur_node = (typeof(cur_node)) quic_link_prev(&_rbt_foreach_queue); \
                quic_link_remove(cur_node); \
                (node_) = (typeof((node_))) cur_node->node; \
                free(cur_node); \
            } \
          }))

extern const quic_rbt_t rbt_nil;
#define quic_rbt_nil ((quic_rbt_t *) &rbt_nil)

#define quic_rbt_is_nil(node)                   \
    (((quic_rbt_t *) (node)) == quic_rbt_nil)

#define QUIC_RBT_UINT64_FIELDS  \
    QUIC_RBT_FIELDS             \
    uint64_t key;

int quic_rbt_uint64_key_comparer(const void *const key, const quic_rbt_t *const node);
int quic_rbt_uint64_comparer(const quic_rbt_t *const lf, const quic_rbt_t *const rt);

#define QUIC_RBT_STRING_FIELDS \
    QUIC_RBT_FIELDS            \
    quic_buf_t key;

int quic_rbt_string_key_comparer(const void *const key, const quic_rbt_t *const node);
int quic_rbt_string_comparer(const quic_rbt_t *const lf, const quic_rbt_t *const rt);

#endif
