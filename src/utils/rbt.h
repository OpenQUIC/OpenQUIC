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
#include "utils/addr.h"
#include <stdint.h>

#define QUIC_RBT_BLACK  0
#define QUIC_RBT_RED    1

#define QUIC_RBT_FIELDS      \
    quic_rbt_t *rb_p;        \
    quic_rbt_t *rb_r;        \
    quic_rbt_t *rb_l;        \
    quic_rbt_t *morris_link; \
    uint8_t rb_color;

#define QUIC_RBT_EQ 0
#define QUIC_RBT_LS 1
#define QUIC_RBT_GT 2

typedef struct quic_rbt_s quic_rbt_t;
struct quic_rbt_s {
    QUIC_RBT_FIELDS
};

extern const quic_rbt_t rbt_nil;
#define quic_rbt_nil ((quic_rbt_t *) &rbt_nil)

#define quic_rbt_is_nil(node)                   \
    (((quic_rbt_t *) (node)) == quic_rbt_nil)

#define quic_rbt_init(node) {           \
    (node)->rb_p = quic_rbt_nil;        \
    (node)->rb_r = quic_rbt_nil;        \
    (node)->rb_l = quic_rbt_nil;        \
    (node)->morris_link = quic_rbt_nil; \
    (node)->rb_color = QUIC_RBT_RED;    \
}

#define quic_rbt_tree_init(root) \
    (root) = (typeof(root)) quic_rbt_nil

typedef int (*quic_rbt_comparer_t) (const quic_rbt_t *const lf, const quic_rbt_t *const rt);
typedef int (*quic_rbt_key_comparer_t) (const void *const key, const quic_rbt_t *const node);

#define quic_rbt_insert(root, node, comparer) \
    quic_rbt_insert_inner((quic_rbt_t **) (root), (quic_rbt_t *) (node), (comparer))
quic_err_t quic_rbt_insert_inner(quic_rbt_t **const root, quic_rbt_t *const node, quic_rbt_comparer_t comparer);
#define quic_rbt_remove(root, node) \
    quic_rbt_remove_inner((quic_rbt_t **) (root), (quic_rbt_t **) (node))
quic_err_t quic_rbt_remove_inner(quic_rbt_t **const root, quic_rbt_t **const node);
#define quic_rbt_find(root, key, comparer) \
    quic_rbt_find_inner((quic_rbt_t *) (root), (const void *) (key), (comparer))
quic_rbt_t *quic_rbt_find_inner(quic_rbt_t *const root, const void *const key, quic_rbt_key_comparer_t comparer);

typedef struct quic_rbt_foreach_qnode_s quic_rbt_foreach_qnode_t;
struct quic_rbt_foreach_qnode_s {
    QUIC_LINK_FIELDS

    quic_rbt_t *node;
};

// Morris Binary Tree Travel
typedef struct quic_rbt_iterator_s quic_rbt_iterator_t;
struct quic_rbt_iterator_s {
    bool interrupt_1;
    bool interrupt_2;

    quic_rbt_t *cur;
    quic_rbt_t *mr;
};

static inline bool quic_rbt_iterator_is_end(quic_rbt_iterator_t *const iter) {
    return quic_rbt_is_nil(iter->cur);
}

static void quic_rbt_iterator_next(quic_rbt_iterator_t *const iter) {
#define __right(node) (quic_rbt_is_nil((node)->rb_r) ? (node)->morris_link : (node)->rb_r)
#define __left(node) (node)->rb_l
    if (iter->interrupt_1) {
        goto travel_interrupt_1;
    }
    if (iter->interrupt_2) {
        goto travel_interrupt_2;
    }

    while (!quic_rbt_is_nil(iter->cur)) {

        if (quic_rbt_is_nil(__left(iter->cur))) {
            iter->interrupt_1 = true;
            return;

travel_interrupt_1:
            iter->interrupt_1 = false;
            iter->cur = __right(iter->cur);
        }
        else {
            iter->mr = __left(iter->cur);
            while (!quic_rbt_is_nil(__right(iter->mr)) && __right(iter->mr) != iter->cur) {
                iter->mr = __right(iter->mr);
            }

            if (quic_rbt_is_nil(__right(iter->mr))) {
                iter->mr->morris_link = iter->cur;
                iter->cur = __left(iter->cur);
            }
            else {
                iter->interrupt_2 = true;
                return;

travel_interrupt_2:
                iter->interrupt_2 = false;
                iter->cur = __right(iter->mr);
                iter->mr->morris_link = quic_rbt_nil;
                iter->cur = __right(iter->cur);
            }
        }
    }

#undef __right
#undef __left
}

static inline quic_err_t quic_rbt_iterator_init(quic_rbt_iterator_t *const iter, quic_rbt_t *const root) {
    iter->interrupt_1 = false;
    iter->interrupt_2 = false;
    iter->cur = root;
    iter->mr = quic_rbt_nil;
    quic_rbt_iterator_next(iter);

    return quic_err_success;
}

#define quic_rbt_foreach(node, root)                                                                        \
    quic_rbt_iterator_t _iter;                                                                              \
    for (({ quic_rbt_iterator_init(&_iter, (quic_rbt_t *) (root)); (node) = (typeof((node))) _iter.cur; }); \
         !quic_rbt_is_nil((node));                                                                          \
         ({ quic_rbt_iterator_next(&_iter); (node) = (typeof((node))) _iter.cur; }))


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

#define QUIC_RBT_ADDR_FIELDS \
    QUIC_RBT_FIELDS          \
    quic_addr_t key;

int quic_rbt_addr_key_comparer(const void *const key, const quic_rbt_t *const node);
int quic_rbt_addr_comparer(const quic_rbt_t *const lf, const quic_rbt_t *const rt);

#define QUIC_RBT_PATH_FIELDS \
    QUIC_RBT_FIELDS          \
    quic_path_t key;

int quic_rbt_path_key_comparer(const void *const key, const quic_rbt_t *const node);
int quic_rbt_path_comparer(const quic_rbt_t *const lf, const quic_rbt_t *const rt);

#endif
