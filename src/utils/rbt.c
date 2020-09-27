/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "utils/rbt.h"
#include <stdio.h>

const quic_rbt_t rbt_nil = {
    .rb_p = quic_rbt_nil,
    .rb_r = quic_rbt_nil,
    .rb_l = quic_rbt_nil,
    .rb_color = QUIC_RBT_BLACK
};

static inline void __rbt_lr(quic_rbt_t **const root, quic_rbt_t *const node);
static inline void __rbt_rr(quic_rbt_t **const root, quic_rbt_t *const node);
static void __rbt_fixup(quic_rbt_t **const root, quic_rbt_t *node);
static inline void __rbt_assign(quic_rbt_t **const root, quic_rbt_t *const target, quic_rbt_t *const ref);
static inline void __rbt_del_case1(quic_rbt_t **const root, quic_rbt_t *const node);
static inline void __rbt_del_case2(quic_rbt_t **const root, quic_rbt_t *const node);
static inline void __rbt_del_case3(quic_rbt_t **const root, quic_rbt_t *const node);
static inline void __rbt_del_case4(quic_rbt_t **const root, quic_rbt_t *const node);
static inline void __rbt_del_case5(quic_rbt_t **const root, quic_rbt_t *const node);
static inline void __rbt_del_case6(quic_rbt_t **const root, quic_rbt_t *const node);
static inline quic_rbt_t *__sibling(const quic_rbt_t *const node);
static quic_rbt_t *__rbt_min(quic_rbt_t *node);
static inline void __rbt_replace(quic_rbt_t **const root, quic_rbt_t *const lf, quic_rbt_t *const rt);

quic_err_t quic_rbt_insert_inner(quic_rbt_t **const root, quic_rbt_t *const node, quic_rbt_comparer_t comparer) {
    quic_rbt_t *rb_p = quic_rbt_nil;
    quic_rbt_t **in = root;

    while (*in != quic_rbt_nil) {
        rb_p = *in;
        switch (comparer(node, rb_p)) {
        case QUIC_RBT_EQ:
            return quic_err_conflict;
        case QUIC_RBT_LS:
            in = &rb_p->rb_l;
            break;
        case QUIC_RBT_GT:
            in = &rb_p->rb_r;
            break;
        }
    }
    node->rb_p = rb_p;
    *in = node;

    __rbt_fixup(root, node);
    return quic_err_success;
}

quic_err_t quic_rbt_remove_inner(quic_rbt_t **const root, quic_rbt_t **const node) {
    quic_rbt_t *ref = *node;
    if (!quic_rbt_is_nil(ref->rb_l) && !quic_rbt_is_nil(ref->rb_r)) {
        quic_rbt_t *next = __rbt_min(ref->rb_r);
        quic_rbt_t tmp;
        __rbt_assign(root, &tmp, next);
        __rbt_assign(root, next, ref);
        __rbt_assign(root, ref, &tmp);
    }
    quic_rbt_t *child = quic_rbt_is_nil(ref->rb_l) ? ref->rb_r : ref->rb_l;
    if (ref->rb_color == QUIC_RBT_BLACK) {
        ref->rb_color = child->rb_color;
        __rbt_del_case1(root, ref);
    }
    __rbt_replace(root, ref, child);
    if (quic_rbt_is_nil(ref->rb_p) && !quic_rbt_is_nil(child)) {
        child->rb_color = QUIC_RBT_BLACK;
    }
    *node = ref;

    return quic_err_success;
}

quic_rbt_t *quic_rbt_find_inner(quic_rbt_t *const root, const void *const key, quic_rbt_key_comparer_t comparer) {
    quic_rbt_t *ret = root;
    while (ret != quic_rbt_nil) {
        switch (comparer(key, ret)) {
        case QUIC_RBT_EQ:
            return ret;
        case QUIC_RBT_LS:
            ret = ret->rb_l;
            break;
        case QUIC_RBT_GT:
            ret = ret->rb_r;
            break;
        }
    }

    return quic_rbt_nil;
}

typedef struct quic_rbt_uint64_key_s quic_rbt_uint64_key_t;
struct quic_rbt_uint64_key_s {
    QUIC_RBT_UINT64_FIELDS
};

int quic_rbt_uint64_key_comparer(const void *const key, const quic_rbt_t *const node) {
    uint64_t key_ref = *(uint64_t *) key;
    quic_rbt_uint64_key_t *node_ref = (quic_rbt_uint64_key_t *) node;

    if (key_ref == node_ref->key) {
        return QUIC_RBT_EQ;
    }
    else if (key_ref < node_ref->key) {
        return QUIC_RBT_LS;
    }
    else {
        return QUIC_RBT_GT;
    }
}

int quic_rbt_uint64_comparer(const quic_rbt_t *const lf, const quic_rbt_t *const rt) {
    quic_rbt_uint64_key_t *lf_ref = (quic_rbt_uint64_key_t *) lf;

    return quic_rbt_uint64_key_comparer(&lf_ref->key, rt);
}

static inline void __rbt_lr(quic_rbt_t **const root, quic_rbt_t *const node) {
    quic_rbt_t *child;

    child = node->rb_r;
    node->rb_r = child->rb_l;
    if (child->rb_l != quic_rbt_nil) {
        child->rb_l->rb_p = node;
    }
    if (!quic_rbt_is_nil(child)) {
        child->rb_p = node->rb_p;
    }
    if (node->rb_p == quic_rbt_nil) {
        *root = child;
    }
    else if (node == node->rb_p->rb_l) {
        node->rb_p->rb_l = child;
    }
    else {
        node->rb_p->rb_r = child;
    }
    if (!quic_rbt_is_nil(child)) {
        child->rb_l = node;
    }
    node->rb_p = child;
}

static inline void __rbt_rr(quic_rbt_t **const root, quic_rbt_t *const node) {
    quic_rbt_t *child;

    child = node->rb_l;
    node->rb_l = child->rb_r;
    if (child->rb_r != quic_rbt_nil) {
        child->rb_r->rb_p = node;
    }
    if (!quic_rbt_is_nil(child)) {
        child->rb_p = node->rb_p;
    }
    if (node->rb_p == quic_rbt_nil) {
        *root = child;
    }
    else if (node == node->rb_p->rb_l) {
        node->rb_p->rb_l = child;
    }
    else {
        node->rb_p->rb_r = child;
    }
    if (!quic_rbt_is_nil(child)) {
        child->rb_r = node;
    }
    node->rb_p = child;
}

static void __rbt_fixup(quic_rbt_t **const root, quic_rbt_t *node) {
    quic_rbt_t *uncle;

    while (node->rb_p->rb_color == QUIC_RBT_RED) {
        if (node->rb_p == node->rb_p->rb_p->rb_l) {
            uncle = node->rb_p->rb_p->rb_r;
            if (uncle->rb_color == QUIC_RBT_RED) {
                uncle->rb_color = QUIC_RBT_BLACK;
                node->rb_p->rb_color = QUIC_RBT_BLACK;
                node->rb_p->rb_p->rb_color = QUIC_RBT_RED;
                node = node->rb_p->rb_p;
            }
            else {
                if (node == node->rb_p->rb_r) {
                    node = node->rb_p;
                    __rbt_lr(root, node);
                }
                node->rb_p->rb_color = QUIC_RBT_BLACK;
                node->rb_p->rb_p->rb_color = QUIC_RBT_RED;
                __rbt_rr(root, node->rb_p->rb_p);
            }
        }
        else {
            uncle = node->rb_p->rb_p->rb_l;
            if (uncle->rb_color == QUIC_RBT_RED) {
                uncle->rb_color = QUIC_RBT_BLACK;
                node->rb_p->rb_color = QUIC_RBT_BLACK;
                node->rb_p->rb_p->rb_color = QUIC_RBT_RED;
                node = node->rb_p->rb_p;
            }
            else {
                if (node == node->rb_p->rb_l) {
                    node = node->rb_p;
                    __rbt_rr(root, node);
                }
                node->rb_p->rb_color = QUIC_RBT_BLACK;
                node->rb_p->rb_p->rb_color = QUIC_RBT_RED;
                __rbt_lr(root, node->rb_p->rb_p);
            }
        }
    }
    (*root)->rb_color = QUIC_RBT_BLACK;
}

static inline void __rbt_assign(quic_rbt_t **const root, quic_rbt_t *const target, quic_rbt_t *const ref) {
    target->rb_color = ref->rb_color;
    target->rb_l = ref->rb_l;
    target->rb_r = ref->rb_r;
    target->rb_p = ref->rb_p;

    if (quic_rbt_is_nil(ref->rb_p)) {
        *root = target;
    }
    else if (ref->rb_p->rb_l == ref) {
        ref->rb_p->rb_l = target;
    }
    else {
        ref->rb_p->rb_r = target;
    }

    if (!quic_rbt_is_nil(ref->rb_l)) {
        ref->rb_l->rb_p = target;
    }
    if (!quic_rbt_is_nil(ref->rb_r)) {
        ref->rb_r->rb_p = target;
    }
}

static inline void __rbt_del_case1(quic_rbt_t **const root, quic_rbt_t *const node) {
    if (!quic_rbt_is_nil(node->rb_p)) {
        __rbt_del_case2(root, node);
    }
}

static inline void __rbt_del_case2(quic_rbt_t **const root, quic_rbt_t *const node) {
    quic_rbt_t *sibling = __sibling(node);

    if (sibling->rb_color == QUIC_RBT_RED) {
        node->rb_p->rb_color = QUIC_RBT_RED;
        sibling->rb_color = QUIC_RBT_BLACK;
        if (node == node->rb_p->rb_l) {
            __rbt_lr(root, node->rb_p);
        }
        else {
            __rbt_rr(root, node->rb_p);
        }
    }
    __rbt_del_case3(root, node);
}

static inline void __rbt_del_case3(quic_rbt_t **const root, quic_rbt_t *const node) {
    quic_rbt_t *sibling = __sibling(node);

    if (node->rb_p->rb_color == QUIC_RBT_BLACK &&
        sibling->rb_color == QUIC_RBT_BLACK &&
        sibling->rb_l->rb_color == QUIC_RBT_BLACK &&
        sibling->rb_r->rb_color == QUIC_RBT_BLACK) {
        sibling->rb_color = QUIC_RBT_RED;
        __rbt_del_case1(root, node->rb_p);
    }
    else {
        __rbt_del_case4(root, node);
    }
}

static inline void __rbt_del_case4(quic_rbt_t **const root, quic_rbt_t *const node) {
    quic_rbt_t *sibling = __sibling(node);

    if (node->rb_p->rb_color == QUIC_RBT_RED &&
        sibling->rb_color == QUIC_RBT_BLACK &&
        sibling->rb_l->rb_color == QUIC_RBT_BLACK &&
        sibling->rb_r->rb_color == QUIC_RBT_BLACK) {
        sibling->rb_color = QUIC_RBT_RED;
        node->rb_p->rb_color = QUIC_RBT_BLACK;
    }
    else {
        __rbt_del_case5(root, node);
    }
}

static inline void __rbt_del_case5(quic_rbt_t **const root, quic_rbt_t *const node) {
    quic_rbt_t *sibling = __sibling(node);

    if (node->rb_p->rb_l == node &&
        sibling->rb_color == QUIC_RBT_BLACK &&
        sibling->rb_l->rb_color == QUIC_RBT_RED &&
        sibling->rb_r->rb_color == QUIC_RBT_BLACK) {
        sibling->rb_color = QUIC_RBT_RED;
        sibling->rb_l->rb_color = QUIC_RBT_BLACK;
        __rbt_rr(root, sibling);
    }
    else if (node->rb_p->rb_r == node &&
             sibling->rb_color == QUIC_RBT_BLACK &&
             sibling->rb_r->rb_color == QUIC_RBT_RED &&
             sibling->rb_l->rb_color == QUIC_RBT_BLACK) {
        sibling->rb_color = QUIC_RBT_RED;
        sibling->rb_r->rb_color = QUIC_RBT_BLACK;
        __rbt_lr(root, sibling);
    }
    __rbt_del_case6(root, node);
}

static inline void __rbt_del_case6(quic_rbt_t **const root, quic_rbt_t *const node) {
    quic_rbt_t *sibling = __sibling(node);

    sibling->rb_color = node->rb_p->rb_color;
    node->rb_p->rb_color = QUIC_RBT_BLACK;
    if (node == node->rb_p->rb_l) {
        sibling->rb_r->rb_color = QUIC_RBT_BLACK;
        __rbt_lr(root, node->rb_p);
    }
    else {
        sibling->rb_l->rb_color = QUIC_RBT_BLACK;
        __rbt_rr(root, node->rb_p);
    }
}

static inline quic_rbt_t *__sibling(const quic_rbt_t *const node) {
    if (node->rb_p->rb_l == node) {
        return node->rb_p->rb_r;
    }
    else {
        return node->rb_p->rb_l;
    }
}

static quic_rbt_t *__rbt_min(quic_rbt_t *node) {
    if (quic_rbt_is_nil(node)) {
        return quic_rbt_nil;
    }
    while (!quic_rbt_is_nil(node->rb_l)) {
        node = node->rb_l;
    }
    return node;
}

static inline void __rbt_replace(quic_rbt_t **const root, quic_rbt_t *const lf, quic_rbt_t *const rt) {
    if (lf == *root) {
        *root = rt;
    }
    else if (lf == lf->rb_p->rb_l) {
        lf->rb_p->rb_l = rt;
    }
    else {
        lf->rb_p->rb_r = rt;
    }
    if (!quic_rbt_is_nil(rt)) {
        rt->rb_p = lf->rb_p;
    }
}
