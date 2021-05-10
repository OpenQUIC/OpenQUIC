/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_RBT_EXTEND_H__
#define __OPENQUIC_RBT_EXTEND_H__

#include "utils/buf.h"
#include "utils/addr.h"
#include "liteco.h"

#ifdef liteco_rbt_find
#undef liteco_rbt_find
#endif

#ifdef liteco_rbt_insert
#undef liteco_rbt_insert
#endif

#define QUIC_RBT_KEY_STRING_FIELDS \
    LITECO_RBT_FIELDS              \
    quic_buf_t key;                \

typedef struct quic_string_rbt_s quic_string_rbt_t;
struct quic_string_rbt_s { QUIC_RBT_KEY_STRING_FIELDS };

liteco_rbt_cmp_result_t quic_rbt_string_cmp_cb(const void *const key, const liteco_rbt_t *const node);

#define quic_rbt_string_insert(root, node) \
    liteco_rbt_insert_impl((liteco_rbt_t **) root, (liteco_rbt_t *) node, quic_rbt_string_cmp_cb, offsetof(quic_string_rbt_t, key))
#define quic_rbt_string_find(root, finded_key) \
    liteco_rbt_find_impl((liteco_rbt_t *) root, finded_key, quic_rbt_string_cmp_cb)

#define QUIC_RBT_KEY_ADDR_FIELDS \
    LITECO_RBT_FIELDS            \
    liteco_addr_t key;           \

typedef struct quic_addr_rbt_s quic_addr_rbt_t;
struct quic_addr_rbt_s { QUIC_RBT_KEY_ADDR_FIELDS };

liteco_rbt_cmp_result_t quic_rbt_addr_cmp_cb(const void *const key, const liteco_rbt_t *const node);

#define quic_rbt_addr_insert(root, node) \
    liteco_rbt_insert_impl((liteco_rbt_t **) root, (liteco_rbt_t *) node, quic_rbt_addr_cmp_cb, offsetof(quic_addr_rbt_t, key))
#define quic_rbt_addr_find(root, finded_key) \
    liteco_rbt_find_impl((liteco_rbt_t *) root, finded_key, quic_rbt_addr_cmp_cb)

#define QUIC_RBT_KEY_PATH_FIELDS \
    LITECO_RBT_FIELDS            \
    quic_path_t key;             \

typedef struct quic_path_rbt_s quic_path_rbt_t;
struct quic_path_rbt_s { QUIC_RBT_KEY_PATH_FIELDS };

liteco_rbt_cmp_result_t quic_rbt_path_cmp_cb(const void *const key, const liteco_rbt_t *const node);

#define quic_rbt_path_insert(root, node) \
    liteco_rbt_insert_impl((liteco_rbt_t **) root, (liteco_rbt_t *) node, quic_rbt_path_cmp_cb, offsetof(quic_path_rbt_t, key))
#define quic_rbt_path_find(root, finded_key) \
    liteco_rbt_find_impl((liteco_rbt_t *) root, finded_key, quic_rbt_path_cmp_cb)

#define liteco_rbt_insert(root, node) (_Generic((*root)->key, \
    uint64_t:    liteco_rbt_uint64_insert(root, node),        \
    int:         liteco_rbt_int_insert(root, node),           \
    quic_buf_t:  quic_rbt_string_insert(root, node),          \
    liteco_addr_t: quic_rbt_addr_insert(root, node),          \
    quic_path_t: quic_rbt_path_insert(root, node)             \
))

#define liteco_rbt_find(root, key) (typeof(root))_Generic(*key, \
    uint64_t:    liteco_rbt_uint64_find(root, key),             \
    int:         liteco_rbt_int_find(root, key),                \
    quic_buf_t:  quic_rbt_string_find(root, key),               \
    liteco_addr_t: quic_rbt_addr_find(root, key),               \
    quic_path_t: quic_rbt_path_find(root, key)                  \
)

#endif
