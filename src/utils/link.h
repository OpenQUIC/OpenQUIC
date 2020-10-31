/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_LINK_H__
#define __OPENQUIC_LINK_H__

#define QUIC_LINK_FIELDS    \
    quic_link_t *next;          \
    quic_link_t *prev;

typedef struct quic_link_s quic_link_t;
struct quic_link_s {
    QUIC_LINK_FIELDS
};

#define quic_link_init(link) {              \
    (link)->next = (quic_link_t *) (link);  \
    (link)->prev = (quic_link_t *) (link);  \
}

#define quic_link_empty(link) \
    ((link)->next == (link))

#define quic_link_next(node) \
    ((typeof(node)) (node)->next)

#define quic_link_prev(node) \
    ((typeof(node)) (node)->prev)

#define quic_link_insert_after(link, node) {     \
    (node)->next = (link)->next;                 \
    (node)->prev = (quic_link_t *) (link);       \
    (link)->next->prev = (quic_link_t *) (node); \
    (link)->next = (quic_link_t *) (node);       \
}

#define quic_link_insert_before(link, node) {    \
    (node)->prev = (link)->prev;                 \
    (node)->next = (quic_link_t *) (link);       \
    (link)->prev->next = (quic_link_t *) (node); \
    (link)->prev = (quic_link_t *) (node);       \
}

#define quic_link_foreach(node, link)                      \
    for ((node) = (typeof(node)) (link)->next;             \
         (quic_link_t *) (node) != (quic_link_t *) (link); \
         (node) = (typeof(node)) (node)->next)

#define quic_link_rforeach(node, link)                     \
    for ((node) = (typeof(node)) (link)->prev;             \
         (quic_link_t *) (node) != (quic_link_t *) (link); \
         (node) = (typeof(node)) (node)->prev)

#define quic_link_remove(node) {        \
    (node)->next->prev = (node)->prev;  \
    (node)->prev->next = (node)->next;  \
}

#endif
