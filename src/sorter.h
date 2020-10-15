/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_SORTER_H__
#define __OPENQUIC_SORTER_H__

#include "utils/link.h"
#include "utils/errno.h"
#include "utils/rbt.h"
#include <stdint.h>

#ifndef QUIC_SORTER_CLUSTER_SIZE
#define QUIC_SORTER_CLUSTER_SIZE 4096
#endif

#ifndef QUIC_SORTER_MAX_SIZE
#define QUIC_SORTER_MAX_SIZE ((1UL << 63) - 1)
#endif

typedef struct quic_sorter_cluster_s quic_sorter_cluster_t;
struct quic_sorter_cluster_s {
    QUIC_RBT_UINT64_FIELDS

    uint8_t data[0];
};

#define quic_sorter_cluster_insert(clusters, cluster)                                                   \
    quic_rbt_insert((clusters), (cluster), quic_rbt_uint64_comparer)
#define quic_sorter_cluster_find(clusters, key)                                                         \
    ((quic_sorter_cluster_t *) quic_rbt_find((clusters), (key), quic_rbt_uint64_key_comparer))

typedef struct quic_sorter_gap_s quic_sorter_gap_t;
struct quic_sorter_gap_s {
    OPENQUIC_LINK_FIELDS

    uint64_t off;
    uint64_t len;
};

#define quic_sorter_gap_start(gap)  \
    ((gap)->off)
#define quic_sorter_gap_end(gap)    \
    ((gap)->off + (gap)->len - 1)

typedef struct quic_sorter_s quic_sorter_t;
struct quic_sorter_s {
    quic_link_t gaps;
    quic_sorter_cluster_t *clusters;

    uint64_t avail_size;
    uint64_t readed_size;
};

quic_err_t quic_sorter_init(quic_sorter_t *const sorter);
quic_err_t quic_sorter_destory(quic_sorter_t *const sorter);
quic_err_t quic_sorter_write(quic_sorter_t *const sorter, uint64_t off, uint64_t len, void *data);
uint64_t quic_sorter_read(quic_sorter_t *const sorter, uint64_t len, void *data);

#define quic_sorter_readable(sorter)                \
    ((sorter)->avail_size - (sorter)->readed_size)

#endif
