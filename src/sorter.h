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
#include <stdint.h>

#define QUIC_SORTER_CLUSTER_SIZE 4096

#define QUIC_SORTER_MAX_SIZE ((1UL << 63) - 1)

typedef struct quic_sorter_cluster_s quic_sorter_cluster_t;
struct quic_sorter_cluster_s {
    OPENQUIC_LINK_FIELDS

    uint64_t off;
    uint8_t data[0];
};

typedef struct quic_sorter_gap_s quic_sorter_gap_t;
struct quic_sorter_gap_s {
    OPENQUIC_LINK_FIELDS

    uint64_t off;
    uint64_t len;

    quic_sorter_cluster_t *cluster;
};

#define quic_sorter_gap_start(gap)  \
    ((gap)->off)
#define quic_sorter_gap_end(gap)    \
    ((gap)->off + (gap)->len - 1)

typedef struct quic_sorter_s quic_sorter_t;
struct quic_sorter_s {
    quic_link_t gaps;
    quic_link_t clusters;
};

quic_err_t quic_sorter_init(quic_sorter_t *const sorter);
quic_err_t quic_sorter_put(quic_sorter_t *const sorter, const uint64_t off, const uint64_t len, void *const data);

#endif
