/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_SORTER_H__
#define __OPENQUIC_SORTER_H__

#include "platform/platform.h"
#include "utils/errno.h"
#include "liteco.h"
#include <stdint.h>
#include <pthread.h>

#ifndef QUIC_SORTER_CLUSTER_SIZE
#define QUIC_SORTER_CLUSTER_SIZE 4096
#endif

#ifndef QUIC_SORTER_MAX_SIZE
#define QUIC_SORTER_MAX_SIZE ((1UL << 63) - 1)
#endif

typedef struct quic_sorter_cluster_s quic_sorter_cluster_t;
struct quic_sorter_cluster_s {
    LITECO_RBT_KEY_UINT64_FIELDS

    uint8_t data[0];
};

typedef struct quic_sorter_gap_s quic_sorter_gap_t;
struct quic_sorter_gap_s {
    LITECO_LINKNODE_BASE

    uint64_t off;
    uint64_t len;
};

#define quic_sorter_gap_start(gap)  \
    ((gap)->off)
#define quic_sorter_gap_end(gap)    \
    ((gap)->off + (gap)->len - 1)

typedef struct quic_sorter_s quic_sorter_t;
struct quic_sorter_s {
    liteco_linknode_t gaps;
    quic_sorter_cluster_t *clusters;

    uint64_t avail_size;
    uint64_t readed_size;
};

quic_err_t quic_sorter_init(quic_sorter_t *const sorter);
quic_err_t quic_sorter_destory(quic_sorter_t *const sorter);
quic_err_t quic_sorter_write(quic_sorter_t *const sorter, uint64_t off, uint64_t len, const void *data);
uint64_t quic_sorter_read(quic_sorter_t *const sorter, uint64_t len, void *data);
uint64_t quic_sorter_peek(quic_sorter_t *const sorter, uint64_t len, void *data);

__quic_header_inline quic_err_t quic_sorter_append(quic_sorter_t *const sorter, uint64_t len, const void *data) {
    return quic_sorter_write(sorter, sorter->avail_size, len, data);
}

#define quic_sorter_readable(sorter) \
    ((sorter)->avail_size - (sorter)->readed_size)

__quic_header_inline bool quic_sorter_empty(quic_sorter_t *const sorter) {
    return quic_sorter_readable(sorter) == 0;
}

#endif
