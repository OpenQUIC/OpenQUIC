/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "sorter.h"
#include <string.h>
#include <malloc.h>

static quic_err_t quic_sorter_write_cluster(quic_sorter_t *const sorter, uint64_t off, uint64_t len, void *data);
static quic_err_t quic_sorter_read_cluster(quic_sorter_t *const sorter, uint64_t len, void *data);

quic_err_t quic_sorter_init(quic_sorter_t *const sorter) {
    quic_rbt_tree_init(sorter->clusters);
    quic_link_init(&sorter->gaps);

    quic_sorter_gap_t *gap = malloc(sizeof(quic_sorter_gap_t));
    if (gap == NULL) {
        return quic_err_internal_error;
    }
    quic_link_init(gap);
    gap->off = 0;
    gap->len = QUIC_SORTER_MAX_SIZE;
    quic_link_insert_after(&sorter->gaps, gap);

    sorter->avail_size = 0;
    sorter->readed_size = 0;

    return quic_err_success;
}

quic_err_t quic_sorter_write(quic_sorter_t *const sorter, uint64_t off, uint64_t len, void *data) {
    quic_sorter_gap_t *start_gap = NULL;
    quic_sorter_gap_t *end_gap = NULL;
    uint64_t end = off + len - 1;
    uint64_t start = off;

    quic_link_foreach(start_gap, &sorter->gaps) {
        if (end < quic_sorter_gap_start(start_gap)) {
            return quic_err_success;
        }

        if (start <= quic_sorter_gap_end(start_gap) && quic_sorter_gap_start(start_gap) <= end) {
            break;
        }
    }
    if (start < quic_sorter_gap_start(start_gap)) {
        start = quic_sorter_gap_start(start_gap);
    }

    end_gap = start_gap;
    while (end > quic_sorter_gap_end(end_gap)) {
        quic_sorter_gap_t *next_end_gap = quic_link_next(end_gap);
        if (end < quic_sorter_gap_start(next_end_gap)) {
            break;
        }

        if (end_gap != start_gap) {
            quic_link_remove(end_gap);
            free(end_gap);
        }
        end_gap = next_end_gap;
    }
    if (end > quic_sorter_gap_end(end_gap)) {
        end = quic_sorter_gap_end(end_gap);
    }

    if (start == quic_sorter_gap_start(start_gap)) {
        if (end >= quic_sorter_gap_end(start_gap)) {
            quic_link_remove(start_gap);
            free(start_gap);
        }

        if (end < quic_sorter_gap_end(end_gap)) {
            end_gap->len = quic_sorter_gap_end(end_gap) - end;
            quic_sorter_gap_start(end_gap) = end + 1;
        }

    }
    else if (end == quic_sorter_gap_end(end_gap)) {
        start_gap->len = start - 1 - quic_sorter_gap_start(start_gap) + 1;
    }
    else if (start_gap == end_gap) {
        quic_sorter_gap_t *gap = malloc(sizeof(quic_sorter_gap_t));
        if (gap == NULL) {
            return quic_err_internal_error;
        }
        quic_sorter_gap_start(gap) = end + 1;
        gap->len = quic_sorter_gap_end(start_gap) - quic_sorter_gap_start(gap) + 1;
        quic_link_insert_after(start_gap, gap);

        start_gap->len = start - 1 - quic_sorter_gap_start(start_gap) + 1;
    }
    else {
        start_gap->len = start - 1 - quic_sorter_gap_start(start_gap) + 1;
        quic_sorter_gap_start(end_gap) = end + 1;
    }

    sorter->avail_size = ((quic_sorter_gap_t *) quic_link_next(&sorter->gaps))->off;

    return quic_sorter_write_cluster(sorter, start, (end - start + 1), data + (start - off));
}

uint64_t quic_sorter_read(quic_sorter_t *const sorter, uint64_t len, void *data) {
    if (quic_sorter_readable(sorter) < len) {
        len = quic_sorter_readable(sorter);
    }
    if (quic_sorter_read_cluster(sorter, len, data) != quic_err_success) {
        return 0;
    }

    sorter->readed_size += len;
    return len;
}

static quic_err_t quic_sorter_write_cluster(quic_sorter_t *const sorter, uint64_t off, uint64_t len, void *data) {
    while (len != 0) {
        uint64_t cluster_key = off / QUIC_SORTER_CLUSTER_SIZE;
        uint64_t cluster_off = off % QUIC_SORTER_CLUSTER_SIZE;
        uint64_t cluster_len = QUIC_SORTER_CLUSTER_SIZE - cluster_off;
        if (len < cluster_len) {
            cluster_len = len;
        }

        quic_sorter_cluster_t *cluster = quic_sorter_cluster_find(sorter->clusters, &cluster_key);
        if (quic_rbt_is_nil(cluster)) {
            if ((cluster = malloc(sizeof(quic_sorter_cluster_t) + QUIC_SORTER_CLUSTER_SIZE)) == NULL) {
                return quic_err_internal_error;
            }
            quic_rbt_init(cluster);
            cluster->key = cluster_key;
            quic_sorter_cluster_insert(&sorter->clusters, cluster);
        }
        memcpy(cluster->data + cluster_off, data, cluster_len);

        off += cluster_len;
        len -= cluster_len;
        data += cluster_len;
    }

    return quic_err_success;
}

static quic_err_t quic_sorter_read_cluster(quic_sorter_t *const sorter, uint64_t len, void *data) {
    uint64_t off = sorter->readed_size == 0 ? 0 : sorter->readed_size - 1;

    while (len != 0) {
        uint64_t cluster_key = off / QUIC_SORTER_CLUSTER_SIZE;
        uint64_t cluster_off = off % QUIC_SORTER_CLUSTER_SIZE;
        uint64_t cluster_len = QUIC_SORTER_CLUSTER_SIZE - cluster_off;
        if (len < cluster_len) {
            cluster_len = len;
        }
        quic_sorter_cluster_t *cluster = quic_sorter_cluster_find(sorter->clusters, &cluster_key);
        if (quic_rbt_is_nil(cluster)) {
            return quic_err_internal_error;
        }

        memcpy(data, cluster->data + cluster_off, cluster_len);

        off += cluster_len;
        len -= cluster_len;
        data += cluster_len;

        if (cluster_key != off / QUIC_SORTER_CLUSTER_SIZE) {
            quic_rbt_remove(&sorter->clusters, &cluster);
            free(cluster);
        }
    }

    return quic_err_success;
}
