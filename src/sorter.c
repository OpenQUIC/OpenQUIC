/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "platform/platform.h"
#include "sorter.h"
#include <string.h>

static quic_err_t quic_sorter_write_cluster(quic_sorter_t *const sorter, uint64_t off, uint64_t len, const void *data);
static uint64_t quic_sorter_read_cluster(quic_sorter_t *const sorter, bool consume, uint64_t len, void *data);

quic_err_t quic_sorter_init(quic_sorter_t *const sorter) {
    liteco_rbt_init(sorter->clusters);
    liteco_link_init(&sorter->gaps);

    quic_sorter_gap_t *gap = malloc(sizeof(quic_sorter_gap_t));
    if (gap == NULL) {
        return quic_err_internal_error;
    }
    liteco_link_init(gap);
    gap->off = 0;
    gap->len = QUIC_SORTER_MAX_SIZE;
    liteco_link_insert_after(&sorter->gaps, gap);

    sorter->avail_size = 0;
    sorter->readed_size = 0;

    return quic_err_success;
}

quic_err_t quic_sorter_destory(quic_sorter_t *const sorter) {
    while (!liteco_link_empty(&sorter->gaps)) {
        quic_sorter_gap_t *gap = (quic_sorter_gap_t *) liteco_link_next(&sorter->gaps);
        liteco_link_remove(gap);
        free(gap);
    }

    while (liteco_rbt_is_not_nil(sorter->clusters)) {
        quic_sorter_cluster_t *cluster = sorter->clusters;
        liteco_rbt_remove(&sorter->clusters, &cluster);
        free(cluster);
    }

    return quic_err_success;
}

quic_err_t quic_sorter_write(quic_sorter_t *const sorter, uint64_t off, uint64_t len, const void *data) {
    if (len == 0) {
        return quic_err_success;
    }

    quic_sorter_gap_t *start_gap = NULL;
    quic_sorter_gap_t *end_gap = NULL;
    uint64_t end = off + len - 1;
    uint64_t start = off;

    liteco_link_foreach(start_gap, &sorter->gaps) {
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
        quic_sorter_gap_t *next_end_gap = liteco_link_next(end_gap);
        if (end < quic_sorter_gap_start(next_end_gap)) {
            break;
        }

        if (end_gap != start_gap) {
            liteco_link_remove(end_gap);
            free(end_gap);
        }
        end_gap = next_end_gap;
    }
    if (end > quic_sorter_gap_end(end_gap)) {
        end = quic_sorter_gap_end(end_gap);
    }

    if (start == quic_sorter_gap_start(start_gap)) {
        if (end >= quic_sorter_gap_end(start_gap)) {
            liteco_link_remove(start_gap);
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
        liteco_link_insert_after(start_gap, gap);

        start_gap->len = start - 1 - quic_sorter_gap_start(start_gap) + 1;
    }
    else {
        start_gap->len = start - 1 - quic_sorter_gap_start(start_gap) + 1;
        quic_sorter_gap_start(end_gap) = end + 1;
    }

    sorter->avail_size = ((quic_sorter_gap_t *) liteco_link_next(&sorter->gaps))->off;

    return quic_sorter_write_cluster(sorter, start, (end - start + 1), data + (start - off));
}

uint64_t quic_sorter_read(quic_sorter_t *const sorter, uint64_t len, void *data) {
    if (quic_sorter_readable(sorter) < len) {
        len = quic_sorter_readable(sorter);
    }
    uint64_t readed = quic_sorter_read_cluster(sorter, true, len, data);

    sorter->readed_size += readed;
    return readed;
}

uint64_t quic_sorter_peek(quic_sorter_t *const sorter, uint64_t len, void *data) {
    if (quic_sorter_readable(sorter) < len) {
        len = quic_sorter_readable(sorter);
    }

    return quic_sorter_read_cluster(sorter, false, len, data);
}

static quic_err_t quic_sorter_write_cluster(quic_sorter_t *const sorter, uint64_t off, uint64_t len, const void *data) {
    while (len != 0) {
        uint64_t cluster_key = off / QUIC_SORTER_CLUSTER_SIZE;
        uint64_t cluster_off = off % QUIC_SORTER_CLUSTER_SIZE;
        uint64_t cluster_len = QUIC_SORTER_CLUSTER_SIZE - cluster_off;
        if (len < cluster_len) {
            cluster_len = len;
        }

        quic_sorter_cluster_t *cluster = liteco_rbt_find(sorter->clusters, &cluster_key);
        if (liteco_rbt_is_nil(cluster)) {
            if ((cluster = malloc(sizeof(quic_sorter_cluster_t) + QUIC_SORTER_CLUSTER_SIZE)) == NULL) {
                return quic_err_internal_error;
            }
            liteco_rbt_node_init(cluster);
            cluster->key = cluster_key;
            liteco_rbt_insert(&sorter->clusters, cluster);
        }
        memcpy(cluster->data + cluster_off, data, cluster_len);

        off += cluster_len;
        len -= cluster_len;
        data += cluster_len;
    }

    return quic_err_success;
}

static uint64_t quic_sorter_read_cluster(quic_sorter_t *const sorter, bool consume, uint64_t len, void *data) {
    uint64_t off = sorter->readed_size;
    uint64_t readed = 0;

    while (len != 0) {
        uint64_t cluster_key = off / QUIC_SORTER_CLUSTER_SIZE;
        uint64_t cluster_off = off % QUIC_SORTER_CLUSTER_SIZE;
        uint64_t cluster_len = QUIC_SORTER_CLUSTER_SIZE - cluster_off;
        if (len < cluster_len) {
            cluster_len = len;
        }
        quic_sorter_cluster_t *cluster = liteco_rbt_find(sorter->clusters, &cluster_key);
        if (liteco_rbt_is_nil(cluster)) {
            return readed;
        }
        memcpy(data, cluster->data + cluster_off, cluster_len);

        off += cluster_len;
        len -= cluster_len;
        data += cluster_len;
        readed += cluster_len;

        if (consume && cluster_key != off / QUIC_SORTER_CLUSTER_SIZE) {
            liteco_rbt_remove(&sorter->clusters, &cluster);
            free(cluster);
        }
    }

    return readed;
}

