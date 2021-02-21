/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_CONNID_GEN_H__
#define __OPENQUIC_CONNID_GEN_H__

#include "session.h"
#include "module.h"
#include "utils/rbt.h"

typedef struct quic_connid_gened_s quic_connid_gened_t;
struct quic_connid_gened_s {
    QUIC_RBT_UINT64_FIELDS

    quic_buf_t connid;
};

#define quic_connid_gened_insert(connids, connid) \
    quic_rbt_insert((connids), (connid), quic_rbt_uint64_comparer)

#define quic_connid_gened_find(connids, key) \
    ((quic_connid_gened_t *) quic_rbt_find((connids), (key), quic_rbt_uint64_key_comparer))

typedef struct quic_connid_gen_module_s quic_connid_gen_module_t;
struct quic_connid_gen_module_s {
    QUIC_MODULE_FIELDS

    int connid_len;
    uint64_t src_hseq;
    uint64_t dst_hretire;

    quic_connid_gened_t *srcs;
    quic_connid_gened_t *dsts;

    uint64_t dst_active;

    bool (*new_connid) (quic_session_t *const, const quic_buf_t);
    void (*retire_connid) (quic_session_t *const, const quic_buf_t);
};

extern quic_module_t quic_connid_gen_module;

quic_err_t quic_connid_gen_issue_src(quic_connid_gen_module_t *const module);
quic_err_t quic_connid_gen_retire_all(quic_connid_gen_module_t *const module);
quic_err_t quic_connid_gen_foreach_src(quic_connid_gen_module_t *const module, void (*cb) (const quic_buf_t connid, void *args), void *const args);

#endif
