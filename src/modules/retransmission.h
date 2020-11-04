/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_RETRANSMISSION_H__
#define __OPENQUIC_RETRANSMISSION_H__

#include "module.h"
#include "session.h"
#include "format/frame.h"
#include "utils/rbt.h"
#include "utils/link.h"
#include "recovery/rtt.h"

typedef struct quic_sent_packet_rbt_s quic_sent_packet_rbt_t;
struct quic_sent_packet_rbt_s {
    QUIC_RBT_UINT64_FIELDS

    uint64_t largest_ack;
    uint64_t sent_time;
    uint32_t pkt_len;
    bool included_unacked;
    quic_link_t frames;
};

#define quic_sent_pkts_insert(pkts, pkt) \
    quic_rbt_insert((pkts), (pkt), quic_rbt_uint64_comparer)

#define quic_sent_pkts_find(pkts, key) \
    ((quic_sent_packet_rbt_t *) quic_rbt_find((pkts), (key), quic_rbt_uint64_key_comparer))

typedef struct quic_retransmission_module_s quic_retransmission_module_t;
struct quic_retransmission_module_s {
    QUIC_MODULE_FIELDS

    quic_sent_packet_rbt_t *sent_mem;
    uint32_t sent_pkt_count;
    uint32_t unacked_len;

    uint64_t max_delay;

    uint64_t loss_time;
    uint64_t last_sent_ack_time;

    uint64_t alarm;

    quic_link_t acked_mem_queue;
};

extern quic_module_t quic_initial_retransmission_module;
extern quic_module_t quic_handshake_retransmission_module;
extern quic_module_t quic_app_retransmission_module;

quic_err_t quic_retransmission_module_find_newly_acked(quic_retransmission_module_t *const module, const quic_frame_ack_t *const frame);
quic_err_t quic_retransmission_module_find_newly_lost(quic_retransmission_module_t *const module);

static inline quic_err_t quic_retransmission_update_alarm(quic_retransmission_module_t *const module) {
    quic_session_t *const session = quic_module_of_session(module);
    module->alarm = module->unacked_len && module->loss_time
        ? module->loss_time
        : module->last_sent_ack_time + quic_rtt_pto(&session->rtt, module->max_delay);
    return quic_err_success;
}

static inline quic_err_t quic_retransmission_sent_mem_push(quic_retransmission_module_t *const module, quic_sent_packet_rbt_t *const pkt) {
    quic_sent_pkts_insert(&module->sent_mem, pkt);
    module->sent_pkt_count++;

    if (pkt->included_unacked) {
        module->last_sent_ack_time = pkt->sent_time;
        module->unacked_len += pkt->pkt_len;
    }

    quic_retransmission_update_alarm(module);

    return quic_err_success;
}

static inline quic_err_t quic_retransmission_sent_mem_drop(quic_retransmission_module_t *const module, quic_sent_packet_rbt_t *pkt, const bool acked) {
    quic_rbt_remove(&module->sent_mem, &pkt);
    while (!quic_link_empty(&pkt->frames)) {
        quic_frame_t *frame = (quic_frame_t *) quic_link_next(&pkt->frames);
        quic_link_remove(frame);

        if (acked) {
            quic_frame_on_acked(frame);
        }

        free(frame);
    }
    free(pkt);

    return quic_err_success;
}

static inline quic_err_t quic_retransmission_process_newly_acked(quic_retransmission_module_t *const module, quic_sent_packet_rbt_t *const pkt) {
    quic_rbt_foreach_qnode_t *node = malloc(sizeof(quic_rbt_foreach_qnode_t));
    if (node == NULL) {
        return quic_err_internal_error;
    }
    node->node = (quic_rbt_t *) pkt;
    quic_link_insert_after(&module->acked_mem_queue, node);

    if (pkt->included_unacked) {
        module->unacked_len -= pkt->pkt_len;

        // TODO congestion on packet acked and detect lost packet alerm
    }

    return quic_err_success;
}

#endif
