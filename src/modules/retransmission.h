/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_RETRANSMISSION_H__
#define __OPENQUIC_RETRANSMISSION_H__

#include "format/frame.h"
#include "utils/rbt.h"
#include "utils/link.h"
#include "rtt.h"
#include "modules/congestion.h"
#include "module.h"
#include "session.h"

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
    uint64_t largest_ack;

    quic_link_t droped_queue;

    uint64_t alarm;

    quic_link_t retransmission_queue;
};

extern quic_module_t quic_initial_retransmission_module;
extern quic_module_t quic_handshake_retransmission_module;
extern quic_module_t quic_app_retransmission_module;

quic_err_t quic_retransmission_module_find_newly_acked(quic_retransmission_module_t *const module, const quic_frame_ack_t *const frame);
quic_err_t quic_retransmission_module_find_newly_lost(quic_retransmission_module_t *const module);
uint64_t quic_retransmission_append_frame(quic_link_t *const frames, const uint64_t capa, quic_retransmission_module_t *const module);

static inline quic_err_t quic_retransmission_module_retransmission(quic_retransmission_module_t *const module, quic_frame_t *const frame) {
    quic_link_insert_before(&module->retransmission_queue, frame);
    return quic_err_success;
}

static inline quic_err_t quic_retransmission_update_alarm(quic_retransmission_module_t *const module) {
    quic_session_t *const session = quic_module_of_session(module);

    if (!module->unacked_len) {
        return quic_err_success;
    }

    module->alarm = module->loss_time
        ? module->loss_time
        : module->last_sent_ack_time + quic_rtt_pto(&session->rtt, module->max_delay);

    quic_session_update_loop_deadline(session, module->alarm);

    return quic_err_success;
}

static inline quic_err_t quic_retransmission_sent_mem_push(quic_retransmission_module_t *const module, quic_sent_packet_rbt_t *const pkt) {
    quic_sent_pkts_insert(&module->sent_mem, pkt);
    module->sent_pkt_count++;

    if (pkt->included_unacked) {
        module->last_sent_ack_time = pkt->sent_time;
        module->unacked_len += pkt->pkt_len;

        quic_retransmission_update_alarm(module);
    }

    return quic_err_success;
}

static inline quic_err_t quic_retransmission_on_lost(quic_retransmission_module_t *const module) {
    if (module->loss_time) {
        quic_retransmission_module_find_newly_lost(module);
    }
    return quic_err_success;
}

#define quic_retransmission_sent_mem_drop_acked 0x01
#define quic_retransmission_sent_mem_drop_lost 0x02

static inline quic_err_t quic_retransmission_sent_mem_drop(quic_retransmission_module_t *const module, quic_sent_packet_rbt_t *pkt, const uint8_t process_type) {
    quic_rbt_remove(&module->sent_mem, &pkt);

    while (!quic_link_empty(&pkt->frames)) {
        quic_frame_t *frame = (quic_frame_t *) quic_link_next(&pkt->frames);
        quic_link_remove(frame);

        switch (process_type) {
        case quic_retransmission_sent_mem_drop_acked:
            if (!frame->on_acked) {
                free(frame);
            }
            quic_frame_on_acked(frame);
            break;

        case quic_retransmission_sent_mem_drop_lost:
            if (!frame->on_lost) {
                free(frame);
            }
            quic_frame_on_lost(frame);
            break;

        default:
            free(frame);
        }
    }
    free(pkt);

    return quic_err_success;
}

static inline quic_err_t quic_retransmission_append_to_drop_queue(quic_retransmission_module_t *const module, quic_sent_packet_rbt_t *const pkt) {
    quic_rbt_foreach_qnode_t *node = malloc(sizeof(quic_rbt_foreach_qnode_t));
    if (node == NULL) {
        return quic_err_internal_error;
    }
    quic_link_init(node);

    node->node = (quic_rbt_t *) pkt;
    quic_link_insert_after(&module->droped_queue, node);

    return quic_err_success;
}

static inline quic_err_t quic_retransmission_process_newly_acked(quic_retransmission_module_t *const module, quic_sent_packet_rbt_t *const pkt, const uint64_t event_time) {
    quic_session_t *const session = quic_module_of_session(module);
    quic_congestion_module_t *const c_module = quic_session_module(quic_congestion_module_t, session, quic_congestion_module);

    quic_retransmission_append_to_drop_queue(module, pkt);
    module->sent_pkt_count--;

    if (pkt->included_unacked) {
        module->unacked_len -= pkt->pkt_len;
        quic_congestion_on_acked(c_module, pkt->key, pkt->pkt_len, module->unacked_len, event_time);
    }

    return quic_err_success;
}

static inline quic_err_t quic_retransmission_process_newly_lost(quic_retransmission_module_t *const module, quic_sent_packet_rbt_t *const pkt) {
    quic_session_t *const session = quic_module_of_session(module);
    quic_congestion_module_t *const c_module = quic_session_module(quic_congestion_module_t, session, quic_congestion_module);

    quic_retransmission_append_to_drop_queue(module, pkt);
    module->sent_pkt_count--;

    if (pkt->included_unacked) {
        module->unacked_len -= pkt->pkt_len;
        quic_congestion_on_lost(c_module, pkt->key, pkt->pkt_len, module->unacked_len);
    }

    return quic_err_success;
}

#endif
