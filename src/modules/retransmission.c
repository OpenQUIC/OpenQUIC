/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "modules/retransmission.h"
#include "format/header.h"
#include "session.h"

static quic_err_t quic_retransmission_module_init(void *const module);

quic_err_t quic_retransmission_module_find_newly_acked(quic_retransmission_module_t *const module, const quic_frame_ack_t *const frame) {
    quic_sent_packet_rbt_t *pkt = NULL;

    quic_link_init(&module->del_mem_queue);

    {
        quic_rbt_foreach(pkt, module->sent_mem) {
            uint64_t end = frame->largest_ack;
            uint64_t start = end - frame->first_range;

            bool lost_flag = frame->ranges.count != 0;
            uint32_t i = 0;
            do {
                if (start <= pkt->key && pkt->key <= end) {
                    quic_retransmission_process_newly_acked(module, pkt);
                }

                if (lost_flag) {
                    end = start - quic_arr(&frame->ranges, i, quic_ack_range_t)->gap - 2;
                    start = end - quic_arr(&frame->ranges, i, quic_ack_range_t)->len;
                }
            } while (++i < frame->ranges.count);
        }
    }

    while (!quic_link_empty(&module->del_mem_queue)) {
        quic_rbt_foreach_qnode_t *node = (quic_rbt_foreach_qnode_t *) quic_link_next(&module->del_mem_queue);
        quic_sent_packet_rbt_t *pkt = (quic_sent_packet_rbt_t *) node->node;
        quic_link_remove(node);
        free(node);

        quic_retransmission_sent_mem_drop(module, pkt);
    }

    return quic_err_success;
}

static quic_err_t quic_retransmission_module_init(void *const module) {
    quic_retransmission_module_t *r_module = (quic_retransmission_module_t *) module;

    r_module->sent_pkt_count = 0;
    r_module->max_delay = 0;
    r_module->unacked_len = 0;

    quic_rbt_tree_init(r_module->sent_mem);
    quic_link_init(&r_module->del_mem_queue);

    return quic_err_success;
}

quic_module_t quic_initial_retransmission_module = {
    .module_size = sizeof(quic_retransmission_module_t),
    .init = quic_retransmission_module_init,
    .process = NULL,
    .destory = NULL
};

quic_module_t quic_handshake_retransmission_module = {
    .module_size = sizeof(quic_retransmission_module_t),
    .init = quic_retransmission_module_init,
    .process = NULL,
    .destory = NULL
};

quic_module_t quic_app_retransmission_module = {
    .module_size = sizeof(quic_retransmission_module_t),
    .init = quic_retransmission_module_init,
    .process = NULL,
    .destory = NULL
};

quic_err_t quic_session_handle_ack_frame(quic_session_t *const session, const quic_frame_t *const frame) {
    const quic_frame_ack_t *const ack_frame = (const quic_frame_ack_t *) frame;
    quic_retransmission_module_t *r_module = NULL;
    switch (ack_frame->packet_type) {
    case quic_packet_initial_type:
        r_module = quic_session_module(quic_retransmission_module_t, session, quic_initial_retransmission_module);
        break;
    case quic_packet_handshake_type:
        r_module = quic_session_module(quic_retransmission_module_t, session, quic_handshake_retransmission_module);
        break;
    case quic_packet_short_type:
        r_module = quic_session_module(quic_retransmission_module_t, session, quic_app_retransmission_module);
        break;
    default:
        return quic_err_internal_error;
    }
    quic_sent_packet_rbt_t *pkt = quic_sent_pkts_find(r_module->sent_mem, &ack_frame->largest_ack);
    if (!quic_rbt_is_nil(pkt)) {
        uint64_t delay = 0;
        if (ack_frame->packet_type == quic_packet_short_type) {
            delay = ack_frame->delay < r_module->max_delay ? ack_frame->delay : r_module->max_delay;
        }

        quic_rtt_update(&session->rtt, ack_frame->recv_time, pkt->sent_time, delay);

        // TODO congestion control
    }

    quic_retransmission_module_find_newly_acked(r_module, ack_frame);

    return quic_err_success;
}
