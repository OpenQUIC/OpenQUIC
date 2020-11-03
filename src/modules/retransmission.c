/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "modules/retransmission.h"

static quic_err_t quic_retransmission_module_init(void *const module);

quic_err_t quic_retransmission_module_find_newly_acked(quic_retransmission_module_t *const module, quic_frame_ack_t *const frame) {
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

    r_module->sent_count = 0;
    quic_rbt_tree_init(r_module->sent_mem);

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
