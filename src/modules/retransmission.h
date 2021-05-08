/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_RETRANSMISSION_H__
#define __OPENQUIC_RETRANSMISSION_H__

#include "platform/platform.h"
#include "format/frame.h"
#include "modules/congestion.h"
#include "module.h"
#include "session.h"
#include "liteco.h"

typedef struct quic_sent_packet_rbt_s quic_sent_packet_rbt_t;
struct quic_sent_packet_rbt_s {
    LITECO_RBT_KEY_UINT64_FIELDS

    uint64_t largest_ack;
    uint64_t sent_time;
    uint32_t pkt_len;
    bool included_unacked;
    liteco_linknode_t frames;
};

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

    uint64_t alarm;
    uint32_t pto_count;
    bool dropped;

    liteco_linknode_t retransmission_queue;
};

extern quic_module_t quic_initial_retransmission_module;
extern quic_module_t quic_handshake_retransmission_module;
extern quic_module_t quic_app_retransmission_module;

uint64_t quic_retransmission_append_frame(liteco_linknode_t *const frames, const uint64_t capa, quic_retransmission_module_t *const module);
quic_err_t quic_retransmission_drop(quic_retransmission_module_t *const module);

__quic_header_inline bool quic_retransmission_empty(quic_retransmission_module_t *const module) {
    return liteco_link_empty(&module->retransmission_queue);
}

__quic_header_inline quic_err_t quic_retransmission_frame_insert(quic_retransmission_module_t *const module, quic_frame_t *const frame) {
    if (module->dropped) {
        return quic_err_success;
    }

    liteco_link_insert_before(&module->retransmission_queue, frame);
    return quic_err_success;
}

__quic_header_inline quic_err_t quic_retransmission_update_alarm(quic_retransmission_module_t *const module) {
    if (module->dropped) {
        return quic_err_success;
    }

    quic_session_t *const session = quic_module_of_session(module);
    quic_congestion_module_t *const c_module = quic_session_module(session, quic_congestion_module);

    if (!module->unacked_len) {
        module->alarm = 0;
        return quic_err_success;
    }

    module->alarm = module->last_sent_ack_time + (quic_congestion_pto(c_module, module->max_delay) << module->pto_count);

    quic_session_update_loop_deadline(session, module->alarm);

    return quic_err_success;
}

__quic_header_inline quic_err_t quic_retransmission_sent_mem_push(quic_retransmission_module_t *const module, quic_sent_packet_rbt_t *const pkt) {
    if (module->dropped) {
        return quic_err_success;
    }
    
    liteco_rbt_insert(&module->sent_mem, pkt);
    module->sent_pkt_count++;

    if (pkt->included_unacked) {
        module->last_sent_ack_time = pkt->sent_time;
        module->unacked_len += pkt->pkt_len;

        quic_retransmission_update_alarm(module);
    }

    return quic_err_success;
}

#endif
