/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_CONGESTION_H__
#define __OPENQUIC_CONGESTION_H__

#include "module.h"

typedef struct quic_congestion_module_s quic_congestion_module_t;
struct quic_congestion_module_s {
    QUIC_MODULE_FIELDS

    quic_err_t (*on_sent) (quic_congestion_module_t *const module, const uint64_t num, const uint64_t sent_bytes, const bool retransmission);
    quic_err_t (*on_acked) (quic_congestion_module_t *const module, const uint64_t num, const uint64_t acked_bytes, const uint64_t unacked_unacked, const uint64_t event_time);
    quic_err_t (*on_lost) (quic_congestion_module_t *const module, const uint64_t num, const uint64_t lost_bytes, const uint64_t unacked_bytes);

    quic_err_t (*update) (quic_congestion_module_t *const module, const uint64_t recv_time, const uint64_t sent_time, const uint64_t ack_delay);
    bool (*allow_send) (quic_congestion_module_t *const module, const uint64_t unacked);
    uint64_t (*next_send_time) (quic_congestion_module_t *const module, const uint64_t unacked);

    uint8_t instance[0];
};

#define quic_congestion_update(module, recv_time, sent_time, ack_delay)    \
    if ((module)->update) {                                                \
        (module)->update((module), (recv_time), (sent_time), (ack_delay)); \
    }

extern quic_module_t quic_congestion_module;

#endif
