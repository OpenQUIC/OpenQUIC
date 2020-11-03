/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_CONGCTRL_H__
#define __OPENQUIC_CONGCTRL_H__

#include "recovery/rtt.h"
#include "utils/errno.h"
#include "space.h"
#include "module.h"
#include <stdbool.h>

typedef struct quic_sent_packet_s quic_sent_packet_t;
struct quic_sent_packet_s {
    uint64_t p_num;
    bool ack_eliciting;
    bool in_flight;
    uint64_t sent_bytes;
    uint64_t time_sent;
};

#define QUIC_CONGCTRL_FIELDS              \
    uint64_t max_datagram_size;           \
    int ecn_ce_counter[quic_space_count]; \
    uint64_t bytes_in_flight;             \
    uint64_t cwnd;                        \
    uint64_t recovery_start_time;         \
    uint64_t ssthresh;                    \
    uint64_t first_rtt_sample;            \

typedef struct quic_congctrl_s quic_congctrl_t;
struct quic_congctrl_s {
    QUIC_CONGCTRL_FIELDS
};

static inline quic_err_t quic_congctrl_init(quic_congctrl_t *const congctrl, const uint64_t initial_cwnd) {
    congctrl->cwnd = initial_cwnd;
    congctrl->bytes_in_flight = 0;
    congctrl->recovery_start_time = 0;
    congctrl->ssthresh = 0;
    congctrl->first_rtt_sample = 0;
    int i;
    for (i = 0; i < quic_space_count; i++) {
        congctrl->ecn_ce_counter[i] = 0;
    }

    return quic_err_success;
}

static inline quic_err_t quic_congctrl_on_sent(quic_congctrl_t *const congctrl, const uint64_t bytes_sent) {
    congctrl->bytes_in_flight += bytes_sent;
    return quic_err_success;
}

static inline bool quic_congctrl_in_recovery(quic_congctrl_t *const congctrl, const uint64_t sent_time) {
    return sent_time <= congctrl->recovery_start_time;
}

typedef struct quic_congctrl_module_s quic_congctrl_module_t;
struct quic_congctrl_module_s {
    QUIC_MODULE_FIELDS

    void (*on_ack) (quic_congctrl_t *const congctrl, const uint64_t num, const uint64_t acked_bytes, const uint64_t prior_in_flight, uint64_t event_time);
    void (*on_lost) (quic_congctrl_t *const congctrl, const uint64_t num, const uint64_t lost_bytes, const uint64_t prior_in_flight);
    void (*on_sent) (quic_congctrl_t *const congctrl, const uint64_t num, const uint64_t in_flight, const uint64_t bytes, const bool is_retransmittable);
    bool (*avail_send) (quic_congctrl_t *const congctrl, const uint64_t bytes);
    uint64_t (*next_send_time) (quic_congctrl_t *const congctrl, const uint64_t in_flight);
};

extern quic_module_t quic_congctrl_module;

#endif
