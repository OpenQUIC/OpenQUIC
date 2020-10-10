/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_RTT_H__
#define __OPENQUIC_RTT_H__

#include "utils/errno.h"
#include <stdint.h>

#define QUIC_RTT_FIELDS    \
    uint64_t min_rtt;      \
    uint64_t smoothed_rtt; \
    uint64_t rttvar;       \

typedef struct quic_rtt_s quic_rtt_t;
struct quic_rtt_s {
    QUIC_RTT_FIELDS
};

static inline quic_err_t quic_rtt_init(quic_rtt_t *const rtt) {
    rtt->min_rtt = 0;
    rtt->smoothed_rtt = 333 * 1000;
    rtt->rttvar = 333 * 1000 >> 2;

    return quic_err_success;
}

static inline quic_err_t quic_rtt_update(quic_rtt_t *const rtt, const uint64_t recv_time, const uint64_t send_time, const uint64_t ack_delay) {
    const uint64_t latest_rtt = recv_time - send_time;

    if (rtt->min_rtt == 0) {
        rtt->min_rtt = latest_rtt;
        rtt->smoothed_rtt = latest_rtt;
        rtt->rttvar = latest_rtt / 2;
    }
    else {
        if (rtt->min_rtt > latest_rtt) {
            rtt->min_rtt = latest_rtt;
        }
        uint64_t adjusted_rtt = latest_rtt;
        if (rtt->min_rtt + ack_delay < latest_rtt) {
            adjusted_rtt -= ack_delay;
        }
        rtt->smoothed_rtt = (7 * rtt->smoothed_rtt + adjusted_rtt) >> 3;
#define __abs_distance__(a, b) ((a) > (b) ? ((a) - (b)) : ((b) - (a)))
        uint64_t rttvar_simple = __abs_distance__(latest_rtt, adjusted_rtt);
#undef __abs_distance__
        rtt->rttvar = (3 * rtt->rttvar + rttvar_simple) >> 2;
    }

    return quic_err_success;
}

static inline uint64_t quic_rtt_pto(quic_rtt_t *const rtt, uint64_t max_ack_delay) {
#define __max__(a, b) ((a) > (b) ? (a) : (b))
    return rtt->smoothed_rtt + __max__(rtt->rttvar << 2, 1000) + max_ack_delay;
#undef __max__
}

#endif
