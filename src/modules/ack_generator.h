/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_ACK_GENERATOR_H__
#define __OPENQUIC_ACK_GENERATOR_H__

#include "utils/link.h"
#include "format/frame.h"
#include "module.h"
#include "recovery/rtt.h"

typedef struct quic_ack_generator_range_s quic_ack_generator_range_t;
struct quic_ack_generator_range_s {
    QUIC_LINK_FIELDS

    uint64_t start;
    uint64_t end;
};

typedef struct quic_ack_generator_module_s quic_ack_generator_module_t;
struct quic_ack_generator_module_s {
    quic_link_t ranges;

    uint32_t ranges_count;
    uint64_t ignore_threhold;

    uint64_t lg_obtime;
    uint64_t lg_obnum;

    bool should_send;
    bool is_sent;

    uint64_t sent_largest_ack;

    uint64_t alarm;
    uint64_t max_delay;

    // since last ack, packet count
    uint32_t ss_pkg;
    // since last ack, packet (eliciting ACK frame) count
    uint32_t ss_ack_pkg;

    bool dropped;
};

extern quic_module_t quic_initial_ack_generator_module;
extern quic_module_t quic_handshake_ack_generator_module;
extern quic_module_t quic_app_ack_generator_module;

quic_err_t quic_ack_generator_insert_ranges(quic_ack_generator_module_t *const module, const uint64_t num);

quic_err_t quic_ack_generator_ignore(quic_ack_generator_module_t *const module);

quic_frame_ack_t *quic_ack_generator_generate(quic_ack_generator_module_t *const module);

bool quic_ack_generator_check_is_lost(quic_ack_generator_module_t *const module, const uint64_t num);

static inline bool quic_ack_generator_contains_lost(quic_ack_generator_module_t *const module) {
    return module->ranges_count > 1
        || ((quic_ack_generator_range_t *) quic_link_next(&module->ranges))->start > module->ignore_threhold;
}

static inline quic_err_t quic_ack_generator_module_received(module, num, recv_time, rtt, should_send)
    quic_ack_generator_module_t *const module; 
    const uint64_t num;
    const uint64_t recv_time; 
    quic_rtt_t *const rtt;
    const bool should_send; {

    if (num < module->ignore_threhold) {
        return quic_err_success;
    }

    bool lost = quic_ack_generator_check_is_lost(module, num);

    if (num >= module->lg_obnum) {
        module->lg_obnum = num;
        module->lg_obtime = recv_time;
    }

    quic_ack_generator_insert_ranges(module, num);

    module->ss_pkg++;
    if (!module->is_sent) {
        module->should_send = true;
        return quic_err_success;
    }

    if (lost) {
        module->should_send = true;
    }

    if (!module->should_send && should_send) {
        module->ss_ack_pkg++;
        if (num > 100) {
            if (module->ss_ack_pkg >= 10) {
                module->should_send = true;
            }
            else if (module->alarm == 0) {
                uint64_t delay = rtt->min_rtt >> 2;
                delay = module->max_delay < delay ? module->max_delay : delay;
                module->alarm = recv_time + delay;
            }
        }
        else if (module->ss_ack_pkg >= 2) {
            module->should_send = true;
        }
        else {
            module->alarm = recv_time + module->max_delay;
        }

        if (quic_ack_generator_contains_lost(module)) {
            uint64_t alarm = recv_time + (rtt->min_rtt >> 3);
            if (module->alarm == 0 || alarm < module->alarm) {
                module->alarm = alarm;
            }
        }
    }

    if (module->should_send) {
        module->alarm = 0;
    }
    return quic_err_success;
}

static inline quic_err_t quic_ack_generator_set_ignore_threhold(quic_ack_generator_module_t *const module, const uint64_t num) {
    if (num <= module->ignore_threhold) {
        return quic_err_success;
    }
    module->ignore_threhold = num;

    return quic_ack_generator_ignore(module);
}

#endif
