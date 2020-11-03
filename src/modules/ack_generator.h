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
#include "recovery/rtt.h"
#include "module.h"

typedef struct quic_ack_generator_range_s quic_ack_generator_range_t;
struct quic_ack_generator_range_s {
    QUIC_LINK_FIELDS

    uint64_t start;
    uint64_t end;
};

typedef struct quic_ack_generator_module_s quic_ack_generator_module_t;
struct quic_ack_generator_module_s {
    QUIC_MODULE_FIELDS

    quic_link_t ranges;

    uint32_t ranges_count;
    uint64_t ignore_threhold;

    uint64_t lg_obtime;
    uint64_t lg_obnum;

    bool should_send;
    bool is_sent;

    uint64_t alarm;
    uint64_t max_delay;

    // since last ack, packet count
    uint32_t ss_pkt;
    // since last ack, packet (eliciting ACK frame) count
    uint32_t ss_ack_pkt;
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

static inline quic_err_t quic_ack_generator_module_received(module, num, recv_time, rtt, ack_eliciting)
    quic_ack_generator_module_t *const module; 
    const uint64_t num;
    const uint64_t recv_time; 
    quic_rtt_t *const rtt;
    const bool ack_eliciting; {

    if (num < module->ignore_threhold) {
        return quic_err_success;
    }

    bool lost = quic_ack_generator_check_is_lost(module, num);

    if (num >= module->lg_obnum) {
        module->lg_obnum = num;
        module->lg_obtime = recv_time;
    }

    quic_ack_generator_insert_ranges(module, num);

    module->ss_pkt++;
    if (!module->is_sent) {
        module->should_send = true;
        return quic_err_success;
    }

    if (lost) {
        module->should_send = true;
    }

    if (!module->should_send && ack_eliciting) {
        module->ss_ack_pkt++;
        if (num > 100) {
            if (module->ss_ack_pkt >= 10) {
                module->should_send = true;
            }
            else if (module->alarm == 0) {
                uint64_t delay = rtt->min_rtt >> 2;
                delay = module->max_delay < delay ? module->max_delay : delay;
                module->alarm = recv_time + delay;
            }
        }
        else if (module->ss_ack_pkt >= 2) {
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

static inline uint64_t quic_ack_generator_append_ack_frame(quic_link_t *const frames, uint64_t *const largest_ack, quic_ack_generator_module_t *const module) {
    quic_frame_ack_t *frame = quic_ack_generator_generate(module);
    if (frame == NULL) {
        return 0;
    }

    *largest_ack = frame->largest_ack;
    uint64_t len = quic_frame_size(frame);
    quic_link_insert_before(frames, frame);

    return len;
}

#endif
