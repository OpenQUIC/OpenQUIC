/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_ACK_GENERATOR_H__
#define __OPENQUIC_ACK_GENERATOR_H__

#include "format/frame.h"
#include "liteco.h"
#include "module.h"
#include "platform/platform.h"

typedef struct quic_ack_generator_range_s quic_ack_generator_range_t;
struct quic_ack_generator_range_s {
    LITECO_LINKNODE_BASE

    uint64_t start;
    uint64_t end;
};

typedef struct quic_ack_generator_module_s quic_ack_generator_module_t;
struct quic_ack_generator_module_s {
    QUIC_MODULE_FIELDS

    liteco_linknode_t ranges;

    uint32_t ranges_count;
    uint64_t ignore_threhold;

    uint64_t lg_obtime;
    uint64_t lg_obnum;

    bool should_send;
    bool is_sent;

    bool dropped;
    uint64_t alarm;
};

extern quic_module_t quic_initial_ack_generator_module;
extern quic_module_t quic_handshake_ack_generator_module;
extern quic_module_t quic_app_ack_generator_module;

bool quic_ack_generator_insert_ranges(quic_ack_generator_module_t *const module, const uint64_t num);
quic_err_t quic_ack_generator_ignore(quic_ack_generator_module_t *const module);
quic_frame_ack_t *quic_ack_generator_generate(quic_ack_generator_module_t *const module);
bool quic_ack_generator_check_is_lost(quic_ack_generator_module_t *const module, const uint64_t num);
quic_err_t quic_ack_generator_drop(quic_ack_generator_module_t *const module);

__quic_header_inline bool quic_ack_generator_contains_lost(quic_ack_generator_module_t *const module) {
    if (module->dropped) {
        return false;
    }

    return module->ranges_count > 1
        || ((quic_ack_generator_range_t *) liteco_link_next(&module->ranges))->start > module->ignore_threhold;
}

__quic_header_inline bool quic_ack_generator_should_send(quic_ack_generator_module_t *const module) {
    if (module->dropped) {
        return false;
    }

    return module->should_send;
}

__quic_header_inline quic_err_t quic_ack_generator_module_received(quic_ack_generator_module_t *const module, const uint64_t num, const uint64_t recv_time) {
    if (num < module->ignore_threhold || module->dropped) {
        return quic_err_success;
    }

    bool lost = quic_ack_generator_check_is_lost(module, num);

    if (num >= module->lg_obnum) {
        module->lg_obnum = num;
        module->lg_obtime = recv_time;
    }

    if (quic_ack_generator_insert_ranges(module, num)) {
        module->should_send = true;
    }
    if (lost) {
        module->should_send = true;
    }
    return quic_err_success;
}

__quic_header_inline quic_err_t quic_ack_generator_set_ignore_threhold(quic_ack_generator_module_t *const module, const uint64_t num) {
    if (num <= module->ignore_threhold) {
        return quic_err_success;
    }
    module->ignore_threhold = num;

    return quic_ack_generator_ignore(module);
}

__quic_header_inline uint64_t quic_ack_generator_append_ack_frame(liteco_linknode_t *const frames, uint64_t *const largest_ack, quic_ack_generator_module_t *const module) {
    quic_frame_ack_t *frame = quic_ack_generator_generate(module);
    if (frame == NULL) {
        return 0;
    }

    *largest_ack = frame->largest_ack;
    uint64_t len = quic_frame_size(frame);
    liteco_link_insert_before(frames, frame);

    return len;
}

#endif
