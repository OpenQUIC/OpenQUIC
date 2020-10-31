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
};

quic_err_t quic_ack_generator_insert_ranges(quic_ack_generator_module_t *const module, const uint64_t num);

quic_err_t quic_ack_generator_ignore(quic_ack_generator_module_t *const module);

quic_frame_ack_t *quic_ack_generator_generate(quic_ack_generator_module_t *const module);

static inline quic_err_t quic_ack_generator_module_received(quic_ack_generator_module_t *const module, const uint64_t num) {
    if (num < module->ignore_threhold) {
        return quic_err_success;
    }

    return quic_ack_generator_insert_ranges(module, num);
}

static inline quic_err_t quic_ack_generator_set_ignore_threhold(quic_ack_generator_module_t *const module, const uint64_t num) {
    if (num <= module->ignore_threhold) {
        return quic_err_success;
    }
    module->ignore_threhold = num;

    return quic_ack_generator_ignore(module);
}

extern quic_module_t quic_ack_generator_module;

#endif
