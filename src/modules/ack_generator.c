/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "modules/ack_generator.h"
#include "utils/time.h"
#include <malloc.h>

static quic_err_t quic_ack_generator_init(void *const module);

quic_err_t quic_ack_generator_insert_ranges(quic_ack_generator_module_t *const module, const uint64_t num) {
    quic_ack_generator_range_t *range = NULL;

    quic_link_foreach(range, &module->ranges) {
        if (range->start <= num && num <= range->end) {
            return quic_err_success;
        }

        bool extends = false;
        if (range->end + 1 == num) {
            extends = true;
            range->end++;
        }
        else if (range->start - 1 == num) {
            extends = true;
            range->start--;
        }

        if (extends) {
            if ((quic_link_t *) quic_link_prev(range) != &module->ranges && quic_link_prev(range)->end + 1 == range->start) {
                quic_link_prev(range)->end = range->end;
                quic_link_remove(range);
                free(range);

                module->ranges_count--;
            }
            if ((quic_link_t *) quic_link_next(range) != &module->ranges && quic_link_next(range)->start - 1 == range->end) {
                quic_link_next(range)->start = range->start;
                quic_link_remove(range);
                free(range);

                module->ranges_count--;
            }

            return quic_err_success;
        }

        if (num < range->start) {
            quic_ack_generator_range_t *new_range = malloc(sizeof(quic_ack_generator_range_t));
            if (new_range == NULL) {
                return quic_err_internal_error;
            }
            quic_link_init(new_range);
            new_range->start = new_range->end = num;

            quic_link_insert_before(range, new_range);
            module->ranges_count++;

            return quic_err_success;
        }
    }

    if ((range = malloc(sizeof(quic_ack_generator_range_t))) == NULL) {
        return quic_err_internal_error;
    }
    quic_link_init(range);
    range->start = range->end = num;

    quic_link_insert_before(&module->ranges, range);
    module->ranges_count++;

    return quic_err_success;
}

quic_err_t quic_ack_generator_ignore(quic_ack_generator_module_t *const module) {
    quic_ack_generator_range_t *range = NULL;

    quic_link_foreach(range, &module->ranges) {
        if (module->ignore_threhold <= range->start) {
            return quic_err_success;
        }

        if (module->ignore_threhold > range->end) {
            quic_link_t *prev = range->prev;

            quic_link_remove(range);
            free(range);

            range = (quic_ack_generator_range_t *) prev;
        }
        else {
            range->start = module->ignore_threhold;
            return quic_err_success;
        }
    }

    return quic_err_success;
}

quic_frame_ack_t *quic_ack_generator_generate(quic_ack_generator_module_t *const module) {
    uint64_t now = quic_now();

    if (!module->should_send && (module->alarm == 0 || now < module->alarm)) {
        return NULL;
    }

    quic_frame_ack_t *frame = malloc(sizeof(quic_frame_ack_t) + sizeof(quic_ack_range_t) * (module->ranges_count - 1));
    frame->first_byte = quic_frame_ack_type;
    frame->ect0 = 0;
    frame->ect1 = 0;
    frame->ect_ce = 0;
    frame->ranges.count = module->ranges_count - 1;
    frame->ranges.size = sizeof(quic_ack_range_t);

    uint64_t smallest = 0;
    bool first = true;
    quic_ack_generator_range_t *range = NULL;
    uint32_t rangeidx = 0;
    quic_link_rforeach(range, &module->ranges) {
        if (first) {
            first = false;

            frame->largest_ack = range->end;
            frame->first_range = range->end - range->start;
            smallest = range->start;
        }
        else {
            quic_arr(&frame->ranges, rangeidx, quic_ack_range_t)->gap = smallest - range->end - 2;
            quic_arr(&frame->ranges, rangeidx, quic_ack_range_t)->len = range->end - range->start;
            smallest = range->start;
            rangeidx++;
        }
    }
    frame->delay = now - module->lg_obtime;

    module->alarm = 0;
    module->should_send = false;
    module->ss_pkt = 0;
    module->ss_ack_pkt = 0;

    return frame;
}

bool quic_ack_generator_check_is_lost(quic_ack_generator_module_t *const module, const uint64_t num) {
    quic_ack_generator_range_t *range = NULL;
    if (num <= module->ignore_threhold || num >= ((quic_ack_generator_range_t *) quic_link_prev(&module->ranges))->start) {
        return false;
    }

    quic_link_foreach(range, &module->ranges) {
        if (num < range->start) {
            return true;
        }
        if (range->start <= num && num <= range->end) {
            return false;
        }
    }

    return false;
}

static quic_err_t quic_ack_generator_init(void *const module) {
    quic_ack_generator_module_t *const ag_module = module;
    ag_module->ignore_threhold = 0;
    ag_module->ranges_count = 0;
    quic_link_init(&ag_module->ranges);

    ag_module->lg_obnum = 0;
    ag_module->lg_obtime = 0;

    ag_module->should_send = false;
    ag_module->is_sent = false;
    ag_module->alarm = 0;

    ag_module->ss_pkt = 0;
    ag_module->ss_ack_pkt = 0;

    ag_module->max_delay = 25 * 1000;

    return quic_err_success;
}

quic_module_t quic_initial_ack_generator_module = {
    .module_size = sizeof(quic_ack_generator_module_t),
    .init = quic_ack_generator_init,
    .process = NULL,
    .destory = NULL
};

quic_module_t quic_handshake_ack_generator_module = {
    .module_size = sizeof(quic_ack_generator_module_t),
    .init = quic_ack_generator_init,
    .process = NULL,
    .destory = NULL
};

quic_module_t quic_app_ack_generator_module = {
    .module_size = sizeof(quic_ack_generator_module_t),
    .init = quic_ack_generator_init,
    .process = NULL,
    .destory = NULL
};
