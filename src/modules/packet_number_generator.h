/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_PACKET_NUMBER_GENERATOR_H__
#define __OPENQUIC_PACKET_NUMBER_GENERATOR_H__

#include "utils/link.h"
#include "module.h"
#include <stdint.h>

typedef struct quic_packet_number_generator_module_s quic_packet_number_generator_module_t;
struct quic_packet_number_generator_module_s {
    QUIC_MODULE_FIELDS

    uint64_t next;
};

uint64_t quic_packet_number_generate(quic_packet_number_generator_module_t *const module);

extern quic_module_t quic_initial_packet_number_generator_module;
extern quic_module_t quic_handshake_packet_number_generator_module;
extern quic_module_t quic_app_packet_number_generator_module;

#endif
