/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "module.h"
#include "modules/packet_number_generator.h"
#include <openssl/rand.h>

static quic_err_t quic_packer_number_generator_module_init(void *const module);

static quic_err_t quic_packer_number_generator_module_init(void *const module) {
    quic_packet_number_generator_module_t *const pngen_module = module;

    pngen_module->next = 0;

    return quic_err_success;
}

uint64_t quic_packet_number_generate(quic_packet_number_generator_module_t *const module) {
    return module->next++;
}

quic_module_t quic_initial_packet_number_generator_module = {
    .name        = "initial_packet_number_generator",
    .module_size = sizeof(quic_packet_number_generator_module_t),
    .init        = quic_packer_number_generator_module_init,
    .process     = NULL,
    .loop        = NULL,
    .destory     = NULL
};

quic_module_t quic_handshake_packet_number_generator_module = {
    .name        = "handshake_packet_number_generator",
    .module_size = sizeof(quic_packet_number_generator_module_t),
    .init        = quic_packer_number_generator_module_init,
    .process     = NULL,
    .loop        = NULL,
    .destory     = NULL
};

quic_module_t quic_app_packet_number_generator_module = {
    .name        = "app_packet_number_generator",
    .module_size = sizeof(quic_packet_number_generator_module_t),
    .init        = quic_packer_number_generator_module_init,
    .process     = NULL,
    .loop        = NULL,
    .destory     = NULL
};
