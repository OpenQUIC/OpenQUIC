/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_MODULE_H__
#define __OPENQUIC_MODULE_H__

#include "liteco.h"
#include <stdint.h>

#define QUIC_MODULE_FIELDS      \
    const char *name;           \
    const uint32_t module_size; \
    liteco_channel_t notifier;  \
    uint32_t off;               \

typedef struct quic_module_s quic_module_t;
struct quic_module_s {
    QUIC_MODULE_FIELDS
};

extern quic_module_t *quic_modules[];

uint32_t quic_modules_size();

#endif
