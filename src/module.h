/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_MODULE_H__
#define __OPENQUIC_MODULE_H__

#include "utils/errno.h"
#include "liteco.h"
#include <stdint.h>

typedef struct quic_session_s quic_session_t;

typedef struct quic_module_s quic_module_t;
struct quic_module_s {
    const uint32_t module_size;
    quic_err_t (*init) (void *const module);
    quic_err_t (*process) (void *const module);
    quic_err_t (*destory) (void *const module);

    uint32_t off;
};

#define QUIC_MODULE_FIELDS \
    quic_module_t *module_declare;

typedef struct quic_base_module_s quic_base_module_t;
struct quic_base_module_s {
    QUIC_MODULE_FIELDS
};

#define quic_module_init(module)                                           \
    if (((quic_base_module_t *) (module))->module_declare->init) {         \
        ((quic_base_module_t *) (module))->module_declare->init((module)); \
    }

extern quic_module_t *quic_modules[];

uint32_t quic_modules_size();

#endif
