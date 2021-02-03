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
#include <stdint.h>
#include <stddef.h>

typedef struct quic_session_s quic_session_t;

typedef struct quic_module_s quic_module_t;
struct quic_module_s {
    const char *name;
    const uint32_t module_size;
    quic_err_t (*init) (void *const module);
    quic_err_t (*start) (void *const module);
    quic_err_t (*process) (void *const module);
    quic_err_t (*destory) (void *const module);
    quic_err_t (*loop) (void *const module, const uint64_t now);

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

#define quic_module_start(module)                                           \
    if (((quic_base_module_t *) (module))->module_declare->start) {         \
        ((quic_base_module_t *) (module))->module_declare->start((module)); \
    }

#define quic_module_process(module)                                           \
    if (((quic_base_module_t *) (module))->module_declare->process) {         \
        ((quic_base_module_t *) (module))->module_declare->process((module)); \
    }

#define quic_module_loop(module, now)                                             \
    if (((quic_base_module_t *) (module))->module_declare->loop) {                \
        ((quic_base_module_t *) (module))->module_declare->loop((module), (now)); \
    }

#define quic_module_destory(module)                                           \
    if (((quic_base_module_t *) (module))->module_declare->destory) {         \
        ((quic_base_module_t *) (module))->module_declare->destory((module)); \
    }

extern quic_module_t *quic_modules[];

uint32_t quic_modules_size();

#endif
