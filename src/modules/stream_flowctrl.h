/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_STREAM_FLOWCTRL_H__
#define __OPENQUIC_STREAM_FLOWCTRL_H__

#include "rtt.h"
#include "utils/errno.h"
#include "module.h"

typedef struct quic_stream_flowctrl_module_s quic_stream_flowctrl_module_t;
struct quic_stream_flowctrl_module_s {
    QUIC_MODULE_FIELDS

    uint32_t module_size;

    quic_err_t (*init) (quic_stream_flowctrl_module_t *const module, void *const flowctrl);
    void (*update_rwnd) (void *const flowctrl, const uint64_t t_off, const bool fin);
    void (*abandon) (void *const flowctrl);
    uint64_t (*get_swnd) (void *const flowctrl);
    void (*sent) (void *const flowctrl, const uint64_t sent_bytes);
    bool (*newly_blocked) (uint64_t *const limit, void *const flowctrl);
    quic_err_t (*destory) (void *const flowctrl);
};

extern quic_module_t quic_stream_flowctrl_module;

#define quic_stream_flowctrl_init(module, instance) \
    if ((module)->init) {                           \
        (module)->init((module), (instance));       \
    }

#define quic_stream_flowctrl_update_rwnd(module, instance, t_off, fin) \
    if ((module)->update_rwnd) {                                       \
        (module)->update_rwnd((instance), (t_off), (fin));             \
    }

#define quic_stream_flowctrl_abandon(module, instance) \
    if ((module)->abandon) {                           \
        (module)->abandon((instance));                 \
    }

#define quic_stream_flowctrl_get_swnd(module, instance) \
    ((module)->get_swnd ? (module)->get_swnd((instance)) : 0)

#define quic_stream_flowctrl_sent(module, instance, sent_bytes) \
    if ((module)->sent) {                                       \
        (module)->sent((instance), (sent_bytes));               \
    }

#define quic_stream_flowctrl_newly_blocked(module, limit, instance) \
    ((module)->newly_blocked ? (module)->newly_blocked((limit), (instance)) : false)

#define quic_stream_flowctrl_destory(module, instance) \
    if ((module)->destory) {                           \
        (module)->destory((instance));                 \
    }

#endif
