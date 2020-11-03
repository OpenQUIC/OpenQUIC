/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_FLOWCTRL_H__
#define __OPENQUIC_FLOWCTRL_H__

#include "recovery/rtt.h"
#include "utils/errno.h"
#include "module.h"
#include <stdint.h>
#include <stdbool.h>

typedef struct quic_session_s quic_session_t;

typedef void quic_conn_flowctrl_t;
typedef void quic_stream_flowctrl_t;

#define QUIC_STREAM_FLOWCTRL_MODULE_FIELDS                                                                    \
    QUIC_MODULE_FIELDS                                                                                        \
                                                                                                              \
    uint32_t size;                                                                                            \
                                                                                                              \
    quic_err_t (*init) (quic_stream_flowctrl_t *const flowctrl, quic_stream_flowctrl_module_t *const module); \
    void (*update_rwnd) (quic_stream_flowctrl_t *const flowctrl, const uint64_t t_off, const bool fin);       \
    bool (*abandon) (quic_stream_flowctrl_t *const flowctrl);                                                 \
    uint64_t (*get_swnd) (quic_stream_flowctrl_t *const flowctrl);                                            \
    void (*sent) (quic_stream_flowctrl_t *const flowctrl, const uint64_t bytes);                              \
    quic_err_t (*destory) (quic_stream_flowctrl_t *const flowctrl);                                           \
    

typedef struct quic_stream_flowctrl_module_s quic_stream_flowctrl_module_t;
struct quic_stream_flowctrl_module_s {
    QUIC_STREAM_FLOWCTRL_MODULE_FIELDS
};

extern quic_module_t quic_connection_flowctrl_module;
extern quic_module_t quic_stream_flowctrl_module;

#define quic_session_stream_flowctrl(sess)  \
    quic_session_module(quic_stream_flowctrl_module_t, sess, quic_stream_flowctrl_module)

#define quic_stream_flowctrl_init(module, flowctrl) \
    ((module)->init && ((module)->init((flowctrl), (module))))

#endif
