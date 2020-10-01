/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_FLOWCTRL_BASE_H__
#define __OPENQUIC_FLOWCTRL_BASE_H__

#include "utils/errno.h"
#include <stdint.h>
#include <stdbool.h>

#define QUIC_FLOWCTRL_FIELDS                                                                    \
    quic_err_t (*init) (quic_flowctrl_t *const flowctrl);                                       \
    bool (*is_newly_blocked) (uint64_t *const swnd, quic_flowctrl_t *const flowctrl);           \
    void (*update_swnd) (quic_flowctrl_t *const flowctrl, const uint64_t swnd);                 \
    uint64_t (*get_swnd) (quic_flowctrl_t *const flowctrl);                                     \
    void (*sent_bytes) (quic_flowctrl_t *const flowctrl, const uint64_t bytes);                 \
    void (*update_rwnd) (quic_flowctrl_t *const flowctrl, const uint64_t rwnd, const bool fin); \
    bool (*abandon) (quic_flowctrl_t *const flowctrl);                                          \
    void (*recv_bytes) (quic_flowctrl_t *const flowctrl, const uint64_t bytes);                 \


typedef struct quic_flowctrl_s quic_flowctrl_t;
struct quic_flowctrl_s { 
    QUIC_FLOWCTRL_FIELDS
};

#define quic_flowctrl_init(flowctrl) ((flowctrl)->init((flowctrl)))
#define quic_flowctrl_is_newly_blocked(swnd, flowctrl) ((flowctrl)->is_newly_blocked((swnd), (flowctrl)))
#define quic_flowctrl_update_swnd(flowctrl, swnd) ((flowctrl)->update_swnd((flowctrl), (swnd)))
#define quic_flowctrl_get_swnd(flowctrl) ((flowctrl)->get_swnd((flowctrl)))
#define quic_flowctrl_sent_bytes(flowctrl, bytes) ((flowctrl)->sent_bytes((flowctrl), (bytes)))
#define quic_flowctrl_update_rwnd(flowctrl, rwnd, fin) ((flowctrl)->update_rwnd((flowctrl), (rwnd), (fin)))
#define quic_flowctrl_abandon(flowctrl) ((flowctrl)->abandon((flowctrl)))
#define quic_flowctrl_recv_bytes(flowctrl, bytes) ((flowctrl)->recv_bytes((flowctrl), (bytes)))

#endif
