/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_CONN_FLOWCTRL_H__
#define __OPENQUIC_CONN_FLOWCTRL_H__

#include "platform/platform.h"
#include "modules/congestion.h"
#include "utils/time.h"
#include "module.h"
#include "session.h"

typedef struct quic_conn_flowctrl_module_s quic_conn_flowctrl_module_t;
struct quic_conn_flowctrl_module_s {
    QUIC_MODULE_FIELDS

    uint64_t rwnd;
    uint64_t rwnd_size;
    uint64_t recv_off;
    uint64_t read_off;

    uint64_t swnd;
    uint64_t sent_bytes;

    uint64_t epoch_off;
    uint64_t epoch_time;

    pthread_mutex_t rwnd_updated_mtx;
    bool updated;
};

extern quic_module_t quic_conn_flowctrl_module;

__quic_header_inline quic_err_t quic_conn_flowctrl_increment_recv(quic_conn_flowctrl_module_t *const module, const uint64_t increment) {
    module->recv_off += increment;

    if (module->recv_off > module->rwnd) {
        // TODO should return disallow recv
        return quic_err_success;
    }

    return quic_err_success;
}

__quic_header_inline quic_err_t quic_conn_flowctrl_update_swnd(quic_conn_flowctrl_module_t *const module, const uint64_t off) {
    if (off > module->swnd) {
        module->swnd = off;
    }
    return quic_err_success;
}

__quic_header_inline void quic_conn_flowctrl_adjust_rwnd(quic_conn_flowctrl_module_t *const module) {
    quic_session_t *const session = quic_module_of_session(module);
    quic_congestion_module_t *const c_module = quic_session_module(session, quic_congestion_module);

    uint64_t smoothed_rtt = quic_congestion_smoothed_rtt(c_module);
    uint64_t in_epoch_readed_bytes = module->read_off - module->epoch_off;
    if (in_epoch_readed_bytes <= (module->rwnd_size >> 1) || !smoothed_rtt) {
        return;
    }

    uint64_t now = quic_now();
    if (now - module->epoch_time < (smoothed_rtt >> 2) * in_epoch_readed_bytes / module->rwnd_size) {
        module->rwnd_size = (module->rwnd_size >> 1) > session->cfg.conn_flowctrl_max_rwnd_size ? session->cfg.conn_flowctrl_max_rwnd_size : (module->rwnd_size >> 1);
    }

    module->epoch_time = now;
    module->epoch_off = module->read_off;

    module->rwnd = module->read_off + module->rwnd_size;
}

__quic_header_inline quic_err_t quic_conn_flowctrl_ensure_min_rwnd_size(quic_conn_flowctrl_module_t *const module, const uint64_t rwnd_size) {
    quic_session_t *const session = quic_module_of_session(module);

    if (rwnd_size > module->rwnd_size) {
        module->rwnd_size = rwnd_size < session->cfg.conn_flowctrl_max_rwnd_size ? rwnd_size : session->cfg.conn_flowctrl_max_rwnd_size;
        module->epoch_time = quic_now();
        module->epoch_off = module->rwnd;
    }
    return quic_err_success;
}

__quic_header_inline quic_err_t quic_conn_flowctrl_update_rwnd(quic_conn_flowctrl_module_t *const module) {
    pthread_mutex_lock(&module->rwnd_updated_mtx);
    module->updated = true;
    pthread_mutex_unlock(&module->rwnd_updated_mtx);

    return quic_err_success;
}

__quic_header_inline quic_err_t quic_conn_flowctrl_read(quic_conn_flowctrl_module_t *const module, const uint64_t bytes) {
    if (!module->read_off) {
        module->epoch_off = 0;
        module->epoch_time = quic_now();
    }
    module->read_off += bytes;
    if (module->rwnd - module->read_off <= ((module->rwnd_size * 3) >> 2)) {
        quic_conn_flowctrl_adjust_rwnd(module);
        quic_conn_flowctrl_update_rwnd(module);
    }

    return quic_err_success;
}

__quic_header_inline quic_err_t quic_conn_flowctrl_sent(quic_conn_flowctrl_module_t *const module, const uint64_t bytes) {
    module->sent_bytes += bytes;

    return quic_err_success;
}

#endif
