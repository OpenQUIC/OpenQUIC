/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "modules/stream_flowctrl.h"
#include "modules/framer.h"
#include "modules/stream.h"
#include "utils/time.h"
#include "session.h"

static quic_err_t quic_stream_flowctrl_module_init(void *const module);
static quic_err_t quic_stream_flowctrl_instance_init(quic_stream_flowctrl_module_t *const module, void *const instance);
static void quic_stream_flowctrl_instance_update_rwnd(void *const instance, const uint64_t off, const bool fin);
static void quic_stream_flowctrl_instance_update_swnd(void *const instance, const uint64_t off);
static void quic_stream_flowctrl_instance_abandon(void *const instance);
static uint64_t quic_stream_flowctrl_instance_get_swnd(void *const instance);
static void quic_stream_flowctrl_instance_sent(void *const instance, const uint64_t sent_bytes);
static void quic_stream_flowctrl_instance_read(void *const instance, const uint64_t sid, const uint64_t readed_bytes);
static bool quic_stream_flowctrl_instance_newly_blocked(uint64_t *const limit, void *const instance);

static inline void quic_stream_flowctrl_adjust_rwnd(quic_stream_flowctrl_t *const flowctrl);

static quic_err_t quic_stream_flowctrl_module_init(void *const module) {
    quic_stream_flowctrl_module_t *const sf_module = module;

    sf_module->module_size = sizeof(quic_stream_flowctrl_t);
    sf_module->init = quic_stream_flowctrl_instance_init;
    sf_module->update_rwnd = quic_stream_flowctrl_instance_update_rwnd;
    sf_module->update_swnd = quic_stream_flowctrl_instance_update_swnd;
    sf_module->abandon = quic_stream_flowctrl_instance_abandon;
    sf_module->get_swnd = quic_stream_flowctrl_instance_get_swnd;
    sf_module->sent = quic_stream_flowctrl_instance_sent;
    sf_module->read = quic_stream_flowctrl_instance_read;
    sf_module->newly_blocked = quic_stream_flowctrl_instance_newly_blocked;
    sf_module->destory = NULL;

    return quic_err_success;
}

static quic_err_t quic_stream_flowctrl_instance_init(quic_stream_flowctrl_module_t *const module, void *const instance) {
    quic_stream_flowctrl_t *flowctrl = instance;
    quic_session_t *const session = quic_module_of_session(module);

    flowctrl->module = module;

    flowctrl->rwnd = session->cfg.stream_flowctrl_initial_rwnd;
    flowctrl->rwnd_size = session->cfg.stream_flowctrl_initial_rwnd;
    flowctrl->recv_off = 0;
    flowctrl->read_off = 0;
    flowctrl->fin_flag = false;

    flowctrl->swnd = session->cfg.stream_flowctrl_initial_swnd;
    flowctrl->sent_bytes = 0;

    flowctrl->last_blocked_at = 0;

    flowctrl->epoch_off = 0;
    flowctrl->epoch_time = 0;

    return quic_err_success;
}

static void quic_stream_flowctrl_instance_update_rwnd(void *const instance, const uint64_t off, const bool fin) {
    quic_stream_flowctrl_t *const flowctrl = instance;

    if (flowctrl->fin_flag && ((fin && off != flowctrl->recv_off) || off > flowctrl->recv_off)) {
        return;
    }
    flowctrl->fin_flag = flowctrl->fin_flag || fin;
    if (off <= flowctrl->recv_off) {
        return;
    }

    flowctrl->recv_off = off;

    // TODO influence connection flowctrl
}

static void quic_stream_flowctrl_instance_update_swnd(void *const instance, const uint64_t off) {
    quic_stream_flowctrl_t *const flowctrl = instance;

    if (off > flowctrl->swnd) {
        flowctrl->swnd= off;
    }
}

static void quic_stream_flowctrl_instance_abandon(void *const instance) {
    quic_stream_flowctrl_t *const flowctrl = instance;

    uint64_t unread_bytes = flowctrl->recv_off - flowctrl->read_off;
    if (unread_bytes > 0) {
        // TODO mark conn flowctrl read
    }
}

static uint64_t quic_stream_flowctrl_instance_get_swnd(void *const instance) {
    quic_stream_flowctrl_t *const flowctrl = instance;

    if (flowctrl->sent_bytes > flowctrl->swnd) {
        return 0;
    }

    return flowctrl->swnd - flowctrl->sent_bytes;
}

static void quic_stream_flowctrl_instance_sent(void *const instance, const uint64_t sent_bytes) {
    quic_stream_flowctrl_t *const flowctrl = instance;

    flowctrl->sent_bytes += sent_bytes;
}

static void quic_stream_flowctrl_instance_read(void *const instance, const uint64_t sid, const uint64_t readed_bytes) {
    quic_stream_flowctrl_t *const flowctrl = instance;
    quic_session_t *const session = quic_module_of_session(flowctrl->module);
    quic_stream_module_t *const s_module = quic_session_module(quic_stream_module_t, session, quic_stream_module);

    if (!flowctrl->read_off) {
        flowctrl->epoch_off = 0;
        flowctrl->epoch_time = quic_now();
    }

    flowctrl->read_off += readed_bytes;
    if (!flowctrl->fin_flag && (flowctrl->rwnd - flowctrl->read_off <= ((flowctrl->rwnd_size * 3) >> 2))) {
        quic_stream_flowctrl_adjust_rwnd(flowctrl);
        quic_stream_module_update_rwnd(s_module, sid);
    }

    // TODO conn flowctrl read
}

static bool quic_stream_flowctrl_instance_newly_blocked(uint64_t *const limit, void *const instance) {
    quic_stream_flowctrl_t *const flowctrl = instance;

    if (quic_stream_flowctrl_instance_get_swnd(instance) != 0 || flowctrl->swnd == flowctrl->last_blocked_at) {
        return false;
    }

    flowctrl->last_blocked_at = flowctrl->swnd;
    *limit = flowctrl->swnd;
    return true;
}

static inline void quic_stream_flowctrl_adjust_rwnd(quic_stream_flowctrl_t *const flowctrl) {
    quic_session_t *const session = quic_module_of_session(flowctrl->module);

    uint64_t in_epoch_readed_bytes = flowctrl->read_off - flowctrl->epoch_off;
    if (in_epoch_readed_bytes <= (flowctrl->rwnd_size >> 1) || !session->rtt.smoothed_rtt) {
        return;
    }

    uint64_t now = quic_now();
    if (now - flowctrl->epoch_time < (session->rtt.smoothed_rtt >> 2) * in_epoch_readed_bytes / flowctrl->rwnd_size) {
        uint64_t prev_rwnd_size = flowctrl->rwnd_size;
        flowctrl->rwnd_size = (flowctrl->rwnd_size >> 1) > session->cfg.stream_flowctrl_max_rwnd_size ? session->cfg.stream_flowctrl_max_rwnd_size : (flowctrl->rwnd_size >> 1);

        if (prev_rwnd_size < flowctrl->rwnd_size) {
            // TODO update conn flowctrl rwnd
        }
    }

    flowctrl->epoch_time = now;
    flowctrl->epoch_off = flowctrl->read_off;

    flowctrl->rwnd = flowctrl->read_off + flowctrl->rwnd_size;
}

quic_module_t quic_stream_flowctrl_module = {
    .module_size = sizeof(quic_stream_flowctrl_module_t),
    .init        = quic_stream_flowctrl_module_init,
    .process     = NULL,
    .loop        = NULL,
    .destory     = NULL
};
