/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "modules/congestion.h"
#include "session.h"
#include "utils/time.h"
#include "utils/rbt.h"
#include <math.h>

typedef struct quic_congestion_base_s quic_congestion_base_t;
struct quic_congestion_base_s {
    uint64_t cwnd;

    bool acked;
    uint64_t largest_acked_num;
    uint64_t largest_sent_num;

    bool lost;
    uint64_t at_loss_largest_sent_num;
    bool at_loss_in_slowstart;

    uint64_t lost_pkt_count;
    uint64_t lost_bytes;
};

typedef struct quic_congestion_slowstart_s quic_congestion_slowstart_t;
struct quic_congestion_slowstart_s {
    uint64_t threshold;
    uint64_t end_num;
    uint64_t last_sent_num;
    bool started;

    uint64_t min_rtt;
    uint32_t rtt_sample_count;

    bool found_threshold;

    uint64_t min_exit_cwnd;
};

typedef struct quic_congestion_cubic_s quic_congestion_cubic_t;
struct quic_congestion_cubic_s {
    uint64_t epoch;
    uint64_t max_cwnd;
    uint64_t reno_cwnd;
    uint64_t origin_cwnd_point;
    uint64_t origin_time_point;
    uint32_t acked_bytes;
};

typedef struct quic_congestion_prr_s quic_congestion_prr_t;
struct quic_congestion_prr_s {
    uint64_t acked_count;
    uint64_t acked_bytes;
    uint64_t unacked_bytes;
    uint64_t sent_bytes;
};

typedef struct quic_congestion_tbp_s quic_congestion_tbp_t;
struct quic_congestion_tbp_s {
    uint64_t budget;
    uint64_t last_sent_time;
};

typedef struct quic_congestion_rtt_s quic_congestion_rtt_t;
struct quic_congestion_rtt_s {
    uint64_t min_rtt;
    uint64_t smoothed_rtt;
    uint64_t rttvar;
    uint64_t latest_simple;
};

typedef struct quic_congestion_status_store_s quic_congestion_status_store_t;
struct quic_congestion_status_store_s {
    QUIC_RBT_PATH_FIELDS

    quic_congestion_base_t base;
    quic_congestion_slowstart_t slowstart;
    quic_congestion_cubic_t cubic;
    quic_congestion_prr_t prr;
    quic_congestion_tbp_t tbp;
    quic_congestion_rtt_t rtt;
};

#define quic_congestion_status_store_insert(store, status) \
    quic_rbt_insert((store), (status), quic_rbt_path_comparer)

#define quic_congestion_status_store_find(store, key) \
    ((quic_congestion_status_store_t *) quic_rbt_find((store), (key), quic_rbt_path_key_comparer))

typedef struct quic_congestion_instance_s quic_congestion_instance_t;
struct quic_congestion_instance_s {
    quic_congestion_status_store_t *store;
    quic_congestion_status_store_t *active_instance;
};

#define quic_congestion_instance(module) ((quic_congestion_instance_t *) (module)->instance)

static inline uint64_t quic_congestion_delta_bandwidth(const uint64_t bytes, const uint64_t delta) {
    return bytes * 1000 * 1000 / delta * 8;
}

static quic_err_t quic_congestion_module_init(void *const module);

static quic_err_t quic_congestion_module_on_acked(quic_congestion_module_t *const module, const uint64_t num, const uint64_t acked_bytes, const uint64_t unacked_bytes, const uint64_t event_time);
static quic_err_t quic_congestion_module_on_sent(quic_congestion_module_t *const module, const uint64_t sent_time, const uint64_t num, const uint64_t sent_bytes, const bool included_unacked);
static quic_err_t quic_congestion_module_on_lost(quic_congestion_module_t *const module, const uint64_t num, const uint64_t lost_bytes, const uint64_t unacked_bytes);
static quic_err_t quic_congestion_module_update(quic_congestion_module_t *const module, const uint64_t recv_time, const uint64_t sent_time, const uint64_t delay);
static bool quic_congestion_module_allow_send(quic_congestion_module_t *const module, const uint64_t unacked_bytes);
static uint64_t quic_congestion_module_next_send_time(quic_congestion_module_t *const module, const uint64_t unacked_bytes);
static bool quic_congestion_module_has_budget(quic_congestion_module_t *const module);
static quic_err_t quic_congestion_module_migrate(quic_congestion_module_t *const module, const quic_path_t path);

static inline quic_err_t quic_congestion_module_increase_cwnd(quic_congestion_module_t *const module, const uint64_t acked_bytes, const uint64_t unacked_bytes, const uint64_t event_time);
static inline bool quic_congestion_module_cwnd_limited(quic_congestion_module_t *const module, const uint64_t unacked_bytes);

static inline quic_err_t quic_congestion_base_init(quic_congestion_module_t *const module, quic_congestion_status_store_t *const status);
static inline bool quic_congestion_in_recovery(quic_congestion_base_t *const module); 

static inline quic_err_t quic_congestion_slowstart_init(quic_congestion_module_t *const module, quic_congestion_status_store_t *const status);

static inline quic_err_t quic_congestion_cubic_init(quic_congestion_module_t *const module, quic_congestion_status_store_t *const status);
static inline uint64_t quic_congestion_cubic_on_acked(quic_congestion_cubic_t *const module, const uint64_t acked_bytes, const uint64_t cwnd, const uint64_t delay_min, const uint64_t event_time);
static inline uint64_t quic_congestion_cubic_on_lost(quic_congestion_cubic_t *const module, const uint64_t cwnd);

static inline quic_err_t quic_congestion_prr_init(quic_congestion_module_t *const module, quic_congestion_status_store_t *const status);
static inline quic_err_t quic_congestion_prr_on_lost(quic_congestion_prr_t *const module, const uint64_t unacked_bytes);
static inline bool quic_congestion_prr_allow_send(quic_congestion_prr_t *const module, const uint64_t cwnd, const uint64_t unacked_bytes, const uint64_t slowstart_threshold);

static inline uint64_t quic_congestion_tbp_max_burst_size(quic_congestion_module_t *const module);
static inline quic_err_t quic_congestion_tbp_init(quic_congestion_module_t *const module, quic_congestion_status_store_t *const status);
static inline uint64_t quic_congestion_tbp_bandwidth(quic_congestion_module_t *const tbp);
static inline quic_err_t quic_congestion_tbp_sent_packet(quic_congestion_module_t *const module, const uint64_t sent_time, const uint64_t bytes);
static inline uint64_t quic_congestion_tbp_budget(quic_congestion_module_t *const module, const uint64_t sent_time);
static inline uint64_t quic_congestion_tbp_next_send_time(quic_congestion_module_t *const module);

static inline quic_err_t quic_congestion_rtt_init(quic_congestion_module_t *const module, quic_congestion_status_store_t *const status);
static inline quic_err_t quic_congestion_rtt_update(quic_congestion_module_t *const module, const uint64_t recv_time, const uint64_t send_time, const uint64_t ack_delay);
static uint64_t quic_congestion_rtt_pto(quic_congestion_module_t *const module, const uint64_t max_ack_delay);
static uint64_t quic_congestion_rtt_smoothed_rtt(quic_congestion_module_t *const module);

static inline quic_err_t quic_congestion_instance_init(quic_congestion_module_t *const module);

static quic_err_t quic_congestion_module_init(void *const module) {
    quic_congestion_module_t *const c_module = module;

    c_module->on_acked = quic_congestion_module_on_acked;
    c_module->on_sent = quic_congestion_module_on_sent;
    c_module->on_lost = quic_congestion_module_on_lost;
    c_module->allow_send = quic_congestion_module_allow_send;
    c_module->update = quic_congestion_module_update;
    c_module->next_send_time = quic_congestion_module_next_send_time;

    c_module->has_budget = quic_congestion_module_has_budget;

    c_module->pto = quic_congestion_rtt_pto;
    c_module->smoothed_rtt = quic_congestion_rtt_smoothed_rtt;

    c_module->migrate = quic_congestion_module_migrate;

    quic_congestion_instance_init(c_module);

    return quic_err_success;
}

static inline quic_err_t quic_congestion_instance_init(quic_congestion_module_t *const module) {
    quic_rbt_tree_init(quic_congestion_instance(module)->store);
    quic_rbt_tree_init(quic_congestion_instance(module)->active_instance);

    return quic_err_success;
}

static quic_err_t quic_congestion_base_init(quic_congestion_module_t *const module, quic_congestion_status_store_t *const status) {
    quic_session_t *const session = quic_module_of_session(module);

    status->base.cwnd = session->cfg.initial_cwnd;

    status->base.acked = false;
    status->base.largest_acked_num = 0;
    status->base.largest_sent_num = 0;

    status->base.lost = false;
    status->base.at_loss_in_slowstart = false;
    status->base.at_loss_largest_sent_num = 0;

    status->base.lost_pkt_count = 0;
    status->base.lost_bytes = 0;

    return quic_err_success;
}

static inline bool quic_congestion_in_recovery(quic_congestion_base_t *const module) {
    return module->acked && module->lost && module->largest_acked_num <= module->at_loss_largest_sent_num;
}

static quic_err_t quic_congestion_slowstart_init(quic_congestion_module_t *const module, quic_congestion_status_store_t *const status) {
    quic_session_t *const session = quic_module_of_session(module);

    status->slowstart.threshold = session->cfg.max_cwnd;
    status->slowstart.end_num = 0;
    status->slowstart.last_sent_num = 0;
    status->slowstart.started = false;

    status->slowstart.min_rtt = 0;
    status->slowstart.rtt_sample_count = 0;

    status->slowstart.found_threshold = false;

    status->slowstart.min_exit_cwnd = 0;

    return quic_err_success;
}

static quic_err_t quic_congestion_prr_init(quic_congestion_module_t *const module, quic_congestion_status_store_t *const status) {
    (void) module;

    status->prr.acked_bytes = 0;
    status->prr.acked_count = 0;
    status->prr.unacked_bytes = 0;
    status->prr.sent_bytes = 0;

    return quic_err_success;
}

static inline quic_err_t quic_congestion_prr_on_lost(quic_congestion_prr_t *const module, const uint64_t unacked_bytes) {
    module->acked_bytes = 0;
    module->acked_count = 0;
    module->unacked_bytes = unacked_bytes;
    module->sent_bytes = 0;

    return quic_err_success;
}

static inline bool quic_congestion_prr_allow_send(quic_congestion_prr_t *const module, const uint64_t cwnd, const uint64_t unacked_bytes, const uint64_t slowstart_threshold) {
    if (module->sent_bytes == 0 || unacked_bytes < 1460) {
        return true;
    }

    if (cwnd > unacked_bytes) {
        return module->acked_bytes + module->acked_count * 1460 > module->sent_bytes;
    }
    return module->acked_bytes * slowstart_threshold > module->sent_bytes * module->unacked_bytes;
}

static inline quic_err_t quic_congestion_cubic_init(quic_congestion_module_t *const module, quic_congestion_status_store_t *const status) {
    (void) module;

    status->cubic.epoch = 0;
    status->cubic.max_cwnd = 0;
    status->cubic.reno_cwnd = 0;
    status->cubic.origin_cwnd_point = 0;
    status->cubic.origin_time_point = 0;
    status->cubic.acked_bytes = 0;

    return quic_err_success;
}

static inline uint64_t quic_congestion_cubic_on_acked(quic_congestion_cubic_t *const module, const uint64_t acked_bytes, const uint64_t cwnd, const uint64_t delay_min, const uint64_t event_time) {
    if (!module->epoch) {
        module->epoch = event_time;
        module->acked_bytes = acked_bytes;
        module->reno_cwnd = cwnd;
        if (module->max_cwnd <= cwnd) {
            module->origin_time_point = 0;
            module->origin_cwnd_point = cwnd;
        }
        else {
            module->origin_time_point = cbrt((1UL << 40) / (410 * 1460) * (module->max_cwnd - cwnd));
            module->origin_cwnd_point = module->max_cwnd;
        }
    }
    else {
        module->acked_bytes += acked_bytes;
    }

    uint64_t elapsed_time = ((event_time + delay_min - module->epoch) << 10) / (1000 * 1000);
    uint64_t offset = module->origin_time_point < elapsed_time ? elapsed_time - module->origin_time_point : module->origin_time_point - elapsed_time;
    uint64_t delta_cwnd = ((410 * offset * offset * offset) * 1460) >> 40;
    uint64_t ret = elapsed_time > module->origin_time_point ? module->origin_cwnd_point + delta_cwnd : module->origin_cwnd_point - delta_cwnd;

    ret = ret < cwnd + (module->acked_bytes >> 1) ? ret : cwnd + (module->acked_bytes >> 1);

    module->reno_cwnd += module->acked_bytes * 1460 * 9 / (17 * module->reno_cwnd);
    module->acked_bytes = 0;

    return ret > module->reno_cwnd ? ret : module->reno_cwnd;
}

static inline uint64_t quic_congestion_cubic_on_lost(quic_congestion_cubic_t *const module, const uint64_t cwnd) {
    if (cwnd + 1460 < module->max_cwnd) {
        module->max_cwnd = cwnd * 17 / 20;
    }
    else {
        module->max_cwnd = cwnd;
    }

    module->epoch = 0;

    return cwnd * 7 / 10;
}

static quic_err_t quic_congestion_module_on_sent(quic_congestion_module_t *const module, const uint64_t sent_time, const uint64_t num, const uint64_t sent_bytes, const bool included_unacked) {
    quic_congestion_status_store_t *const status = quic_congestion_instance(module)->active_instance;
    quic_congestion_base_t *const base = &status->base;
    quic_congestion_slowstart_t *const slowstart = &status->slowstart;
    quic_congestion_prr_t *const prr = &status->prr;

    quic_congestion_tbp_sent_packet(module, sent_time, sent_bytes);

    if (!included_unacked) {
        return quic_err_success;
    }

    if (quic_congestion_in_recovery(base)) {
        prr->sent_bytes += sent_bytes;
    }

    base->largest_sent_num = num;
    slowstart->last_sent_num = num;

    return quic_err_success;
}

static quic_err_t quic_congestion_module_on_lost(quic_congestion_module_t *const module, const uint64_t num, const uint64_t lost_bytes, const uint64_t unacked_bytes) {
    quic_session_t *const session = quic_module_of_session(module);
    quic_congestion_status_store_t *const status = quic_congestion_instance(module)->active_instance;
    quic_congestion_base_t *const base = &status->base;
    quic_congestion_slowstart_t *const slowstart = &status->slowstart;
    quic_congestion_prr_t *const prr = &status->prr;
    quic_congestion_cubic_t *const cubic = &status->cubic;

    if (base->lost && num <= base->at_loss_largest_sent_num) {
        if (base->at_loss_in_slowstart) {
            base->lost_pkt_count++;
            base->lost_bytes += lost_bytes;
            if (session->cfg.slowstart_large_reduction) {
                base->cwnd -= lost_bytes;
                base->cwnd = base->cwnd < slowstart->min_exit_cwnd ? slowstart->min_exit_cwnd : base->cwnd;
                slowstart->threshold = base->cwnd;
            }
        }
        return quic_err_success;
    }

    base->at_loss_in_slowstart = base->cwnd < slowstart->threshold;
    if (base->at_loss_in_slowstart) {
        base->lost_pkt_count++;
    }

    if (!session->cfg.disable_prr) {
        quic_congestion_prr_on_lost(prr, unacked_bytes);
    }

    if (session->cfg.slowstart_large_reduction && base->at_loss_in_slowstart) {
        if (base->cwnd >= 2 * session->cfg.initial_cwnd) {
            slowstart->min_exit_cwnd = base->cwnd / 2;
        }
        base->cwnd -= 1460;
    }
    else {
        base->cwnd = quic_congestion_cubic_on_lost(cubic, base->cwnd);
    }
    slowstart->threshold = base->cwnd;

    base->cwnd = base->cwnd < session->cfg.min_cwnd ? session->cfg.min_cwnd : base->cwnd;
    base->lost = true;
    base->at_loss_largest_sent_num = base->largest_sent_num;

    return quic_err_success;
}

static bool quic_congestion_module_allow_send(quic_congestion_module_t *const module, const uint64_t unacked_bytes) {
    quic_session_t *const session = quic_module_of_session(module);
    quic_congestion_status_store_t *const status = quic_congestion_instance(module)->active_instance;
    quic_congestion_base_t *const base = &status->base;
    quic_congestion_prr_t *const prr = &status->prr;
    quic_congestion_slowstart_t *const slowstart = &status->slowstart;

    if (!session->cfg.disable_prr && quic_congestion_in_recovery(base)) {
        return quic_congestion_prr_allow_send(prr, base->cwnd, unacked_bytes, slowstart->threshold);
    }
    return unacked_bytes < base->cwnd;
}

static quic_err_t quic_congestion_module_on_acked(quic_congestion_module_t *const module, const uint64_t num, const uint64_t acked_bytes, const uint64_t unacked_bytes, const uint64_t event_time) {
    quic_session_t *const session = quic_module_of_session(module);
    quic_congestion_status_store_t *const status = quic_congestion_instance(module)->active_instance;
    quic_congestion_base_t *const base = &status->base;
    quic_congestion_prr_t *const prr = &status->prr;
    quic_congestion_slowstart_t *const slowstart = &status->slowstart;

    if (!base->acked) {
        base->acked = true;
        base->largest_acked_num = num;
    }
    else if (base->largest_acked_num < num) {
        base->largest_acked_num = num;
    }

    if (quic_congestion_in_recovery(base)) {
        if (!session->cfg.disable_prr) {
            prr->acked_bytes += acked_bytes;
            prr->acked_count++;
        }
        return quic_err_success;
    }

    quic_congestion_module_increase_cwnd(module, acked_bytes, unacked_bytes, event_time);
    if (base->cwnd < slowstart->threshold && slowstart->end_num < num) {
        slowstart->started = false;
    }

    return quic_err_success;
}

static inline quic_err_t quic_congestion_module_increase_cwnd(quic_congestion_module_t *const module, const uint64_t acked_bytes, const uint64_t unacked_bytes, const uint64_t event_time) {
    quic_congestion_status_store_t *const status = quic_congestion_instance(module)->active_instance;
    quic_congestion_base_t *const base = &status->base;
    quic_congestion_cubic_t *const cubic = &status->cubic;
    quic_congestion_slowstart_t *const slowstart = &status->slowstart;
    quic_congestion_rtt_t *const rtt = &status->rtt;
    quic_session_t *const session = quic_module_of_session(module);

    if (!quic_congestion_module_cwnd_limited(module, unacked_bytes)) {
        cubic->epoch = 0;
        return quic_err_success;
    }

    if (base->cwnd >= session->cfg.max_cwnd) {
        return quic_err_success;
    }

    if (base->cwnd < slowstart->threshold) {
        base->cwnd += 1460;
        return quic_err_success;
    }
    base->cwnd = quic_congestion_cubic_on_acked(cubic, acked_bytes, base->cwnd, rtt->min_rtt, event_time);
    base->cwnd = base->cwnd > session->cfg.max_cwnd ? session->cfg.max_cwnd : base->cwnd;

    return quic_err_success;
}

static inline bool quic_congestion_module_cwnd_limited(quic_congestion_module_t *const module, const uint64_t unacked_bytes) {
    quic_congestion_status_store_t *const status = quic_congestion_instance(module)->active_instance;
    quic_congestion_base_t *const base = &status->base;
    quic_congestion_slowstart_t *const slowstart = &status->slowstart;

    if (unacked_bytes >= base->cwnd) {
        return true;
    }

    return (base->cwnd < slowstart->threshold && unacked_bytes > base->cwnd / 2) || (base->cwnd - unacked_bytes) <= 3 * 1460;
}

static inline quic_err_t quic_congestion_tbp_init(quic_congestion_module_t *const module, quic_congestion_status_store_t *const status) {
    (void) module;

    status->tbp.budget = quic_congestion_tbp_bandwidth(module);
    status->tbp.last_sent_time = 0;

    return quic_err_success;
}

static inline uint64_t quic_congestion_tbp_max_burst_size(quic_congestion_module_t *const module) {
    uint64_t burst_size = 2000 * quic_congestion_tbp_bandwidth(module) / 1000000;
    return burst_size > 14600 ? burst_size : 14600;
}

static inline uint64_t quic_congestion_tbp_bandwidth(quic_congestion_module_t *const module) {
    quic_congestion_status_store_t *const status = quic_congestion_instance(module)->active_instance;
    quic_congestion_base_t *const base = &status->base;
    quic_congestion_rtt_t *const rtt = &status->rtt;

    if (rtt->smoothed_rtt == 0) {
        return ~0;
    }
    return (base->cwnd * 1000 * 1000 / rtt->smoothed_rtt * 5) >> 2;
}

static inline quic_err_t quic_congestion_tbp_sent_packet(quic_congestion_module_t *const module, const uint64_t sent_time, const uint64_t bytes) {
    quic_congestion_status_store_t *const status = quic_congestion_instance(module)->active_instance;
    quic_congestion_tbp_t *const tbp = &status->tbp;

    uint64_t budget = quic_congestion_tbp_budget(module, sent_time);
    if (bytes > budget) {
        tbp->budget = 0;
    }
    else {
        tbp->budget = budget - bytes;
    } 
    tbp->last_sent_time = sent_time;

    return quic_err_success;
}

static inline uint64_t quic_congestion_tbp_budget(quic_congestion_module_t *const module, const uint64_t sent_time) {
    quic_congestion_status_store_t *const status = quic_congestion_instance(module)->active_instance;
    quic_congestion_tbp_t *const tbp = &status->tbp;

    uint64_t max_burst_size = quic_congestion_tbp_max_burst_size(module);
    if (tbp->last_sent_time == 0) {
        return max_burst_size;
    }
    uint64_t budget = tbp->budget + quic_congestion_tbp_bandwidth(module) * (sent_time - tbp->last_sent_time) / 1000000;

    return max_burst_size < budget ? max_burst_size : budget;
}

static inline uint64_t quic_congestion_tbp_next_send_time(quic_congestion_module_t *const module) {
    quic_congestion_status_store_t *const status = quic_congestion_instance(module)->active_instance;
    quic_congestion_tbp_t *const tbp = &status->tbp;

    if (tbp->budget >= 14600) {
        return 0;
    }
    uint64_t delta = ceil((14600 - tbp->budget) * 1000000 / quic_congestion_tbp_bandwidth(module));
    return tbp->last_sent_time + (delta > 1000 ? delta : 1000);
}

static inline quic_err_t quic_congestion_rtt_init(quic_congestion_module_t *const module, quic_congestion_status_store_t *const status) {
    (void) module;

    status->rtt.min_rtt = 0;
    status->rtt.smoothed_rtt = 333 * 1000;
    status->rtt.rttvar = 333 * 1000 >> 2;
    status->rtt.latest_simple = 0;

    return quic_err_success;
}

static inline quic_err_t quic_congestion_rtt_update(quic_congestion_module_t *const module, const uint64_t recv_time, const uint64_t send_time, const uint64_t ack_delay) {
    quic_congestion_status_store_t *const status = quic_congestion_instance(module)->active_instance;
    quic_congestion_rtt_t *const rtt = &status->rtt;

    const uint64_t latest_rtt = recv_time - send_time;

    if (rtt->min_rtt == 0) {
        rtt->min_rtt = latest_rtt;
        rtt->smoothed_rtt = latest_rtt;
        rtt->rttvar = latest_rtt / 2;
    }
    else {
        if (rtt->min_rtt > latest_rtt) {
            rtt->min_rtt = latest_rtt;
        }
        uint64_t adjusted_rtt = latest_rtt;
        if (rtt->min_rtt + ack_delay < latest_rtt) {
            adjusted_rtt -= ack_delay;
        }
        rtt->latest_simple = adjusted_rtt;
        rtt->smoothed_rtt = (7 * rtt->smoothed_rtt + adjusted_rtt) >> 3;
#define __abs_distance__(a, b) ((a) > (b) ? ((a) - (b)) : ((b) - (a)))
        uint64_t rttvar_simple = __abs_distance__(latest_rtt, adjusted_rtt);
#undef __abs_distance__
        rtt->rttvar = (3 * rtt->rttvar + rttvar_simple) >> 2;
    }

    return quic_err_success;
}

static uint64_t quic_congestion_rtt_pto(quic_congestion_module_t *const module, const uint64_t max_ack_delay) {
    quic_congestion_status_store_t *const status = quic_congestion_instance(module)->active_instance;
    quic_congestion_rtt_t *const rtt = &status->rtt;

#define __max__(a, b) ((a) > (b) ? (a) : (b))
    return rtt->smoothed_rtt + __max__(rtt->rttvar << 2, 1000) + max_ack_delay;
#undef __max__
}

static uint64_t quic_congestion_rtt_smoothed_rtt(quic_congestion_module_t *const module) {
    quic_congestion_status_store_t *const status = quic_congestion_instance(module)->active_instance;
    quic_congestion_rtt_t *const rtt = &status->rtt;

    return rtt->smoothed_rtt;
}

static quic_err_t quic_congestion_module_update(quic_congestion_module_t *const module, const uint64_t recv_time, const uint64_t sent_time, const uint64_t delay) {
    quic_congestion_status_store_t *const status = quic_congestion_instance(module)->active_instance;
    quic_congestion_base_t *const base = &status->base;
    quic_congestion_slowstart_t *const slowstart = &status->slowstart;
    quic_congestion_rtt_t *const rtt = &status->rtt;

    quic_congestion_rtt_update(module, recv_time, sent_time, delay);

    if (base->cwnd >= slowstart->threshold) {
        return quic_err_success;
    }

    // is in the slow start phase
    if (!slowstart->started) {
        slowstart->started = true;
        slowstart->end_num = slowstart->last_sent_num;
        slowstart->min_rtt = 0;
        slowstart->rtt_sample_count = 0;
    }

    if (slowstart->found_threshold) {
        slowstart->threshold = base->cwnd;
        return quic_err_success;
    }

    slowstart->rtt_sample_count++;
    if (slowstart->rtt_sample_count <= 8 && (slowstart->min_rtt == 0 || slowstart->min_rtt > rtt->latest_simple)) {
        slowstart->min_rtt = rtt->latest_simple;
    }
    if (slowstart->rtt_sample_count == 8) {
        uint64_t inc_threhold = rtt->min_rtt >> 3;
        inc_threhold = inc_threhold < 16000 ? inc_threhold : 1600;
        inc_threhold = inc_threhold < 4000 ? 4000 : inc_threhold;

        if (slowstart->min_rtt > rtt->min_rtt + inc_threhold) {
            slowstart->found_threshold = true;
        }
    }

    if (base->cwnd / 1460 >= 16 && slowstart->found_threshold) {
        slowstart->threshold = base->cwnd;
    }

    return quic_err_success;
}

static uint64_t quic_congestion_module_next_send_time(quic_congestion_module_t *const module, const uint64_t unacked_bytes) {
    (void) unacked_bytes;

    return quic_congestion_tbp_next_send_time(module);
}

static bool quic_congestion_module_has_budget(quic_congestion_module_t *const module) {
    return quic_congestion_tbp_budget(module, quic_now()) >= 14600;
}

static quic_err_t quic_congestion_module_migrate(quic_congestion_module_t *const module, const quic_path_t key) {
    quic_congestion_instance_t *const instance = quic_congestion_instance(module);
    quic_congestion_status_store_t *store = quic_congestion_status_store_find(instance->store, &key);
    if (quic_rbt_is_nil(store)) {
        store = malloc(sizeof(quic_congestion_status_store_t));
        if (!store) {
            return quic_err_internal_error;
        }
        quic_rbt_init(store);
        store->key = key;

        quic_congestion_base_init(module, store);
        quic_congestion_slowstart_init(module, store);
        quic_congestion_cubic_init(module, store);
        quic_congestion_prr_init(module, store);
        quic_congestion_tbp_init(module, store);
        quic_congestion_rtt_init(module, store);

        quic_congestion_status_store_insert(&instance->store, store);
    }
    instance->active_instance = store;

    return quic_err_success;
}

quic_module_t quic_congestion_module = {
    .name        = "congestion",
    .module_size = sizeof(quic_congestion_module_t) + sizeof(quic_congestion_instance_t),
    .init        = quic_congestion_module_init,
    .start       = NULL,
    .process     = NULL,
    .loop        = NULL,
    .destory     = NULL
};
