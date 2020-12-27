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

typedef struct quic_congestion_status_store_s quic_congestion_status_store_t;
struct quic_congestion_status_store_s {
    QUIC_RBT_UINT64_FIELDS

    quic_congestion_base_t base;
    quic_congestion_slowstart_t slowstart;
    quic_congestion_cubic_t cubic;
    quic_congestion_prr_t prr;
    quic_congestion_tbp_t tbp;
};

#define quic_congestion_status_store_insert(store, status) \
    quic_rbt_insert((store), (status), quic_rbt_uint64_comparer);

#define quic_congestion_status_store_find(store, status) \
    ((quic_congestion_status_store_t *) quic_rbt_find((store), (status), quic_rbt_uint64_key_comparer))

typedef struct quic_congestion_instance_s quic_congestion_instance_t;
struct quic_congestion_instance_s {
    quic_congestion_base_t base;
    quic_congestion_slowstart_t slowstart;
    quic_congestion_cubic_t cubic;
    quic_congestion_prr_t prr;
    quic_congestion_tbp_t tbp;
    uint64_t id;

    uint64_t id_counter;
    quic_congestion_status_store_t *store;
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
static uint64_t quic_congestion_module_id(quic_congestion_module_t *const module);
static quic_err_t quic_congestion_module_store(quic_congestion_module_t *const module);
static quic_err_t quic_congestion_module_restore(quic_congestion_module_t *const module, const uint64_t id);
static quic_err_t quic_congestion_module_new_instance(quic_congestion_module_t *const module);

static inline quic_err_t quic_congestion_module_increase_cwnd(quic_congestion_module_t *const module, const uint64_t acked_bytes, const uint64_t unacked_bytes, const uint64_t event_time);
static inline bool quic_congestion_module_cwnd_limited(quic_congestion_module_t *const module, const uint64_t unacked_bytes);

static inline quic_err_t quic_congestion_base_init(quic_congestion_module_t *const module);
static inline bool quic_congestion_in_recovery(quic_congestion_base_t *const module); 

static inline quic_err_t quic_congestion_slowstart_init(quic_congestion_module_t *const module);

static inline quic_err_t quic_congestion_cubic_init(quic_congestion_module_t *const module);
static inline uint64_t quic_congestion_cubic_on_acked(quic_congestion_cubic_t *const module, const uint64_t acked_bytes, const uint64_t cwnd, const uint64_t delay_min, const uint64_t event_time);
static inline uint64_t quic_congestion_cubic_on_lost(quic_congestion_cubic_t *const module, const uint64_t cwnd);

static inline quic_err_t quic_congestion_prr_init(quic_congestion_module_t *const module);
static inline quic_err_t quic_congestion_prr_on_lost(quic_congestion_prr_t *const module, const uint64_t unacked_bytes);
static inline bool quic_congestion_prr_allow_send(quic_congestion_prr_t *const module, const uint64_t cwnd, const uint64_t unacked_bytes, const uint64_t slowstart_threshold);

static inline uint64_t quic_congestion_tbp_max_burst_size(quic_congestion_module_t *const module);
static inline quic_err_t quic_congestion_tbp_init(quic_congestion_module_t *const module);
static inline uint64_t quic_congestion_tbp_bandwidth(quic_congestion_module_t *const tbp);
static inline quic_err_t quic_congestion_tbp_sent_packet(quic_congestion_module_t *const module, const uint64_t sent_time, const uint64_t bytes);
static inline uint64_t quic_congestion_tbp_budget(quic_congestion_module_t *const module, const uint64_t sent_time);
static inline uint64_t quic_congestion_tbp_next_send_time(quic_congestion_module_t *const module);

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

    c_module->id = quic_congestion_module_id;
    c_module->store = quic_congestion_module_store;
    c_module->restore = quic_congestion_module_restore;
    c_module->new_instance = quic_congestion_module_new_instance;

    quic_congestion_instance_init(c_module);

    return quic_err_success;
}

static inline quic_err_t quic_congestion_instance_init(quic_congestion_module_t *const module) {
    quic_congestion_instance(module)->id = 0;
    quic_congestion_instance(module)->id_counter = 0;
    quic_rbt_tree_init(quic_congestion_instance(module)->store);

    quic_congestion_module_new_instance(module);

    return quic_err_success;
}

static quic_err_t quic_congestion_base_init(quic_congestion_module_t *const module) {
    quic_congestion_base_t *const base = &quic_congestion_instance(module)->base;
    quic_session_t *const session = quic_module_of_session(module);

    base->cwnd = session->cfg.initial_cwnd;

    base->acked = false;
    base->largest_acked_num = 0;
    base->largest_sent_num = 0;

    base->lost = false;
    base->at_loss_in_slowstart = false;
    base->at_loss_largest_sent_num = 0;

    base->lost_pkt_count = 0;
    base->lost_bytes = 0;

    return quic_err_success;
}

static inline bool quic_congestion_in_recovery(quic_congestion_base_t *const module) {
    return module->acked && module->lost && module->largest_acked_num <= module->at_loss_largest_sent_num;
}

static quic_err_t quic_congestion_slowstart_init(quic_congestion_module_t *const module) {
    quic_congestion_slowstart_t *const slowstart = &quic_congestion_instance(module)->slowstart;
    quic_session_t *const session = quic_module_of_session(module);

    slowstart->threshold = session->cfg.max_cwnd;
    slowstart->end_num = 0;
    slowstart->last_sent_num = 0;
    slowstart->started = false;

    slowstart->min_rtt = 0;
    slowstart->rtt_sample_count = 0;

    slowstart->found_threshold = false;

    slowstart->min_exit_cwnd = 0;

    return quic_err_success;
}

static quic_err_t quic_congestion_prr_init(quic_congestion_module_t *const module) {
    quic_congestion_prr_t *const prr = &quic_congestion_instance(module)->prr;

    prr->acked_bytes = 0;
    prr->acked_count = 0;
    prr->unacked_bytes = 0;
    prr->sent_bytes = 0;

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

static inline quic_err_t quic_congestion_cubic_init(quic_congestion_module_t *const module) {
    quic_congestion_cubic_t *const cubic = &quic_congestion_instance(module)->cubic;

    cubic->epoch = 0;
    cubic->max_cwnd = 0;
    cubic->reno_cwnd = 0;
    cubic->origin_cwnd_point = 0;
    cubic->origin_time_point = 0;
    cubic->acked_bytes = 0;

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
    quic_congestion_tbp_sent_packet(module, sent_time, sent_bytes);

    if (!included_unacked) {
        return quic_err_success;
    }

    if (quic_congestion_in_recovery(&quic_congestion_instance(module)->base)) {
        quic_congestion_instance(module)->prr.sent_bytes += sent_bytes;
    }

    quic_congestion_instance(module)->base.largest_sent_num = num;
    quic_congestion_instance(module)->slowstart.last_sent_num = num;

    return quic_err_success;
}

static quic_err_t quic_congestion_module_on_lost(quic_congestion_module_t *const module, const uint64_t num, const uint64_t lost_bytes, const uint64_t unacked_bytes) {
    quic_session_t *const session = quic_module_of_session(module);
    quic_congestion_base_t *const base = &quic_congestion_instance(module)->base;
    quic_congestion_slowstart_t *const slowstart = &quic_congestion_instance(module)->slowstart;

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
        quic_congestion_prr_on_lost(&quic_congestion_instance(module)->prr, unacked_bytes);
    }

    if (session->cfg.slowstart_large_reduction && base->at_loss_in_slowstart) {
        if (base->cwnd >= 2 * session->cfg.initial_cwnd) {
            slowstart->min_exit_cwnd = base->cwnd / 2;
        }
        base->cwnd -= 1460;
    }
    else {
        base->cwnd = quic_congestion_cubic_on_lost(&quic_congestion_instance(module)->cubic, base->cwnd);
    }
    slowstart->threshold = base->cwnd;

    base->cwnd = base->cwnd < session->cfg.min_cwnd ? session->cfg.min_cwnd : base->cwnd;
    base->lost = true;
    base->at_loss_largest_sent_num = base->largest_sent_num;

    return quic_err_success;
}

static bool quic_congestion_module_allow_send(quic_congestion_module_t *const module, const uint64_t unacked_bytes) {
    quic_session_t *const session = quic_module_of_session(module);

    if (!session->cfg.disable_prr && quic_congestion_in_recovery(&quic_congestion_instance(module)->base)) {
        return quic_congestion_prr_allow_send(&quic_congestion_instance(module)->prr,
                                              quic_congestion_instance(module)->base.cwnd,
                                              unacked_bytes,
                                              quic_congestion_instance(module)->slowstart.threshold);
    }
    return unacked_bytes < quic_congestion_instance(module)->base.cwnd;
}

static quic_err_t quic_congestion_module_on_acked(quic_congestion_module_t *const module, const uint64_t num, const uint64_t acked_bytes, const uint64_t unacked_bytes, const uint64_t event_time) {
    quic_session_t *const session = quic_module_of_session(module);
    quic_congestion_base_t *const base = &quic_congestion_instance(module)->base;
    quic_congestion_prr_t *const prr = &quic_congestion_instance(module)->prr;
    quic_congestion_slowstart_t *const slowstart = &quic_congestion_instance(module)->slowstart;

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
    quic_congestion_base_t *const base = &quic_congestion_instance(module)->base;
    quic_session_t *const session = quic_module_of_session(module);

    if (!quic_congestion_module_cwnd_limited(module, unacked_bytes)) {
        quic_congestion_instance(module)->cubic.epoch = 0;
        return quic_err_success;
    }

    if (base->cwnd >= session->cfg.max_cwnd) {
        return quic_err_success;
    }

    if (base->cwnd < quic_congestion_instance(module)->slowstart.threshold) {
        base->cwnd += 1460;
        return quic_err_success;
    }
    base->cwnd = quic_congestion_cubic_on_acked(&quic_congestion_instance(module)->cubic, acked_bytes, base->cwnd, session->rtt.min_rtt, event_time);
    base->cwnd = base->cwnd > session->cfg.max_cwnd ? session->cfg.max_cwnd : base->cwnd;
    return quic_err_success;
}

static inline bool quic_congestion_module_cwnd_limited(quic_congestion_module_t *const module, const uint64_t unacked_bytes) {
    quic_congestion_base_t *const base = &quic_congestion_instance(module)->base;
    quic_congestion_slowstart_t *const slowstart = &quic_congestion_instance(module)->slowstart;

    if (unacked_bytes >= quic_congestion_instance(module)->base.cwnd) {
        return true;
    }

    return (base->cwnd < slowstart->threshold && unacked_bytes > base->cwnd / 2) || (base->cwnd - unacked_bytes) <= 3 * 1460;
}

static inline quic_err_t quic_congestion_tbp_init(quic_congestion_module_t *const module) {
    quic_congestion_tbp_t *const tbp = &quic_congestion_instance(module)->tbp;

    tbp->budget = quic_congestion_tbp_bandwidth(module);
    tbp->last_sent_time = 0;

    return quic_err_success;
}

static inline uint64_t quic_congestion_tbp_max_burst_size(quic_congestion_module_t *const module) {
    uint64_t burst_size = 2000 * quic_congestion_tbp_bandwidth(module) / 1000000;
    return burst_size > 14600 ? burst_size : 14600;
}

static inline uint64_t quic_congestion_tbp_bandwidth(quic_congestion_module_t *const module) {
    quic_congestion_base_t *const base = &quic_congestion_instance(module)->base;
    quic_session_t *const session = quic_module_of_session(module);

    if (session->rtt.smoothed_rtt == 0) {
        return ~0;
    }
    return (base->cwnd * 1000 * 1000 / session->rtt.smoothed_rtt * 5) >> 2;
}

static inline quic_err_t quic_congestion_tbp_sent_packet(quic_congestion_module_t *const module, const uint64_t sent_time, const uint64_t bytes) {
    quic_congestion_tbp_t *const tbp = &quic_congestion_instance(module)->tbp;
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
    quic_congestion_tbp_t *const tbp = &quic_congestion_instance(module)->tbp;
    uint64_t max_burst_size = quic_congestion_tbp_max_burst_size(module);
    if (tbp->last_sent_time == 0) {
        return max_burst_size;
    }
    uint64_t budget = tbp->budget + quic_congestion_tbp_bandwidth(module) * (sent_time - tbp->last_sent_time) / 1000000;

    return max_burst_size < budget ? max_burst_size : budget;
}

static inline uint64_t quic_congestion_tbp_next_send_time(quic_congestion_module_t *const module) {
    quic_congestion_tbp_t *const tbp = &quic_congestion_instance(module)->tbp;
    if (tbp->budget >= 14600) {
        return 0;
    }
    uint64_t delta = ceil((14600 - tbp->budget) * 1000000 / quic_congestion_tbp_bandwidth(module));
    return tbp->last_sent_time + (delta > 1000 ? delta : 1000);
}

static quic_err_t quic_congestion_module_update(quic_congestion_module_t *const module, const uint64_t recv_time, const uint64_t sent_time, const uint64_t delay) {
    quic_session_t *const session = quic_module_of_session(module);
    quic_congestion_base_t *const base = &quic_congestion_instance(module)->base;
    quic_congestion_slowstart_t *const slowstart = &quic_congestion_instance(module)->slowstart;

    quic_rtt_update(&session->rtt, recv_time, sent_time, delay);

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
    if (slowstart->rtt_sample_count <= 8 && (slowstart->min_rtt == 0 || slowstart->min_rtt > session->rtt.latest_simple)) {
        slowstart->min_rtt = session->rtt.latest_simple;
    }
    if (slowstart->rtt_sample_count == 8) {
        uint64_t inc_threhold = session->rtt.min_rtt >> 3;
        inc_threhold = inc_threhold < 16000 ? inc_threhold : 1600;
        inc_threhold = inc_threhold < 4000 ? 4000 : inc_threhold;

        if (slowstart->min_rtt > session->rtt.min_rtt + inc_threhold) {
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

static uint64_t quic_congestion_module_id(quic_congestion_module_t *const module) {
    return quic_congestion_instance(module)->id;
}

static quic_err_t quic_congestion_module_store(quic_congestion_module_t *const module) {
    quic_congestion_instance_t *const instance = quic_congestion_instance(module);
    quic_congestion_status_store_t *store = quic_congestion_status_store_find(instance->store, &instance->id);
    if (quic_rbt_is_nil(store)) {
        store = malloc(sizeof(quic_congestion_status_store_t));
        quic_rbt_init(store);
        store->key = instance->id;

        quic_congestion_status_store_insert(&instance->store, store);
    }

    store->base = instance->base;
    store->slowstart = instance->slowstart;
    store->cubic = instance->cubic;
    store->prr = instance->prr;
    store->tbp = instance->tbp;

    return quic_err_success;
}

static quic_err_t quic_congestion_module_restore(quic_congestion_module_t *const module, const uint64_t id) {
    quic_congestion_instance_t *const instance = quic_congestion_instance(module);
    quic_congestion_status_store_t *store = quic_congestion_status_store_find(instance->store, &id);
    if (quic_rbt_is_nil(store)) {
        return quic_err_internal_error;
    }

    instance->id = store->key;
    instance->base = store->base;
    instance->slowstart = store->slowstart;
    instance->cubic = store->cubic;
    instance->prr = store->prr;
    instance->tbp = store->tbp;

    return quic_err_success;
}

static quic_err_t quic_congestion_module_new_instance(quic_congestion_module_t *const module) {
    quic_congestion_instance(module)->id = quic_congestion_instance(module)->id_counter++;

    quic_congestion_base_init(module);
    quic_congestion_slowstart_init(module);
    quic_congestion_cubic_init(module);
    quic_congestion_prr_init(module);
    quic_congestion_tbp_init(module);

    return quic_err_success;
}

quic_module_t quic_congestion_module = {
    .name        = "congestion",
    .module_size = sizeof(quic_congestion_module_t) + sizeof(quic_congestion_instance_t),
    .init        = quic_congestion_module_init,
    .process     = NULL,
    .loop        = NULL,
    .destory     = NULL
};
