/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_TRANSPORT_PARAMETER_H__
#define __OPENQUIC_TRANSPORT_PARAMETER_H__

#include "utils/buf.h"
#include "utils/varint.h"
#include "utils/errno.h"
#include <stdint.h>

typedef enum quic_transport_parameter_type_e quic_transport_parameter_type_t;
enum quic_transport_parameter_type_e {
    quic_trans_param_original_connid = 0x00,
    quic_trans_param_idle_timeout = 0x01,
    quic_trans_param_stateless_reset_token = 0x02,
    quic_trans_param_max_packet_size = 0x03,
    quic_trans_param_max_data = 0x04,
    quic_trans_param_max_stream_data_bidi_local = 0x05,
    quic_trans_param_max_stream_data_bidi_remote = 0x06,
    quic_trans_param_max_stream_data_uni = 0x07,
    quic_trans_param_max_stream_bidi = 0x08,
    quic_trans_param_max_stream_uni = 0x09,
    quic_trans_param_ack_delay_exponent = 0x0a,
    quic_trans_param_max_ack_delay = 0x0b,
    quic_trans_param_disable_migration = 0x0c,
    quic_trans_param_active_connid_limit = 0x0e,
};

typedef struct quic_transport_parameter_s quic_transport_parameter_t;
struct quic_transport_parameter_s {
    quic_buf_t original_connid;
    uint64_t idle_timeout;
    quic_buf_t stateless_reset_token;
    uint64_t max_pkt_size;
    uint64_t max_data;
    uint64_t max_stream_data_bidi_local;
    uint64_t max_stream_data_bidi_remote;
    uint64_t max_stream_data_uni;
    uint64_t max_stream_bidi;
    uint64_t max_stream_uni;
    uint8_t ack_delay_exponent;
    uint64_t max_ack_delay;
    bool disable_migration;
    uint64_t active_connid;
};

#define QUIC_TRANS_PARAM_ACK_DELAY_EXPONENT_DEFAULT 3
#define QUIC_TRANS_PARAM_MAX_ACK_DELAY_DEFAULT 25000

static inline quic_err_t quic_transport_parameter_init(quic_transport_parameter_t *const params) {
    quic_buf_init(&params->original_connid);
    params->idle_timeout = 0;
    quic_buf_init(&params->stateless_reset_token);
    params->max_pkt_size = 0;
    params->max_data = 0;
    params->max_stream_data_bidi_local = 0;
    params->max_stream_data_bidi_remote = 0;
    params->max_stream_data_uni = 0;
    params->max_stream_bidi = 0;
    params->max_stream_uni = 0;
    params->ack_delay_exponent = QUIC_TRANS_PARAM_ACK_DELAY_EXPONENT_DEFAULT;
    params->max_ack_delay = QUIC_TRANS_PARAM_MAX_ACK_DELAY_DEFAULT;
    params->disable_migration = false;
    params->active_connid = 0;
    
    return quic_err_success;
}

static inline size_t quic_transport_parameter_size(quic_transport_parameter_t *const params) {
    return 2
        + 4 + quic_varint_format_len(params->idle_timeout)
        + 4 + quic_varint_format_len(params->max_pkt_size)
        + 4 + quic_varint_format_len(params->max_data)
        + 4 + quic_varint_format_len(params->max_stream_data_bidi_local)
        + 4 + quic_varint_format_len(params->max_stream_data_bidi_remote)
        + 4 + quic_varint_format_len(params->max_stream_data_uni)
        + 4 + quic_varint_format_len(params->max_stream_bidi)
        + 4 + quic_varint_format_len(params->max_stream_uni)
        + 4 + quic_varint_format_len(params->max_ack_delay)
        + 4 + quic_varint_format_len((uint64_t) params->ack_delay_exponent)
        + 4 + quic_varint_format_len(params->active_connid / 1000)
        + (params->disable_migration ? 4 : 0)
        + (quic_buf_size(&params->stateless_reset_token) != 0 ? 4 + quic_buf_size(&params->stateless_reset_token) : 0)
        + (quic_buf_size(&params->original_connid) != 0 ? 4 + quic_buf_size(&params->original_connid) : 0);
}

#endif
