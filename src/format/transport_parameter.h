/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_TRANSPORT_PARAMETER_H__
#define __OPENQUIC_TRANSPORT_PARAMETER_H__

#include <stdint.h>

typedef enum quic_transport_parameter_type_e quic_transport_parameter_type_t;
enum quic_transport_parameter_type_e {
    quic_trans_param_original_connid = 0x00,
    quic_trans_param_idle_timeout = 0x01,
    quic_trans_param_stateless_reset_token = 0x02,
    quic_trans_param_max_packet_size = 0x03,
    quic_trans_param_init_max_data = 0x04,
    quic_trans_param_init_max_stream_data_bidi_local = 0x05,
    quic_trans_param_init_max_stream_data_bidi_remote = 0x06,
    quic_trans_param_init_max_stream_data_uni = 0x07,
    quic_trans_param_init_max_stream_bidi = 0x08,
    quic_trans_param_init_max_stream_uni = 0x09,
    quic_trans_param_ack_delay_exponent = 0x0a,
    quic_trans_param_max_ack_delay = 0x0b,
    quic_trans_param_disable_migration = 0x0c,
    quic_trans_param_active_connid_limit = 0x0e,
};

#endif
