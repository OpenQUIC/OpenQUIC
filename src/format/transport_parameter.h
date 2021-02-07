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

static inline size_t quic_transport_parameter_size(const quic_transport_parameter_t params) {
    return 2
        + 4 + quic_varint_format_len(params.idle_timeout)
        + 4 + quic_varint_format_len(params.max_pkt_size)
        + 4 + quic_varint_format_len(params.max_data)
        + 4 + quic_varint_format_len(params.max_stream_data_bidi_local)
        + 4 + quic_varint_format_len(params.max_stream_data_bidi_remote)
        + 4 + quic_varint_format_len(params.max_stream_data_uni)
        + 4 + quic_varint_format_len(params.max_stream_bidi)
        + 4 + quic_varint_format_len(params.max_stream_uni)
        + 4 + quic_varint_format_len(params.max_ack_delay)
        + 4 + quic_varint_format_len((uint64_t) params.ack_delay_exponent)
        + 4 + quic_varint_format_len(params.active_connid / 1000)
        + (params.disable_migration ? 4 : 0)
        + (quic_buf_size(&params.stateless_reset_token) != 0 ? 4 + quic_buf_size(&params.stateless_reset_token) : 0)
        + (quic_buf_size(&params.original_connid) != 0 ? 4 + quic_buf_size(&params.original_connid) : 0);
}

static inline bool quic_transport_parameter_varint_format(quic_buf_t *const buf, uint16_t id, uint64_t value) {
    uint16_t varint_len = quic_varint_format_len(value);
    if (buf->buf + buf->capa < buf->pos + 4 + varint_len) {
        return false;
    }

    *((uint16_t *) buf->pos) = bswap_16(id);
    buf->pos += 2;
    *((uint16_t *) buf->pos) = bswap_16(varint_len);
    buf->pos += 2;

    quic_varint_format_r(buf, value);

    return true;
}

static inline bool quic_transport_parameter_string_format(quic_buf_t *const buf, uint16_t id, quic_buf_t value) {
    if (quic_buf_size(&value)) {
        if (buf->buf + buf->capa < buf->pos + 4 + quic_buf_size(&value)) {
            return false;
        }
        *((uint16_t *) buf->pos) = bswap_16(id);
        buf->pos += 2;
        *((uint16_t *) buf->pos) = bswap_16(quic_buf_size(&value));
        buf->pos += 2;
        memcpy(buf->pos, value.pos, quic_buf_size(&value));
        buf->pos += quic_buf_size(&value);
    }

    return true;
}

static inline bool quic_transport_parameter_bool_format(quic_buf_t *const buf, uint16_t id, bool value) {
    if (value) {
        if (buf->buf + buf->capa < buf->pos + 4) {
            return false;
        }
        *((uint16_t *) buf->pos) = bswap_16(id);
        buf->pos += 2;
        *((uint16_t *) buf->pos) = 0x0000;
        buf->pos += 2;
    }
    return true;
}

static inline quic_err_t quic_transport_parameter_format(quic_buf_t *const buf, const quic_transport_parameter_t params) {
    uint16_t *len = buf->pos;

    buf->pos += 2;
    bool ret = quic_transport_parameter_varint_format(buf, quic_trans_param_idle_timeout, params.idle_timeout)
        && quic_transport_parameter_varint_format(buf, quic_trans_param_max_packet_size, params.max_pkt_size)
        && quic_transport_parameter_varint_format(buf, quic_trans_param_max_data, params.max_data)
        && quic_transport_parameter_varint_format(buf, quic_trans_param_max_stream_data_bidi_local, params.max_stream_data_bidi_local)
        && quic_transport_parameter_varint_format(buf, quic_trans_param_max_stream_data_bidi_remote, params.max_stream_data_bidi_remote)
        && quic_transport_parameter_varint_format(buf, quic_trans_param_max_stream_data_uni, params.max_stream_data_uni)
        && quic_transport_parameter_varint_format(buf, quic_trans_param_max_stream_bidi, params.max_stream_bidi)
        && quic_transport_parameter_varint_format(buf, quic_trans_param_max_stream_uni, params.max_stream_uni)
        && quic_transport_parameter_varint_format(buf, quic_trans_param_ack_delay_exponent, params.ack_delay_exponent)
        && quic_transport_parameter_varint_format(buf, quic_trans_param_max_ack_delay, params.max_ack_delay)
        && quic_transport_parameter_varint_format(buf, quic_trans_param_active_connid_limit, params.active_connid)
        && quic_transport_parameter_string_format(buf, quic_trans_param_original_connid, params.original_connid)
        && quic_transport_parameter_string_format(buf, quic_trans_param_stateless_reset_token, params.stateless_reset_token)
        && quic_transport_parameter_bool_format(buf, quic_trans_param_disable_migration, params.disable_migration);

    if (!ret) {
        return quic_err_internal_error;
    }
    *len = bswap_16(buf->pos - buf->buf);

    return quic_err_success;
}

static inline quic_buf_t quic_transport_parameter_string_parse(quic_buf_t *const buf) {
    quic_buf_t ret;
    ret.capa = bswap_16(*(uint16_t *) buf->pos);
    buf->pos += 2;
    if (ret.capa > (size_t) quic_buf_size(buf)) {
        return ret;
    }
    ret.buf = malloc(ret.capa);
    if (!ret.buf) {
        return ret;
    }
    memcpy(ret.buf, buf->pos, ret.capa);
    quic_buf_setpl(&ret);

    buf->pos += ret.capa;

    return ret;
}

static inline uint64_t quic_transport_parameter_varint_parse(quic_buf_t *const buf) {
    buf->pos += 2;
    uint64_t ret = quic_varint_r(buf->pos);
    buf->pos += quic_varint_len(buf->pos);

    return ret;
}

static inline bool quic_transport_parameter_bool_parse(quic_buf_t *const buf) {
    buf->pos += 2;
    return true;
}

static inline quic_transport_parameter_t quic_transport_parameter_parse(quic_buf_t *const buf) {
    quic_transport_parameter_t ret = { };
    quic_transport_parameter_init(&ret);

    uint16_t len = bswap_16(*(uint16_t *) buf->pos);
    buf->pos += 2;
    len -= 2;

    if (len != quic_buf_size(buf)) {
        return ret;
    }

    while (quic_buf_size(buf) >= 4) {
        uint16_t id = bswap_16(*(uint16_t *) buf->pos);
        buf->pos += 2;

        switch (id) {
        case quic_trans_param_original_connid:
            ret.original_connid = quic_transport_parameter_string_parse(buf);
            break;
        case quic_trans_param_idle_timeout:
            ret.idle_timeout = quic_transport_parameter_varint_parse(buf);
            break;
        case quic_trans_param_stateless_reset_token:
            ret.stateless_reset_token = quic_transport_parameter_string_parse(buf);
            break;
        case quic_trans_param_max_packet_size:
            ret.max_pkt_size = quic_transport_parameter_varint_parse(buf);
            break;
        case quic_trans_param_max_data:
            ret.max_data = quic_transport_parameter_varint_parse(buf);
            break;
        case quic_trans_param_max_stream_data_bidi_local:
            ret.max_stream_data_bidi_local = quic_transport_parameter_varint_parse(buf);
            break;
        case quic_trans_param_max_stream_data_bidi_remote:
            ret.max_stream_data_bidi_remote = quic_transport_parameter_varint_parse(buf);
            break;
        case quic_trans_param_max_stream_data_uni:
            ret.max_stream_data_uni = quic_transport_parameter_varint_parse(buf);
            break;
        case quic_trans_param_max_stream_bidi:
            ret.max_stream_bidi = quic_transport_parameter_varint_parse(buf);
            break;
        case quic_trans_param_max_stream_uni:
            ret.max_stream_uni = quic_transport_parameter_varint_parse(buf);
            break;
        case quic_trans_param_ack_delay_exponent:
            ret.ack_delay_exponent = quic_transport_parameter_varint_parse(buf);
            break;
        case quic_trans_param_max_ack_delay:
            ret.max_ack_delay = quic_transport_parameter_varint_parse(buf);
            break;
        case quic_trans_param_disable_migration:
            ret.disable_migration = quic_transport_parameter_bool_parse(buf);
            break;
        case quic_trans_param_active_connid_limit:
            ret.active_connid = quic_transport_parameter_varint_parse(buf);
            break;
        }
    }

    return ret;
}

#endif
