/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "module.h"
#include "modules/sender.h"
#include "modules/packet_number_generator.h"
#include "modules/framer.h"
#include "modules/udp_runway.h"
#include "format/header.h"
#include "session.h"

/* These functions is only responsible for generating some fields of the QUIC header,
 * and lacks the packet number length field, packet number field, and payload length field. */
static inline quic_err_t quic_sender_generate_long_header(quic_session_t *const session, const uint8_t type, quic_buf_t *const buf);
static inline quic_err_t quic_sender_generate_initial_header(quic_sender_module_t *const sender, quic_buf_t *const buf);
static inline quic_err_t quic_sender_generate_0rtt_header(quic_sender_module_t *const sender, quic_buf_t *const buf);
static inline quic_err_t quic_sender_generate_handshake_header(quic_sender_module_t *const sender, quic_buf_t *const buf);
static inline quic_err_t quic_sender_generate_retry_header(quic_sender_module_t *const sender, quic_buf_t *const buf);

/* all fields of the short header are completely filled */
static inline quic_err_t quic_sender_generate_short_header(quic_session_t *const session, quic_buf_t *const buf);

static quic_send_packet_t *quic_sender_pack_app_packet(quic_sender_module_t *const sender);

static quic_err_t quic_sender_module_init(void *const module);
static quic_err_t quic_sender_module_process(void *const module);

static inline quic_err_t  quic_sender_generate_long_header(quic_session_t *const session, const uint8_t type, quic_buf_t *const buf) {
    quic_long_header_t *const header = buf->pos;
    header->first_byte = type;
    header->version = 0x00000000;

    quic_long_header_dst_conn_len(header) = quic_buf_size(&session->dst);
    memcpy(quic_long_header_dst_conn_off(header), session->dst.pos, quic_buf_size(&session->dst));
    quic_long_header_src_conn_len(header) = quic_buf_size(&session->key);
    memcpy(quic_long_header_src_conn_off(header), session->key.pos, quic_buf_size(&session->key));

    uint32_t spec_size = quic_long_header_payload(header) - buf->pos;
    buf->pos += spec_size;

    return quic_err_success;
}

static inline quic_err_t quic_sender_generate_initial_header(quic_sender_module_t *const sender, quic_buf_t *const buf) {
    quic_session_t *const session = quic_module_of_session(sender, quic_sender_module);
    quic_sender_generate_long_header(session, quic_packet_initial_type, buf);
    quic_varint_format_r(buf, 0);
    return quic_err_success;
}

static inline quic_err_t quic_sender_generate_0rtt_header(quic_sender_module_t *const sender, quic_buf_t *const buf) {
    quic_session_t *const session = quic_module_of_session(sender, quic_sender_module);
    quic_sender_generate_long_header(session, quic_packet_0rtt_type, buf);
    return quic_err_success;
}

static inline quic_err_t quic_sender_generate_handshake_header(quic_sender_module_t *const sender, quic_buf_t *const buf) {
    quic_session_t *const session = quic_module_of_session(sender, quic_sender_module);
    quic_sender_generate_long_header(session, quic_packet_handshake_type, buf);
    return quic_err_success;
}

static inline quic_err_t quic_sender_generate_retry_header(quic_sender_module_t *const sender, quic_buf_t *const buf) {
    quic_session_t *const session = quic_module_of_session(sender, quic_sender_module);
    quic_sender_generate_long_header(session, quic_packet_retry_type, buf);
    return quic_err_success;
}

static inline quic_err_t quic_sender_generate_short_header(quic_session_t *const session, quic_buf_t *const buf) {
    quic_packet_number_generator_module_t *const numgen = quic_session_module(quic_packet_number_generator_module_t, session, quic_app_packet_number_generator_module);

    quic_short_header_t *const header = buf->pos;
    
    header->first_byte = quic_packet_short_type;
    memcpy(quic_short_header_dst_conn_off(header), session->dst.pos, quic_buf_size(&session->dst));
    buf->pos += 1 + quic_buf_size(&session->dst);

    uint8_t numlen = quic_packet_number_format_len(numgen->next);
    header->first_byte |= (uint8_t) (numlen - 1);
    quic_packet_number_format(buf->pos, numgen->next, numlen);
    buf->pos += numlen;

    numgen->next++;
    return quic_err_success;
}

static quic_send_packet_t *quic_sender_pack_app_packet(quic_sender_module_t *const sender) {
    quic_session_t *const session = quic_module_of_session(sender, quic_sender_module);
    quic_framer_module_t *const framer = quic_session_module(quic_framer_module_t, session, quic_framer_module);
    quic_send_packet_t *packet = NULL;
    quic_send_packet_init(packet, sender->mtu);

    quic_sender_generate_short_header(session, &packet->buf);

    uint32_t max_bytes = packet->buf.capa - (packet->buf.pos - packet->buf.buf);
    uint32_t frame_len = 0;

    for ( ;; ) {
        frame_len = quic_framer_append_ctrl_frame(&packet->frames, max_bytes, framer);
        max_bytes -= frame_len;
        if (frame_len == 0) {
            break;
        }
    }
    for ( ;; ) {
        frame_len = quic_framer_append_stream_frame(&packet->frames, max_bytes, false, framer);
        max_bytes -= frame_len;
        if (frame_len == 0) {
            break;
        }
    }

    return packet;
}

static quic_err_t quic_sender_module_init(void *const module) {
    quic_sender_module_t *const sender_module = module;

    sender_module->mtu = 1460;

    return quic_err_success;
}

static quic_err_t quic_sender_module_process(void *const module) {
    quic_session_t *const session = quic_module_of_session(module, quic_sender_module);
    quic_sender_module_t *const sender_module = module;
    quic_send_packet_t *packet = NULL;
    quic_udp_runway_module_t *const udp_runway = quic_session_module(quic_udp_runway_module_t, session, quic_udp_runway_module);

    quic_frame_t *frame = NULL;

    packet = quic_sender_pack_app_packet(sender_module);

    quic_link_foreach(frame, &packet->frames) {
        quic_frame_format(&packet->buf, frame);
    }

    quic_udp_runway_push(udp_runway, packet);

    return quic_err_success;
}

quic_module_t quic_sender_module = {
    .module_size = sizeof(quic_sender_module_t),
    .init = quic_sender_module_init,
    .process = quic_sender_module_process,
    .destory = NULL
};
