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
#include "modules/udp_fd.h"
#include "modules/ack_generator.h"
#include "modules/congestion.h"
#include "modules/stream.h"
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
static inline quic_err_t quic_sender_generate_short_header(quic_session_t *const session, const uint64_t num, quic_buf_t *const buf);

static quic_send_packet_t *quic_sender_pack_app_packet(quic_sender_module_t *const sender);

static inline quic_err_t quic_sender_send_packet(quic_sender_module_t *const module, quic_send_packet_t *const pkt);

static quic_err_t quic_sender_module_init(void *const module);
static quic_err_t quic_sender_module_loop(void *const module, const uint64_t now);

static inline quic_err_t  quic_sender_generate_long_header(quic_session_t *const session, const uint8_t type, quic_buf_t *const buf) {
    quic_long_header_t *const header = buf->pos;
    header->first_byte = type;
    header->version = 0x00000000;

    quic_long_header_dst_conn_len(header) = quic_buf_size(&session->cfg.dst);
    memcpy(quic_long_header_dst_conn_off(header), session->cfg.dst.pos, quic_buf_size(&session->cfg.dst));
    quic_long_header_src_conn_len(header) = quic_buf_size(&session->key);
    memcpy(quic_long_header_src_conn_off(header), session->key.pos, quic_buf_size(&session->key));

    uint32_t spec_size = quic_long_header_payload(header) - buf->pos;
    buf->pos += spec_size;

    return quic_err_success;
}

static inline quic_err_t quic_sender_generate_initial_header(quic_sender_module_t *const sender, quic_buf_t *const buf) {
    quic_session_t *const session = quic_module_of_session(sender);
    quic_sender_generate_long_header(session, quic_packet_initial_type, buf);
    quic_varint_format_r(buf, 0);
    return quic_err_success;
}

static inline quic_err_t quic_sender_generate_0rtt_header(quic_sender_module_t *const sender, quic_buf_t *const buf) {
    quic_session_t *const session = quic_module_of_session(sender);
    quic_sender_generate_long_header(session, quic_packet_0rtt_type, buf);
    return quic_err_success;
}

static inline quic_err_t quic_sender_generate_handshake_header(quic_sender_module_t *const sender, quic_buf_t *const buf) {
    quic_session_t *const session = quic_module_of_session(sender);
    quic_sender_generate_long_header(session, quic_packet_handshake_type, buf);
    return quic_err_success;
}

static inline quic_err_t quic_sender_generate_retry_header(quic_sender_module_t *const sender, quic_buf_t *const buf) {
    quic_session_t *const session = quic_module_of_session(sender);
    quic_sender_generate_long_header(session, quic_packet_retry_type, buf);
    return quic_err_success;
}

static inline quic_err_t quic_sender_generate_short_header(quic_session_t *const session, const uint64_t num, quic_buf_t *const buf) {

    quic_short_header_t *const header = buf->pos;
    
    header->first_byte = quic_packet_short_type;
    memcpy(quic_short_header_dst_conn_off(header), session->cfg.dst.pos, quic_buf_size(&session->cfg.dst));
    buf->pos += 1 + quic_buf_size(&session->cfg.dst);

    uint8_t numlen = quic_packet_number_format_len(num);
    header->first_byte |= (uint8_t) (numlen - 1);
    quic_packet_number_format(buf->pos, num, numlen);
    buf->pos += numlen;

    return quic_err_success;
}

static quic_send_packet_t *quic_sender_pack_app_packet(quic_sender_module_t *const sender) {
    quic_session_t *const session = quic_module_of_session(sender);
    quic_stream_module_t *const stream_module = quic_session_module(quic_stream_module_t, session, quic_stream_module);

    quic_packet_number_generator_module_t *const numgen = quic_session_module(quic_packet_number_generator_module_t, session, quic_app_packet_number_generator_module);
    quic_framer_module_t *const f_module = quic_session_module(quic_framer_module_t, session, quic_framer_module);
    quic_ack_generator_module_t *const ag_module = quic_session_module(quic_ack_generator_module_t, session, quic_app_ack_generator_module);
    quic_retransmission_module_t *const r_module = quic_session_module(quic_retransmission_module_t, session, quic_app_retransmission_module);

    quic_frame_t *frame = NULL;

    // generate max stream data
    quic_stream_module_process_rwnd(stream_module);

    if (quic_framer_empty(f_module) && quic_retransmission_empty(r_module) && !quic_ack_generator_should_send(ag_module)) {
        return NULL;
    }

    // init send_pkt
    quic_send_packet_t *pkt = NULL;
    quic_send_packet_init(pkt, sender->mtu);
    pkt->retransmission_module = quic_session_module(quic_retransmission_module_t, session, quic_app_retransmission_module);
    pkt->num = numgen->next;

    // generate short header
    quic_sender_generate_short_header(session, pkt->num, &pkt->buf);

    uint32_t max_bytes = pkt->buf.capa - (pkt->buf.pos - pkt->buf.buf);
    uint32_t frame_len = 0;

    // generate ACK frame and serialize it
    frame_len = quic_ack_generator_append_ack_frame(&pkt->frames, &pkt->largest_ack, ag_module);
    max_bytes -= frame_len;

    // serialize retransmission frames
    for ( ;; ) {
        frame_len = quic_retransmission_append_frame(&pkt->frames, max_bytes, pkt->retransmission_module);
        max_bytes -= frame_len;
        if (frame_len == 0) {
            break;
        }
        pkt->included_unacked = true;
    }

    // serialize ctrl frames
    for ( ;; ) {
        frame_len = quic_framer_append_ctrl_frame(&pkt->frames, max_bytes, f_module);
        max_bytes -= frame_len;
        if (frame_len == 0) {
            break;
        }
        pkt->included_unacked = true;
    }
    // serialize stream frames
    for ( ;; ) {
        frame_len = quic_framer_append_stream_frame(&pkt->frames, max_bytes, false, f_module, pkt->retransmission_module);
        max_bytes -= frame_len;
        if (frame_len == 0) {
            break;
        }
        pkt->included_unacked = true;
    }

    if (quic_link_empty(&pkt->frames)) {
        free(pkt);
        return NULL;
    }

    numgen->next++;
    quic_link_foreach(frame, &pkt->frames) {
        quic_frame_format(&pkt->buf, frame);
    }

    return pkt;
}

static quic_err_t quic_sender_module_init(void *const module) {
    quic_sender_module_t *const s_module = module;

    s_module->mtu = 1460;
    s_module->next_send_time = 0;

    return quic_err_success;
}

static quic_err_t quic_sender_module_loop(void *const module, const uint64_t now) {
    quic_sender_module_t *const s_module = module;

    quic_session_t *const session = quic_module_of_session(s_module);

    if (now < s_module->next_send_time && s_module->next_send_time != 0) {
        quic_session_update_loop_deadline(session, s_module->next_send_time);
        return quic_err_success;
    }
    s_module->next_send_time = 0;

    quic_retransmission_module_t *const app_r_module = quic_session_module(quic_retransmission_module_t, session, quic_app_retransmission_module);
    quic_retransmission_module_t *const hs_r_module = quic_session_module(quic_retransmission_module_t, session, quic_handshake_retransmission_module);
    quic_retransmission_module_t *const init_r_module = quic_session_module(quic_retransmission_module_t, session, quic_initial_retransmission_module);
    quic_congestion_module_t *const c_module = quic_session_module(quic_congestion_module_t, session, quic_congestion_module);


    uint64_t unacked_pkt_count = app_r_module->sent_pkt_count + hs_r_module->sent_pkt_count + init_r_module->sent_pkt_count;
    if (unacked_pkt_count >= (25000 >> 2)) {
        return quic_err_success;
    }
    // TODO probe pkt (on lost)
    uint64_t unacked_bytes = app_r_module->unacked_len + hs_r_module->unacked_len + init_r_module->unacked_len;
    if (!quic_congestion_allow_send(c_module, unacked_bytes) || unacked_pkt_count >= 20000) {
        // TODO send ACK
        return quic_err_success;
    }

    quic_send_packet_t *pkt = NULL;
    pkt = quic_sender_pack_app_packet(s_module);
    if (pkt == NULL) {
        return quic_err_success;
    }

    quic_sender_send_packet(s_module, pkt);
    free(pkt);

    return quic_err_success;
}

static inline quic_err_t quic_sender_send_packet(quic_sender_module_t *const module, quic_send_packet_t *const pkt) {
    quic_session_t *const session = quic_module_of_session(module);
    quic_udp_fd_module_t *const uf_module = quic_session_module(quic_udp_fd_module_t, session, quic_udp_fd_module);
    quic_congestion_module_t *const c_module = quic_session_module(quic_congestion_module_t, session, quic_congestion_module);

    quic_sent_packet_rbt_t *sent_pkt = malloc(sizeof(quic_sent_packet_rbt_t));
    if (sent_pkt) {
        quic_rbt_init(sent_pkt);
        sent_pkt->key = pkt->num;

        // note: linked lists have been transferred to 'mem', no need to release them
        sent_pkt->frames.next = pkt->frames.next;
        sent_pkt->frames.next->prev = &sent_pkt->frames;
        sent_pkt->frames.prev = pkt->frames.prev;
        sent_pkt->frames.prev->next = &sent_pkt->frames;

        sent_pkt->largest_ack = pkt->largest_ack;
        sent_pkt->sent_time = quic_now();
        sent_pkt->pkt_len = pkt->buf.pos - pkt->buf.buf;
        sent_pkt->included_unacked = pkt->included_unacked;

        quic_retransmission_sent_mem_push(pkt->retransmission_module, sent_pkt);
        quic_congestion_on_sent(c_module, sent_pkt->key, sent_pkt->pkt_len, sent_pkt->included_unacked);

        module->next_send_time = (module->next_send_time > sent_pkt->sent_time ? module->next_send_time : sent_pkt->sent_time)
            + quic_congestion_next_send_time(c_module, pkt->retransmission_module->unacked_len);

        quic_session_update_loop_deadline(session, module->next_send_time);
    }

    quic_udp_fd_write(uf_module, pkt->data, pkt->buf.pos - pkt->buf.buf);

    return quic_err_success;
}

quic_module_t quic_sender_module = {
    .name        = "sender",
    .module_size = sizeof(quic_sender_module_t),
    .init        = quic_sender_module_init,
    .process     = NULL,
    .loop        = quic_sender_module_loop,
    .destory     = NULL
};
