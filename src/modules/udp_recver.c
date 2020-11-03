/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "modules/udp_recver.h"
#include "modules/ack_generator.h"
#include "format/header.h"

static inline quic_err_t quic_udp_recver_handle_packet(quic_udp_recver_module_t *const module);
static quic_err_t quic_udp_recver_process_packet(quic_session_t *const sess, quic_udp_recver_module_t *const module, const quic_payload_t *payload, const uint64_t recv_time);
static quic_err_t quic_udp_recver_process_packet_payload(quic_session_t *const sess, quic_udp_recver_module_t *const module, const quic_payload_t *payload, const uint64_t recv_time);

static quic_err_t quic_udp_recver_module_init(void *const module);
static quic_err_t quic_udp_recver_module_process(void *const module);

extern quic_session_handler_t quic_session_handler[256];

static inline quic_err_t quic_udp_recver_handle_packet(quic_udp_recver_module_t *const module) {
    quic_session_t *const session = quic_module_of_session(module, quic_udp_recver_module);
    quic_ack_generator_module_t *ag_module = NULL;

    quic_buf_t recv_buf = { .buf = module->curr_packet->data, .capa = module->curr_packet->len };
    quic_buf_setpl(&recv_buf);

    union {
        quic_initial_header_t initial;
        quic_handshake_header_t handshake;
        quic_0rtt_header_t zero_rtt;
        quic_payload_t short_payload;
    } payload;

    quic_header_t *const header = (quic_header_t *) module->curr_packet->data;

    if (session->cfg.is_cli && !module->recv_first && quic_header_is_long(header)) {
        quic_buf_t src = quic_long_header_src_conn(header);
        quic_buf_setpl(&src);

        if (quic_buf_cmp(&src, &session->dst) != 0) {
            quic_buf_copy(&session->dst, &src);
        }
    }

    module->recv_first = true;
    module->last_recv_time = module->curr_packet->recv_time;

    if (quic_header_is_long(header)) {
        switch (quic_packet_type(header)) {
        case quic_packet_initial_type:
            payload.initial = quic_initial_header(header);
            ag_module = quic_session_module(quic_ack_generator_module_t, session, quic_initial_ack_generator_module);
            break;

        case quic_packet_handshake_type:
            payload.handshake = quic_handshake_header(header);
            ag_module = quic_session_module(quic_ack_generator_module_t, session, quic_handshake_ack_generator_module);
            break;

        case quic_packet_0rtt_type:
            payload.zero_rtt = quic_0rtt_header(header);
            break;

        case quic_packet_retry_type:
            return quic_err_not_implemented;
        }
    }
    else {
        payload.short_payload = quic_short_header(header, session->cfg.conn_len);
        payload.short_payload.payload_len = module->curr_packet->len - ((uint8_t *) payload.short_payload.payload - module->curr_packet->data);
        ag_module = quic_session_module(quic_ack_generator_module_t, session, quic_app_ack_generator_module);
    }

    quic_udp_recver_process_packet(session, module, (quic_payload_t *) &payload, module->curr_packet->recv_time);

    if (ag_module) {
        quic_ack_generator_module_received(ag_module,
                                           ((quic_payload_t *) &payload)->p_num,
                                           module->curr_packet->recv_time,
                                           &session->rtt,
                                           module->curr_ack_eliciting);
    }

    return quic_err_success;
}

static quic_err_t quic_udp_recver_process_packet(quic_session_t *const sess, quic_udp_recver_module_t *const module, const quic_payload_t *payload, const uint64_t recv_time) {
    quic_err_t err = quic_err_success;

    if ((err = quic_udp_recver_process_packet_payload(sess, module, payload, recv_time)) != quic_err_success) {
        return err;
    }

    return quic_err_success;
}

static quic_err_t quic_udp_recver_process_packet_payload(quic_session_t *const sess, quic_udp_recver_module_t *const module, const quic_payload_t *payload, const uint64_t recv_time) {
    quic_err_t err = quic_err_success;

    quic_buf_t buf;
    buf.buf = payload->payload;
    buf.capa = payload->payload_len;
    quic_buf_setpl(&buf);

    module->curr_ack_eliciting = false;
    while (!quic_buf_empty(&buf)) {
        quic_frame_t *frame = NULL;

        if ((err = quic_frame_parse(frame, &buf)) != quic_err_success) {
            return err;
        }

        if (frame->first_byte == quic_frame_ack_type || frame->first_byte == quic_frame_ack_ecn_type) {
            ((quic_frame_ack_t *) frame)->packet_type = payload->type;
            ((quic_frame_ack_t *) frame)->recv_time = recv_time;
        }
        else if (frame->first_byte == quic_frame_crypto_type) {
            ((quic_frame_crypto_t *) frame)->packet_type = payload->type;
        }

        if (!quic_session_handler[frame->first_byte]) {
            free(frame);
            continue;
        }
        if ((err = quic_session_handler[frame->first_byte](sess, frame)) != quic_err_success) {
            free(frame);
            return err;
        }

        if (frame->first_byte != quic_frame_ack_type && frame->first_byte == quic_frame_ack_ecn_type) {
            module->curr_ack_eliciting = true;
        }
    }

    return quic_err_success;
}

static quic_err_t quic_udp_recver_module_init(void *const module) {
    quic_udp_recver_module_t *const ur_module = module;

    pthread_mutex_init(&ur_module->mtx, NULL);
    quic_link_init(&ur_module->queue);
    ur_module->curr_packet = NULL;
    ur_module->curr_ack_eliciting = false;

    ur_module->recv_first = false;
    ur_module->last_recv_time = 0;

    return quic_err_success;
}

static quic_err_t quic_udp_recver_module_process(void *const module) {
    quic_udp_recver_module_t *const ur_module = module;

    pthread_mutex_lock(&ur_module->mtx);
    ur_module->curr_packet = (quic_recv_packet_t *) quic_link_next(&ur_module->queue);
    quic_link_remove(ur_module->curr_packet);
    pthread_mutex_unlock(&ur_module->mtx);

    quic_udp_recver_handle_packet(module);

    free(ur_module->curr_packet);
    ur_module->curr_packet = NULL;

    return quic_err_success;
}

quic_module_t quic_udp_recver_module = {
    .module_size = sizeof(quic_udp_recver_module_t),
    .init = quic_udp_recver_module_init,
    .process = quic_udp_recver_module_process,
    .destory = NULL
};
