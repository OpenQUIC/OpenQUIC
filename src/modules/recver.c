/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "modules/recver.h"
#include "format/frame.h"
#include "modules/ack_generator.h"
#include "modules/sealer.h"
#include "format/header.h"

static quic_err_t quic_recver_handle_packet(quic_recver_module_t *const module);
static quic_err_t quic_recver_process_packet(quic_session_t *const sess, quic_recver_module_t *const r_module, quic_ack_generator_module_t *const a_module, const quic_payload_t *payload, const uint64_t recv_time);
static quic_err_t quic_recver_process_packet_payload(quic_session_t *const sess, quic_recver_module_t *const r_module, quic_ack_generator_module_t *const a_module, const quic_payload_t *payload, const uint64_t recv_time);

static quic_err_t quic_recver_module_init(void *const module);
static quic_err_t quic_recver_module_process(void *const module);
static quic_err_t quic_recver_module_destory(void *const module);

extern quic_session_handler_t quic_session_handler[256];

static quic_err_t quic_recver_handle_packet(quic_recver_module_t *const module) {
    quic_session_t *const session = quic_module_of_session(module);
    quic_ack_generator_module_t *ag_module = NULL;
    quic_sealer_module_t *const sealer_module = quic_session_module(session, quic_sealer_module);

    quic_err_t err = quic_sealer_open(module->curr_packet, sealer_module, quic_buf_size(&session->src));
    if (err != quic_err_success) {
        return err;
    }

    quic_buf_t recv_buf = { .buf = module->curr_packet->pkt.buf, .capa = module->curr_packet->pkt.ret };
    quic_buf_setpl(&recv_buf);

    union {
        quic_initial_header_t initial;
        quic_handshake_header_t handshake;
        quic_0rtt_header_t zero_rtt;
        quic_payload_t short_payload;
    } payload;

    quic_header_t *const header = (quic_header_t *) module->curr_packet->pkt.buf;

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
            ag_module = quic_session_module(session, quic_initial_ack_generator_module);
            break;

        case quic_packet_handshake_type:
            payload.handshake = quic_handshake_header(header);
            ag_module = quic_session_module(session, quic_handshake_ack_generator_module);
            break;

        case quic_packet_0rtt_type:
            payload.zero_rtt = quic_0rtt_header(header);
            break;

        case quic_packet_retry_type:
            return quic_err_not_implemented;
        }
    }
    else {
        payload.short_payload = quic_short_header(header, quic_buf_size(&session->src));
        payload.short_payload.payload_len = module->curr_packet->pkt.ret - ((uint8_t *) payload.short_payload.payload - module->curr_packet->pkt.buf);
        ag_module = quic_session_module(session, quic_app_ack_generator_module);
    }

    quic_recver_process_packet(session, module, ag_module, (quic_payload_t *) &payload, module->curr_packet->recv_time);

    return quic_err_success;
}

static quic_err_t quic_recver_process_packet(quic_session_t *const sess, quic_recver_module_t *const r_module, quic_ack_generator_module_t *const a_module, const quic_payload_t *payload, const uint64_t recv_time) {
    quic_err_t err = quic_err_success;

    if ((err = quic_recver_process_packet_payload(sess, r_module, a_module, payload, recv_time)) != quic_err_success) {
        return err;
    }

    return quic_err_success;
}

static quic_err_t quic_recver_process_packet_payload(quic_session_t *const sess, quic_recver_module_t *const r_module, quic_ack_generator_module_t *const a_module, const quic_payload_t *payload, const uint64_t recv_time) {
    quic_err_t err = quic_err_success;
    bool should_ack = false;

    quic_buf_t buf;
    buf.buf = payload->payload;
    buf.capa = payload->payload_len;
    quic_buf_setpl(&buf);

    r_module->curr_ack_eliciting = false;
    while (!quic_buf_empty(&buf)) {
        quic_frame_t *frame = NULL;

        if ((err = quic_frame_parse(frame, &buf)) != quic_err_success) {
            return err;
        }

        if (frame->first_byte == quic_frame_ack_type || frame->first_byte == quic_frame_ack_ecn_type) {
            ((quic_frame_ack_t *) frame)->packet_type = payload->type;
            ((quic_frame_ack_t *) frame)->recv_time = recv_time;
        }
        else {
            should_ack = true;

            if (frame->first_byte == quic_frame_crypto_type) {
                ((quic_frame_crypto_t *) frame)->packet_type = payload->type;
            }
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
            r_module->curr_ack_eliciting = true;
        }

        free(frame);
    }

    if (a_module) {
        quic_ack_generator_module_received(a_module, payload->p_num, recv_time, should_ack);
    }

    return quic_err_success;
}

static quic_err_t quic_recver_module_init(void *const module) {
    quic_recver_module_t *const ur_module = module;

    pthread_mutex_init(&ur_module->mtx, NULL);
    liteco_link_init(&ur_module->queue);
    ur_module->curr_packet = NULL;
    ur_module->curr_ack_eliciting = false;

    ur_module->recv_first = false;
    ur_module->last_recv_time = 0;

    return quic_err_success;
}

static quic_err_t quic_recver_module_process(void *const module) {
    quic_recver_module_t *const ur_module = module;

    pthread_mutex_lock(&ur_module->mtx);
    while (!liteco_link_empty(&ur_module->queue)) {
        ur_module->curr_packet = (quic_recv_packet_t *) liteco_link_next(&ur_module->queue);
        liteco_link_remove(ur_module->curr_packet);
        pthread_mutex_unlock(&ur_module->mtx);

        quic_recver_handle_packet(module);
        quic_recv_packet_recovery(ur_module->curr_packet);
        ur_module->curr_packet = NULL;

        pthread_mutex_lock(&ur_module->mtx);
    }
    pthread_mutex_unlock(&ur_module->mtx);


    return quic_err_success;
}

static quic_err_t quic_recver_module_destory(void *const module) {
    quic_recver_module_t *const ur_module = module;
    
    pthread_mutex_destroy(&ur_module->mtx);

    while (!liteco_link_empty(&ur_module->queue)) {
        quic_recv_packet_t *recvpkt = (quic_recv_packet_t *) liteco_link_next(&ur_module->queue);
        liteco_link_remove(recvpkt);
        quic_recv_packet_recovery(recvpkt);
    }

    if (ur_module->curr_packet) {
        quic_recv_packet_recovery(ur_module->curr_packet);
        ur_module->curr_packet = NULL;
    }

    return quic_err_success;
}

quic_module_t quic_recver_module = {
    .name        = "recver",
    .module_size = sizeof(quic_recver_module_t),
    .init        = quic_recver_module_init,
    .start       = NULL,
    .process     = quic_recver_module_process,
    .loop        = NULL,
    .destory     = quic_recver_module_destory
};
