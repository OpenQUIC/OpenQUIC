/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_SEALER_H__
#define __OPENQUIC_SEALER_H__

#include "module.h"
#include "sorter.h"
#include "session.h"
#include "format/frame.h"
#include "modules/framer.h"
#include "modules/ack_generator.h"
#include <openssl/ssl.h>
#include <malloc.h>
#include <byteswap.h>

#define quic_ssl_session_id_context "OpenQUIC server"

typedef struct quic_sealer_s quic_sealer_t;
struct quic_sealer_s {
    EVP_AEAD_CTX *w_ctx;
    const EVP_AEAD *(*w_aead)();
    size_t w_aead_tag_size;
    quic_buf_t w_sec;
    quic_buf_t w_key;
    quic_buf_t w_iv;

    EVP_AEAD_CTX *r_ctx;
    const EVP_AEAD *(*r_aead)();
    size_t r_aead_tag_size;
    quic_buf_t r_sec;
    quic_buf_t r_key;
    quic_buf_t r_iv;
};

static inline quic_err_t quic_sealer_init(quic_sealer_t *const sealer) {
    sealer->w_ctx = NULL;
    sealer->w_aead = NULL;
    sealer->w_aead_tag_size = 0;
    quic_buf_init(&sealer->w_sec);
    quic_buf_init(&sealer->w_key);
    quic_buf_init(&sealer->w_iv);

    sealer->r_ctx = NULL;
    sealer->r_aead = NULL;
    sealer->r_aead_tag_size = 0;
    quic_buf_init(&sealer->r_sec);
    quic_buf_init(&sealer->r_key);
    quic_buf_init(&sealer->r_iv);

    return quic_err_success;
}

static inline quic_err_t quic_sealer_set(quic_sealer_t *const sealer, const uint8_t *rsec, const uint8_t *wsec, const size_t len) {
    sealer->r_sec.capa = len;
    sealer->r_sec.buf = malloc(len);
    if (!sealer->r_sec.buf) {
        return quic_err_internal_error;
    }
    memcpy(sealer->r_sec.buf, rsec, len);

    sealer->w_sec.capa = len;
    sealer->w_sec.buf = malloc(len);
    if (!sealer->w_sec.buf) {
        return quic_err_internal_error;
    }
    memcpy(sealer->w_sec.buf, wsec, len);

    return quic_err_success;
}

typedef struct quic_sealer_module_s quic_sealer_module_t;
struct quic_sealer_module_s {
    QUIC_MODULE_FIELDS

    SSL_CTX *ssl_ctx;
    SSL *ssl;

    int tls_alert;
    uint32_t off;

    enum ssl_encryption_level_t r_level;
    enum ssl_encryption_level_t w_level;

    enum ssl_encryption_level_t level;

    quic_sealer_t initial_sealer;
    quic_sealer_t handshake_sealer;
    quic_sealer_t app_sealer;

    quic_sorter_t initial_r_sorter;
    quic_sorter_t initial_w_sorter;
    quic_sorter_t handshake_r_sorter;
    quic_sorter_t handshake_w_sorter;
};

extern quic_module_t quic_sealer_module;

static inline quic_err_t quic_sealer_set_level(quic_sealer_module_t *const module, enum ssl_encryption_level_t level) {
    quic_session_t *const session = quic_module_of_session(module);
    quic_ack_generator_module_t *ag_module = NULL;
    quic_retransmission_module_t *r_module = NULL;

    switch (level) {
    case ssl_encryption_handshake:
        ag_module = quic_session_module(quic_ack_generator_module_t, session, quic_initial_ack_generator_module);
        r_module = quic_session_module(quic_retransmission_module_t, session, quic_initial_retransmission_module);
        break;

    case ssl_encryption_application:
        ag_module = quic_session_module(quic_ack_generator_module_t, session, quic_handshake_ack_generator_module);
        r_module = quic_session_module(quic_retransmission_module_t, session, quic_handshake_retransmission_module);
        break;
    default:
        break;
    }

    if (ag_module) {
        quic_ack_generator_drop(ag_module);
    }
    if (r_module) {
        quic_retransmission_drop(r_module);
    }

    module->level = level;
    
    return quic_err_success;
}

static inline quic_err_t quic_sealer_handshake_process(quic_sealer_module_t *const module) {
    int result = SSL_do_handshake(module->ssl);
    if (result >= 0) {
        quic_session_t *const session = quic_module_of_session(module);

        if (!session->cfg.is_cli) {
            quic_framer_module_t *const f_module = quic_session_module(quic_framer_module_t, session, quic_framer_module);
            quic_sealer_set_level(module, ssl_encryption_application);

            quic_frame_handshake_done_t *frame = malloc(sizeof(quic_frame_handshake_done_t));
            quic_frame_init(frame, quic_frame_handshake_done_type);

            quic_framer_ctrl(f_module, (quic_frame_t *) frame);
            quic_module_activate(session, quic_sender_module);
        }
        return quic_err_success;
    }

    int err = SSL_get_error(module->ssl, result);
    switch (err) {
    case SSL_ERROR_WANT_READ:
        break;
    case SSL_ERROR_WANT_WRITE:
        break;
    case SSL_ERROR_WANT_X509_LOOKUP:
        break;
    case SSL_ERROR_SSL:
        break;
    }

    return quic_err_success;
}

static inline uint64_t quic_sealer_append_crypto_frame(quic_link_t *const frames, uint64_t len, quic_sealer_module_t *const module, enum ssl_encryption_level_t level) {
    quic_sorter_t *sorter = NULL;

    switch (level) {
    case ssl_encryption_initial:
        sorter = &module->initial_w_sorter;
        break;
    case ssl_encryption_handshake:
        sorter = &module->handshake_w_sorter;
        break;
    default:
        return 0;
    }

    if (quic_sorter_empty(sorter)) {
        return 0;
    }

    if (len > quic_sorter_readable(sorter)) {
        len = quic_sorter_readable(sorter);
    }

    // modify, same as generate max stream data
    quic_frame_crypto_t *frame = malloc(sizeof(quic_frame_crypto_t) + len);
    if (!frame) {
        return 0;
    }
    quic_frame_init(frame, quic_frame_crypto_type);
    frame->len = len;
    frame->off = sorter->readed_size;

    quic_sorter_read(sorter, len, frame->data);
    
    quic_link_insert_before(frames, frame);

    return quic_frame_size(frame);
}

static inline bool quic_sealer_should_send(quic_sealer_module_t *const module, enum ssl_encryption_level_t level) {
    switch (level) {
    case ssl_encryption_initial:
        return !quic_sorter_empty(&module->initial_w_sorter);
    case ssl_encryption_handshake:
        return !quic_sorter_empty(&module->handshake_w_sorter);
    default:
        return false;
    }
}

#endif
