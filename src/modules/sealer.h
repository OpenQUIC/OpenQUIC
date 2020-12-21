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
#include <malloc.h>
#include <openssl/ssl.h>
#include <byteswap.h>

#define quic_ssl_session_id_context "OpenQUIC server"

typedef struct quic_sealer_s quic_sealer_t;
struct quic_sealer_s {
    const EVP_AEAD *(*w_aead)();
    size_t w_aead_tag_size;
    quic_buf_t w_sec;
    quic_buf_t w_key;
    quic_buf_t w_iv;

    const EVP_AEAD *(*r_aead)();
    size_t r_aead_tag_size;
    quic_buf_t r_sec;
    quic_buf_t r_key;
    quic_buf_t r_iv;
};

static inline quic_err_t quic_sealer_init(quic_sealer_t *const sealer) {
    sealer->w_aead = NULL;
    sealer->w_aead_tag_size = 0;
    quic_buf_init(&sealer->w_sec);
    quic_buf_init(&sealer->w_key);
    quic_buf_init(&sealer->w_iv);

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

    quic_sealer_t initial_sealer;
    quic_sealer_t handshake_sealer;
    quic_sealer_t app_sealer;
};

static inline quic_err_t quic_sealer_handshake_process(quic_sealer_module_t *const module) {
    int result = SSL_do_handshake(module->ssl);
    if (result >= 0) {
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

extern quic_module_t quic_sealer_module;

#endif
