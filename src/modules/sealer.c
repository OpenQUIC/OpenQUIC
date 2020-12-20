/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "modules/sealer.h"
#include "modules/framer.h"
#include "session.h"
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#define QUIC_DEFAULT_TLE_CIPHERS                     \
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:" \
    "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256"

#define QUIC_DEFAULT_CURVE_GROUPS "X25519"

static quic_err_t quic_sealer_module_init(void *const module);

static int quic_sealer_module_set_read_secret(SSL *ssl, enum ssl_encryption_level_t level, const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len);
static int quic_sealer_module_set_write_secret(SSL *ssl, enum ssl_encryption_level_t level, const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len);
static int quic_sealer_module_write_handshake_data(SSL *ssl, enum ssl_encryption_level_t level, const uint8_t *data, size_t len);
static int quic_sealer_module_flush_flight(SSL *ssl);
static int quic_sealer_module_send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert);
static int quic_sealer_module_alpn_select_proto_cb(SSL *ssl, const uint8_t **out, uint8_t *outlen, const uint8_t *in, uint32_t inlen, void *arg);
static enum ssl_verify_result_t quic_sealer_module_custom_verify(SSL *ssl, uint8_t *const alert);
static inline int quic_sealer_module_set_chains_and_key(quic_sealer_module_t *const module, const char *const chain_file, const char *const key_file);

static const uint16_t quic_signalg[] = {
    SSL_SIGN_ED25519,
    SSL_SIGN_ECDSA_SECP256R1_SHA256,
    SSL_SIGN_RSA_PSS_RSAE_SHA256,
    SSL_SIGN_RSA_PKCS1_SHA256,
};

static SSL_QUIC_METHOD ssl_quic_method = {
    quic_sealer_module_set_read_secret,
    quic_sealer_module_set_write_secret,
    quic_sealer_module_write_handshake_data,
    quic_sealer_module_flush_flight,
    quic_sealer_module_send_alert
};

static int quic_sealer_module_set_read_secret(SSL *ssl, enum ssl_encryption_level_t level, const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len) {
    quic_sealer_module_t *const s_module = SSL_get_app_data(ssl);
    quic_sealer_t *sealer = NULL;

    switch (level) {
    case ssl_encryption_initial:
        sealer = &s_module->initial_sealer;
        break;
    case ssl_encryption_handshake:
        sealer = &s_module->handshake_sealer;
        break;
    case ssl_encryption_application:
        sealer = &s_module->app_sealer;
        break;
    case ssl_encryption_early_data:
        // ignore early data
        break;
    }
    if (sealer == NULL) {
        return 0;
    }
    sealer->r_cipher = cipher;
    sealer->r_sec.buf = malloc(secret_len);
    sealer->r_sec.capa = secret_len;
    memcpy(sealer->r_sec.buf, secret, secret_len);
    quic_buf_setpl(&sealer->r_sec);
    s_module->r_level = level;

    return 1;
}

static int quic_sealer_module_set_write_secret(SSL *ssl, enum ssl_encryption_level_t level, const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len) {
    quic_sealer_module_t *const s_module = SSL_get_app_data(ssl);
    quic_sealer_t *sealer = NULL;

    switch (level) {
    case ssl_encryption_initial:
        sealer = &s_module->initial_sealer;
        break;
    case ssl_encryption_handshake:
        sealer = &s_module->handshake_sealer;
        break;
    case ssl_encryption_application:
        sealer = &s_module->app_sealer;
        break;
    case ssl_encryption_early_data:
        // ignore early data
        break;
    }
    if (sealer == NULL) {
        return 0;
    }
    sealer->w_cipher = cipher;
    sealer->w_sec.buf = malloc(secret_len);
    sealer->w_sec.capa = secret_len;
    memcpy(sealer->w_sec.buf, secret, secret_len);
    quic_buf_setpl(&sealer->w_sec);
    s_module->w_level = level;

    return 1;
}

static int quic_sealer_module_write_handshake_data(SSL *ssl, enum ssl_encryption_level_t level, const uint8_t *data, size_t len) {
    (void) level;

    quic_sealer_module_t *const s_module = SSL_get_app_data(ssl);
    quic_session_t *const session = quic_module_of_session(s_module);
    quic_framer_module_t *const f_module = quic_session_module(quic_framer_module_t, session, quic_framer_module);

    quic_frame_crypto_t *c_frame = malloc(sizeof(quic_frame_crypto_t) + len);
    if (c_frame) {
        quic_frame_init(c_frame, quic_frame_crypto_type);
        memcpy(c_frame->data, data, len);
        c_frame->len = len;
        c_frame->off = s_module->off;
        s_module->off += len;

        quic_framer_ctrl(f_module, (quic_frame_t *) c_frame);
    }

    return 1;
}

static int quic_sealer_module_flush_flight(SSL *ssl) {
    (void) ssl;
    return 1;
}

static int quic_sealer_module_send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert) {
    (void) level;

    quic_sealer_module_t *const module = SSL_get_app_data(ssl);
    module->tls_alert = alert;

    return 1;
}

static int quic_sealer_module_alpn_select_proto_cb(SSL *ssl, const uint8_t **out, uint8_t *outlen, const uint8_t *in, uint32_t inlen, void *arg) {
    (void) ssl;
    (void) arg;

    *out = in;
    *outlen = inlen;

    return SSL_TLSEXT_ERR_OK;
}

static inline int quic_sealer_module_set_chains_and_key(quic_sealer_module_t *const module, const char *const chain_file, const char *const key_file) {
    if (!chain_file || !key_file) {
        return quic_err_success;
    }

    BIO *chain_bio = BIO_new_file(chain_file, "r");
    char *name = NULL;
    char *header = NULL;
    uint8_t *data = NULL;
    long data_len = 0;

    if (!PEM_read_bio(chain_bio, &name, &header, &data, &data_len)) {
        return quic_err_internal_error;
    }
    OPENSSL_free(name);
    OPENSSL_free(header);
    name = NULL;
    header = NULL;

    CRYPTO_BUFFER *chain_buffer = CRYPTO_BUFFER_new(data, data_len, NULL);
    OPENSSL_free(data);
    BIO_free(chain_bio);

    BIO * pkey_bio = BIO_new_file(key_file, "r");
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(pkey_bio, NULL, NULL, NULL);
    BIO_free(pkey_bio);

    if (!SSL_CTX_set_chain_and_key(module->ssl_ctx, &chain_buffer, 1, pkey, NULL)) {
        return quic_err_success;
    }
    SSL_CTX_check_private_key(module->ssl_ctx);

    return quic_err_success;
}

static enum ssl_verify_result_t quic_sealer_module_custom_verify(SSL *ssl, uint8_t *const alert) {
    // TODO

    return ssl_verify_ok;
}

static quic_err_t quic_sealer_module_init(void *const module) {
    quic_sealer_module_t *const s_module = module;
    quic_session_t *const session = quic_module_of_session(s_module);

    CRYPTO_library_init();

    if (session->cfg.is_cli) {
        s_module->ssl_ctx = SSL_CTX_new(TLS_with_buffers_method());
        SSL_CTX_set_session_cache_mode(s_module->ssl_ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
        SSL_CTX_set_allow_unknown_alpn_protos(s_module->ssl_ctx, 1);
        SSL_CTX_set_custom_verify(s_module->ssl_ctx, 0, quic_sealer_module_custom_verify);
    }
    else {
        s_module->ssl_ctx = SSL_CTX_new(TLS_with_buffers_method());
        SSL_CTX_set_options(s_module->ssl_ctx, (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) | SSL_OP_SINGLE_ECDH_USE | SSL_OP_CIPHER_SERVER_PREFERENCE);
        SSL_CTX_set_mode(s_module->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

        SSL_CTX_set_alpn_select_cb(s_module->ssl_ctx, quic_sealer_module_alpn_select_proto_cb, NULL);
    }

    SSL_CTX_set_quic_method(s_module->ssl_ctx, &ssl_quic_method);

    SSL_CTX_set_session_id_context(s_module->ssl_ctx, session->dst.buf, quic_buf_size(&session->dst));

    SSL_CTX_set_min_proto_version(s_module->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(s_module->ssl_ctx, TLS1_3_VERSION);

    SSL_CTX_set_verify_algorithm_prefs(s_module->ssl_ctx, quic_signalg, sizeof(quic_signalg) / sizeof(uint16_t));

    if (session->cfg.tls_ciphers) {
        SSL_CTX_set_cipher_list(s_module->ssl_ctx, session->cfg.tls_ciphers);
    }
    else {
        SSL_CTX_set_cipher_list(s_module->ssl_ctx, QUIC_DEFAULT_TLE_CIPHERS);
    }
    if (session->cfg.tls_curve_groups) {
        SSL_CTX_set1_curves_list(s_module->ssl_ctx, session->cfg.tls_curve_groups);
    }
    else {
        SSL_CTX_set1_curves_list(s_module->ssl_ctx, QUIC_DEFAULT_CURVE_GROUPS);
    }

    if (session->cfg.tls_verify_client_ca) {
        STACK_OF(X509_NAME) *certs = SSL_load_client_CA_file(session->cfg.tls_verify_client_ca);
        SSL_CTX_set_client_CA_list(s_module->ssl_ctx, certs);
    }

    quic_sealer_module_set_chains_and_key(module, session->cfg.tls_cert_chain_file, session->cfg.tls_key_file);

    int i;
    for (i = 0; session->cfg.tls_ca && session->cfg.tls_ca[i]; i++) {
        SSL_CTX_load_verify_locations(s_module->ssl_ctx, session->cfg.tls_ca[i], NULL);
    }
    for (i = 0; session->cfg.tls_capath && session->cfg.tls_capath[i]; i++) {
        SSL_CTX_load_verify_locations(s_module->ssl_ctx, NULL, session->cfg.tls_capath[i]);
    }

    s_module->ssl = SSL_new(s_module->ssl_ctx);
    SSL_set_app_data(s_module->ssl, s_module);

    if (session->cfg.is_cli) {
        static const uint8_t H3_ALPN[] = "\x5h3-29\x5h3-30\x5h3-31\x5h3-32";
        SSL_set_alpn_protos(s_module->ssl, H3_ALPN, sizeof(H3_ALPN) - 1);

        // TODO transport parameters
        static const uint8_t transport_parameter[] = "CLIENT";
        SSL_set_quic_transport_params(s_module->ssl, transport_parameter, sizeof(transport_parameter));

        SSL_set_connect_state(s_module->ssl);
        quic_sealer_handshake_process(s_module);
    }
    else {
        SSL_set_accept_state(s_module->ssl);

        // TODO transport parameters
        static const uint8_t transport_parameter[] = "SERVER";
        SSL_set_quic_transport_params(s_module->ssl, transport_parameter, sizeof(transport_parameter));
    }

    s_module->tls_alert = 0;
    s_module->off = 0;

    s_module->r_level = ssl_encryption_initial;
    s_module->w_level = ssl_encryption_initial;
    quic_sealer_init(&s_module->app_sealer);
    quic_sealer_init(&s_module->handshake_sealer);
    quic_sealer_init(&s_module->initial_sealer);

    return quic_err_success;
}

quic_module_t quic_sealer_module = {
    .name        = "sealer",
    .module_size = sizeof(quic_sealer_module_t),
    .init        = quic_sealer_module_init,
    .process     = NULL,
    .loop        = NULL,
    .destory     = NULL
};

quic_err_t quic_session_handle_crypto_frame(quic_session_t *const session, const quic_frame_t *const frame) {
    quic_frame_crypto_t *const c_frame = (quic_frame_crypto_t *) frame;
    quic_sealer_module_t *const s_module = quic_session_module(quic_sealer_module_t, session, quic_sealer_module);

    SSL_provide_quic_data(s_module->ssl, s_module->r_level, c_frame->data, c_frame->len);

    quic_sealer_handshake_process(s_module);

    return quic_err_success;
}
