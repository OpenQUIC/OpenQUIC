/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "format/header.h"
#include "modules/sealer.h"
#include "session.h"
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/hkdf.h>
#include <byteswap.h>

#define QUIC_DEFAULT_TLE_CIPHERS                     \
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:" \
    "TLS_CHACHA20_POLY1305_SHA256"

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
static inline quic_err_t quic_sealer_module_set_key_iv(quic_buf_t *const key, quic_buf_t *const iv, const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len);
static inline quic_err_t quic_sealer_module_hkdf_expand_label(uint8_t *out, const size_t outlen, const EVP_MD *prf, const uint8_t *secret, size_t secret_len, const uint8_t *label, size_t label_size);

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

static inline quic_err_t quic_sealer_module_hkdf_expand_label(uint8_t *out, const size_t outlen, const EVP_MD *prf, const uint8_t *secret, size_t secret_len, const uint8_t *label, size_t label_size) {
    uint8_t hkdf_label[19] = { };
    size_t hkdf_label_size = 2 + 1 + 6 + label_size + 1;

    *(uint16_t *) hkdf_label = bswap_16((uint16_t) outlen);
    *(uint8_t *) (hkdf_label + 2) = 6 + label_size + 1;
    memcpy(hkdf_label + 3, "tls13 ", 6);
    memcpy(hkdf_label + 3 + 6, label, label_size);
    hkdf_label[3 + 6 + label_size] = 0;

    if (!HKDF_expand(out, outlen, prf, secret, secret_len, hkdf_label, hkdf_label_size)) {
        return quic_err_internal_error;
    }

    return quic_err_success;
}

static inline quic_err_t quic_sealer_module_set_key_iv(quic_buf_t *const key, quic_buf_t *const iv, const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len) {
    static const uint8_t key_label[] = "quic key";
    static const uint8_t iv_label[] = "quic iv";

    const EVP_MD *prf = EVP_get_digestbynid(SSL_CIPHER_get_prf_nid(cipher));
    quic_sealer_module_hkdf_expand_label(key->buf, key->capa, prf, secret, secret_len, key_label, sizeof(key_label) - 1);
    quic_sealer_module_hkdf_expand_label(iv->buf, iv->capa, prf, secret, secret_len, key_label, sizeof(iv_label) - 1);

    return quic_err_success;
}

#define quic_sealer_alloc_buf(_buf, size) { \
    (_buf).capa = size;                     \
    if (!((_buf).buf = malloc(size))) {     \
        return quic_err_internal_error;     \
    }                                       \
    quic_buf_setpl(&(_buf));                \
}

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
    sealer->r_sec.buf = malloc(secret_len);
    sealer->r_sec.capa = secret_len;
    memcpy(sealer->r_sec.buf, secret, secret_len);
    quic_buf_setpl(&sealer->r_sec);
    s_module->r_level = level;

    switch (SSL_CIPHER_get_id(cipher)) {
    case TLS1_CK_AES_128_GCM_SHA256:
        sealer->r_aead = EVP_aead_aes_128_gcm;
        quic_sealer_alloc_buf(sealer->r_key, 16);
        quic_sealer_alloc_buf(sealer->r_iv, 12);
        sealer->r_aead_tag_size = 16;

        break;

    case TLS1_CK_AES_256_GCM_SHA384:
        sealer->r_aead = EVP_aead_aes_256_gcm;
        quic_sealer_alloc_buf(sealer->r_key, 32);
        quic_sealer_alloc_buf(sealer->r_iv, 12);
        sealer->r_aead_tag_size = 16;

        break;

    case TLS1_CK_CHACHA20_POLY1305_SHA256:
        sealer->r_aead = EVP_aead_chacha20_poly1305;
        quic_sealer_alloc_buf(sealer->r_key, 32);
        quic_sealer_alloc_buf(sealer->r_iv, 12);
        sealer->r_aead_tag_size = 16;

        break;
    }

    quic_sealer_module_set_key_iv(&sealer->r_key, &sealer->r_iv, cipher, secret, secret_len);
    if (sealer->r_ctx) {
        EVP_AEAD_CTX_free(sealer->r_ctx);
    }
    sealer->r_ctx = EVP_AEAD_CTX_new(sealer->r_aead(), sealer->r_key.buf, sealer->r_key.capa, sealer->r_aead_tag_size);

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
    sealer->w_sec.buf = malloc(secret_len);
    sealer->w_sec.capa = secret_len;
    memcpy(sealer->w_sec.buf, secret, secret_len);
    quic_buf_setpl(&sealer->w_sec);
    s_module->w_level = level;

    switch (SSL_CIPHER_get_id(cipher)) {
    case TLS1_CK_AES_128_GCM_SHA256:
        sealer->w_aead = EVP_aead_aes_128_gcm;
        quic_sealer_alloc_buf(sealer->w_key, 16);
        quic_sealer_alloc_buf(sealer->w_iv, 12);
        sealer->w_aead_tag_size = 16;

        break;

    case TLS1_CK_AES_256_GCM_SHA384:
        sealer->w_aead = EVP_aead_aes_256_gcm;
        quic_sealer_alloc_buf(sealer->w_key, 32);
        quic_sealer_alloc_buf(sealer->w_iv, 12);
        sealer->w_aead_tag_size = 16;

        break;

    case TLS1_CK_CHACHA20_POLY1305_SHA256:
        sealer->w_aead = EVP_aead_chacha20_poly1305;
        quic_sealer_alloc_buf(sealer->w_key, 32);
        quic_sealer_alloc_buf(sealer->w_iv, 12);
        sealer->w_aead_tag_size = 16;

        break;
    }

    quic_sealer_module_set_key_iv(&sealer->w_key, &sealer->w_iv, cipher, secret, secret_len);
    if (sealer->w_ctx) {
        EVP_AEAD_CTX_free(sealer->w_ctx);
    }
    sealer->w_ctx = EVP_AEAD_CTX_new(sealer->w_aead(), sealer->w_key.buf, sealer->w_key.capa, sealer->w_aead_tag_size);

    return 1;
}

#undef quic_sealer_alloc_buf

static int quic_sealer_module_write_handshake_data(SSL *ssl, enum ssl_encryption_level_t level, const uint8_t *data, size_t len) {
    quic_sealer_module_t *const s_module = SSL_get_app_data(ssl);
    quic_session_t *const session = quic_module_of_session(s_module);

    switch (level) {
    case ssl_encryption_initial:
        quic_sorter_append(&s_module->initial_w_sorter, len, data);
        quic_module_activate(session, quic_sealer_module);
        break;
    case ssl_encryption_handshake:
        quic_sorter_append(&s_module->handshake_w_sorter, len, data);
        quic_module_activate(session, quic_sealer_module);
        break;
    default:
        break;
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
    (void) ssl;
    (void) alert;

    return ssl_verify_ok;
}

static quic_err_t quic_sealer_module_init(void *const module) {
    quic_sealer_module_t *const s_module = module;
    quic_session_t *const session = quic_module_of_session(s_module);

    s_module->tls_alert = 0;
    s_module->off = 0;
    s_module->level = ssl_encryption_initial;
    s_module->handshake_done_cb = NULL;

    s_module->r_level = ssl_encryption_initial;
    s_module->w_level = ssl_encryption_initial;
    quic_sealer_init(&s_module->app_sealer);
    quic_sealer_init(&s_module->handshake_sealer);
    quic_sealer_init(&s_module->initial_sealer);

    quic_sorter_init(&s_module->initial_r_sorter);
    quic_sorter_init(&s_module->initial_w_sorter);
    quic_sorter_init(&s_module->handshake_r_sorter);
    quic_sorter_init(&s_module->handshake_w_sorter);

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
    quic_sorter_t *sorter = NULL;

    switch (c_frame->packet_type & 0xf0) {
    case quic_packet_initial_type:
        sorter = &s_module->initial_r_sorter;
        break;

    case quic_packet_handshake_type:
        sorter = &s_module->handshake_r_sorter;
        break;

    default:
        return quic_err_internal_error;
    }

    quic_sorter_write(sorter, c_frame->off, c_frame->len, c_frame->data);

    for ( ;; ) {
        uint32_t fragment_size = 0;
        if (quic_sorter_readable(sorter) < 4) {
            return quic_err_success;
        }
        quic_sorter_peek(sorter, 4, &fragment_size);
        fragment_size = bswap_32(fragment_size & 0xFFFFFF00);
        fragment_size += 4;

        if (quic_sorter_readable(sorter) < fragment_size) {
            return quic_err_success;
        }

        uint8_t *fragment = malloc(fragment_size);
        if (fragment == NULL) {
            return quic_err_internal_error;
        }
        quic_sorter_read(sorter, fragment_size, fragment);

        SSL_provide_quic_data(s_module->ssl, s_module->r_level, fragment, fragment_size);
        free(fragment);

        quic_sealer_handshake_process(s_module);
    }

    return quic_err_success;
}

quic_err_t quic_session_handle_handshake_done_frame(quic_session_t *const session, const quic_frame_t *const frame) {
    (void) frame;
    quic_sealer_module_t *const s_module = quic_session_module(quic_sealer_module_t, session, quic_sealer_module);

    if (!session->cfg.is_cli) {
        return quic_err_internal_error;
    }
    quic_sealer_set_level(s_module, ssl_encryption_application);

    return quic_err_success;
}
