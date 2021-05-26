#include "server.h"
#include "modules/stream.h"
#include "liteco.h"
#include <stdio.h>

uint8_t buf[256];

quic_err_t write_done(quic_stream_t *const str, void *data, const size_t capa, const size_t len) {
    (void) data;
    (void) capa;
    (void) len;

    printf("send: pong\n");

    quic_stream_close(str, NULL);

    return quic_err_success;
}

quic_err_t read_done(quic_stream_t *const str, void *const data, const size_t capa, const size_t len) {
    (void) str;
    (void) capa;
    (void) len;

    printf("recv: %s\n", (char *) data);

    quic_stream_write(str, "pong", 5, write_done);

    return quic_err_success;
}

quic_err_t accept_stream(quic_stream_t *const str) {
    quic_stream_read(str, buf, sizeof(buf), read_done);

    return quic_err_success;
}

quic_err_t handshake_done(quic_session_t *const session) {
    quic_session_accept(session, 0, accept_stream);

    return quic_err_success;
}

void on_close(quic_session_t *const session) {
    (void) session;

    printf("closed\n");
}

quic_err_t accept_session(quic_session_t *const session) {
    quic_session_handshake_done(session, handshake_done);

    quic_session_on_close(session, on_close);

    return quic_err_success;
}

int main() {

    quic_server_t server;
    quic_server_init(&server, 0, 8192);

    quic_server_listen(&server, liteco_ipv4("127.0.0.1", 11001));

    quic_server_cert_file(&server, "./tests/crt.crt");
    quic_server_key_file(&server, "./tests/key.key");

    quic_server_accept(&server, accept_session);

    quic_server_start_loop(&server);

    return 0;
}
