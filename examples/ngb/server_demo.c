#include "server.h"
#include "modules/stream.h"
#include <stdio.h>

uint8_t buf[256];

quic_err_t closed_cb(quic_stream_t *const str) {
    (void) str;

    printf("closed\n");

    return quic_err_success;
}

quic_err_t read_done(quic_stream_t *const str, void *const buf, const size_t capa, const size_t len) {
    quic_stream_extends(int, str) += len;
    printf("%d\n", quic_stream_extends(int, str));

    if (len == 0 && quic_stream_fin(str)) {
        quic_stream_close(str, closed_cb);
        return quic_err_success;
    }

    quic_stream_read(str, buf, capa, read_done);

    return quic_err_success;
}

quic_err_t accept_stream(quic_stream_t *const str) {
    quic_stream_read(str, buf, sizeof(buf), read_done);

    return quic_err_success;
}

quic_err_t handshake_done(quic_session_t *const session) {
    quic_session_accept(session, sizeof(int), accept_stream);

    return quic_err_success;
}

void on_close(quic_session_t *const session) {
    (void) session;

    printf("closed\n");
}

quic_err_t accept_session_cb(quic_session_t *const session) {
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

    quic_server_accept(&server, accept_session_cb);

    quic_server_start_loop(&server);

    return 0;
}
