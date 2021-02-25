#include "client.h"
#include "modules/stream.h"

uint8_t buf[255];

quic_err_t read_done(quic_stream_t *const str, void *const data, const size_t capa, const size_t len) {
    (void) capa;
    (void) len;

    printf("recv: %s\n", (char *) data);

    quic_stream_close(str, NULL);

    quic_session_t *session = quic_stream_session(str);
    quic_session_close(session);

    return quic_err_success;
}

quic_err_t write_done(quic_stream_t *const str, void *data, const size_t capa, const size_t len) {
    (void) data;
    (void) capa;
    (void) len;

    printf("send: ping\n");

    quic_stream_read(str, buf, sizeof(buf), read_done);

    return quic_err_success;
}

quic_err_t handshake_done_cb(quic_session_t *const session) {
    quic_stream_t *stream = quic_session_open(session, true);
    quic_stream_write(stream, "ping", 5, write_done);

    return quic_err_success;
}

int main() {
    quic_client_t client;
    quic_client_init(&client, 8192);

    quic_client_path_use(&client, quic_path_ipv4("127.0.0.1", 11000, "127.0.0.1", 11001));
    quic_client_handshake_done(&client, handshake_done_cb);

    quic_client_start_loop(&client);

    return 0;
}
