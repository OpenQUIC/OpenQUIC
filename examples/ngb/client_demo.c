#include "client.h"
#include "modules/stream.h"

uint8_t data[1024] = { 0 };
void stream_write_block(quic_stream_t *const stream);

quic_err_t write_done_cb(quic_stream_t *const stream, void *const data, const size_t capa, const size_t len) {
    (void) data;
    (void) capa;
    (void) len;

    printf("sended %dKB\n", 1024 * 1024 - quic_stream_extends(int, stream));

    stream_write_block(stream);

    return quic_err_success;
}

void stream_write_block(quic_stream_t *const stream) {
    if (quic_stream_extends(int, stream)) {
        quic_stream_write(stream, data, sizeof(data), write_done_cb);

        quic_stream_extends(int, stream)--;
    }
    else {
        quic_stream_close(stream, NULL);
    }
}

quic_err_t handshake_done_cb(quic_session_t *const session) {
    quic_stream_t *stream = quic_session_open(session, sizeof(int), true);

    quic_stream_extends(int, stream) = 1024 * 1024;

    stream_write_block(stream);

    return quic_err_success;
}

int main() {
    quic_client_t client;
    quic_client_init(&client, 0, 8192);

    quic_client_path_use(&client, quic_path_ipv4("127.0.0.1", 11000, "127.0.0.1", 11001));
    quic_client_handshake_done(&client, handshake_done_cb);

    quic_client_start_loop(&client);

    return 0;
}
