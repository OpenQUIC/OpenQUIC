#include "client.h"
#include "modules/stream.h"

quic_err_t handshake_done_cb(quic_session_t *const session) {
    quic_stream_t *stream = quic_session_open(session, sizeof(int), true);

    quic_stream_extends(int, stream) = 1024 * 1024;

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
