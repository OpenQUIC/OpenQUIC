#include "utils/buf.h"
#include "session.h"
#include "modules/stream.h"
#include <arpa/inet.h>
#include <unistd.h>

int main() {
    quic_config_t cfg = { };
    cfg.conn_len = 1;
    cfg.is_cli = true;
    cfg.src.buf = "1";
    cfg.src.capa = 1;
    quic_buf_setpl(&cfg.src);
    cfg.dst.buf = "1";
    cfg.dst.capa = 1;
    quic_buf_setpl(&cfg.dst);
    cfg.disable_prr = false;
    cfg.initial_cwnd = 1460;
    cfg.min_cwnd = 1460;
    cfg.max_cwnd = 10 * 1460;
    cfg.slowstart_large_reduction = true;
    cfg.stream_flowctrl_initial_rwnd = 1460;
    cfg.stream_flowctrl_max_rwnd_size = 5 * 1460;
    cfg.stream_flowctrl_initial_swnd = 1460;


    cfg.local_addr.v4.sin_addr.s_addr = inet_addr("127.0.0.1");
    cfg.remote_addr.v4.sin_addr.s_addr = inet_addr("127.0.0.1");
    cfg.local_addr.v4.sin_family = AF_INET;
    cfg.remote_addr.v4.sin_family = AF_INET;
    cfg.remote_addr.v4.sin_port = htons(11001);
    cfg.local_addr.v4.sin_port = htons(11000);

    quic_session_t *const session = quic_session_create(cfg);
    quic_stream_t *stream = quic_session_open_stream(session, true);
    quic_stream_write(stream, "fuckyou", 7);

    return 0;
}
