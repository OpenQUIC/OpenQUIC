#include "utils/buf.h"
#include "session.h"
#include "modules/stream.h"
#include "modules/udp_fd.h"
#include <arpa/inet.h>

int main() {
    quic_config_t cfg = { };
    cfg.conn_len = 1;
    cfg.is_cli = false;
    cfg.src.buf = "1";
    cfg.src.capa = 1;
    quic_buf_setpl(&cfg.src);
    cfg.dst.buf = "1";
    cfg.dst.capa = 1;
    quic_buf_setpl(&cfg.dst);
    cfg.stream_recv_timeout = 1000 * 1000;
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
    cfg.remote_addr.v4.sin_port = htons(11000);
    cfg.local_addr.v4.sin_port = htons(11001);

    quic_session_t *const session = quic_session_create(cfg);

    quic_session_recv_packet(session);

    quic_stream_t *stream = quic_session_accept_stream(session, true);
    uint8_t buf[255];
    quic_stream_read(stream, buf, sizeof(buf));

    printf("%s\n", buf);

    return 0;
}
