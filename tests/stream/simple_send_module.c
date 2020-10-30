#include "utils/buf.h"
#include "session.h"
#include "modules/stream.h"
#include <arpa/inet.h>
#include <unistd.h>

uint64_t get_swnd(quic_stream_flowctrl_t *const flowctrl) {
    (void) flowctrl;
    return 13;
}

void sent(quic_stream_flowctrl_t *const flowctrl, const uint64_t bytes) {
    (void) flowctrl;
    (void) bytes;
}

quic_err_t quic_stream_flowctrl_module_init(void *const module) {
    quic_stream_flowctrl_module_t *const ref = module;
    ref->init = NULL;
    ref->get_swnd = get_swnd;
    ref->sent = sent;

    return quic_err_success;
}

quic_module_t quic_stream_flowctrl_module = {
    .module_size = sizeof(quic_stream_flowctrl_module_t),
    .init        = quic_stream_flowctrl_module_init,
    .destory     = NULL
};

quic_module_t quic_connection_flowctrl_module = {
    .module_size = 0,
    .init = NULL,
    .destory = NULL
};

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
