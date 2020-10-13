#include "module.h"
#include "modules/stream.h"
#include "recovery/flowctrl.h"
#include "liteco.h"
#include <pthread.h>
#include <unistd.h>

bool abandon(quic_stream_flowctrl_t *const flowctrl) {
    (void) flowctrl;

    return true;
}

void update_rwnd(quic_stream_flowctrl_t *const flowctrl, const uint64_t rwnd, const bool fin) {
    (void) flowctrl;
    (void) rwnd;
    (void) fin;
}

quic_recv_stream_t *str;
liteco_channel_t channel;

liteco_runtime_t rt;

void *thread(void *const args) {
    (void) args;

    char line[] = "Hello World\n";

    quic_frame_stream_t *frame1 = malloc(sizeof(quic_frame_stream_t) + 5);
    frame1->first_byte = quic_frame_stream_type | quic_frame_stream_type_len;
    frame1->off = 0;
    frame1->len = 5;
    frame1->sid = 1;
    memcpy(frame1->data, line, 5);

    quic_frame_stream_t *frame2 = malloc(sizeof(quic_frame_stream_t) + sizeof(line) - 5);
    frame2->first_byte = quic_frame_stream_type | quic_frame_stream_type_len | quic_frame_stream_type_off | quic_frame_stream_type_fin;
    frame2->off = 5; 
    frame2->len = sizeof(line) - 5;
    frame2->sid = 1;
    memcpy(frame2->data, (uint8_t *) line + 5, sizeof(line) - 5);

    sleep(3);
    quic_recv_stream_handle_frame(str, frame1);

    sleep(3);
    quic_recv_stream_handle_frame(str, frame2);


    return NULL;
}

int quic_handle_co(void *const args) {
    (void) args;

    return 0;
}

quic_module_t quic_connection_flowctrl_module = {
    .module_size = 0,
    .init        = NULL,
    .destory     = NULL
};

quic_err_t quic_stream_flowctrl_module_init(void *const module, quic_session_t *const sess) {
    (void) sess;

    quic_stream_flowctrl_module_t *const ref = module;
    ref->init = NULL;
    ref->abandon = abandon;
    ref->update_rwnd = update_rwnd;

    return quic_err_success;
}

quic_module_t quic_stream_flowctrl_module = {
    .module_size = sizeof(quic_stream_flowctrl_module_t),
    .init        = quic_stream_flowctrl_module_init,
    .destory     = NULL
};

int main() {
    quic_buf_t src = { .buf = "1", .capa = 1 };
    quic_buf_t dst = { .buf = "1", .capa = 1 };
    quic_session_t *session = quic_session_create(src, dst);

    quic_stream_t *stream = quic_stream_create(1, session, &channel, &channel);
    str = &stream->recv;

    pthread_t pthread;

    liteco_channel_init(&channel);
    liteco_runtime_init(&rt);

    pthread_create(&pthread, NULL, thread, NULL);

    uint8_t line[255];
    uint64_t len = quic_recv_stream_read(str, sizeof(line), line);

    printf("%ld %s\n", len, line);

    return 0;
}
