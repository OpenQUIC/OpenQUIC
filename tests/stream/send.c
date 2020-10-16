#include "module.h"
#include "modules/stream.h"
#include "recovery/flowctrl.h"
#include "liteco.h"
#include <pthread.h>
#include <unistd.h>

quic_send_stream_t *str;
liteco_channel_t channel;

void *thread(void *const args) {
    (void) args;
    sleep(1);

    char line[] = "Hello World\n";

    printf("HELLO %ld\n", sizeof(line));
    quic_send_stream_write(str, line, sizeof(line));

    sleep(10);

    quic_send_stream_write(str, line, sizeof(line));

    return NULL;
}

uint64_t get_swnd(quic_stream_flowctrl_t *const flowctrl) {
    (void) flowctrl;
    return 13;
}

liteco_runtime_t rt;

int quic_generate_co(void *const args) {
    (void) args;

    liteco_recv(NULL, NULL, &rt, 0, &channel);
    printf("World\n");

    quic_frame_stream_t *frame = quic_send_stream_generate(str, 1024, true);
    printf("%ld %s\n", frame->len, frame->data);
    liteco_recv(NULL, NULL, &rt, 0, &channel);

    frame = quic_send_stream_generate(str, 1024, true);
    printf("%ld %s\n", frame->len, frame->data);
    return 0;
}

quic_stream_flowctrl_module_t quic_flowctrl_module = {
    .get_swnd = get_swnd
};

quic_module_t quic_connection_flowctrl_module = {
    .module_size = 0,
    .init        = NULL,
    .destory     = NULL
};

quic_err_t quic_stream_flowctrl_module_init(void *const module, quic_session_t *const sess) {
    (void) sess;

    quic_stream_flowctrl_module_t *const ref = module;
    ref->init = NULL;
    ref->get_swnd = get_swnd;

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

    quic_stream_t *stream = quic_stream_create(1, session, 0, &channel, &channel);
    str = &stream->send;

    pthread_t pthread;

    liteco_channel_init(&channel);

    pthread_create(&pthread, NULL, thread, NULL);


    liteco_runtime_init(&rt);
    liteco_coroutine_t co;
    uint8_t stack[4096];
    liteco_create(&co, stack, sizeof(stack), quic_generate_co, NULL, NULL);
    liteco_runtime_join(&rt, &co);

    while (co.status != LITECO_TERMINATE) {
        liteco_runtime_execute(&rt, &co);
    }

    return 0;
}
