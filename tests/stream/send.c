#include "stream.h"
#include "liteco.h"
#include <pthread.h>
#include <unistd.h>

quic_send_stream_t str;
liteco_channel_t channel;

void *thread(void *const args) {
    (void) args;
    sleep(1);

    char line[] = "Hello World\n";

    printf("HELLO %ld\n", sizeof(line));
    quic_send_stream_write(&str, sizeof(line), line);

    sleep(10);

    quic_send_stream_write(&str, sizeof(line), line);

    return NULL;
}

uint64_t quic_flowctrl_get_swnd_impl(quic_flowctrl_t *const flowctrl) {
    (void) flowctrl;
    return 13;
}

liteco_runtime_t rt;

int quic_generate_co(void *const args) {
    (void) args;

    liteco_recv(NULL, NULL, &rt, 0, &channel);
    printf("World\n");

    quic_frame_stream_t *frame = quic_send_stream_generate(&str, 1024, true);
    printf("%ld %s\n", frame->len, frame->data);
    liteco_recv(NULL, NULL, &rt, 0, &channel);

    frame = quic_send_stream_generate(&str, 1024, true);
    printf("%ld %s\n", frame->len, frame->data);
    return 0;
}

quic_flowctrl_module_t quic_flowctrl_module = {
    .get_swnd = quic_flowctrl_get_swnd_impl
};

int main() {
    pthread_t pthread;

    liteco_channel_init(&channel);

    quic_send_stream_init(&str, 1, NULL, &channel);
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
