#include "stream.h"
#include "liteco.h"
#include <pthread.h>
#include <unistd.h>

bool abandon(quic_flowctrl_t *const flowctrl) {
    (void) flowctrl;


    return true;
}

void update_rwnd(quic_flowctrl_t *const flowctrl, const uint64_t rwnd, const bool fin) {
    (void) flowctrl;
    (void) rwnd;
    (void) fin;
}

quic_recv_stream_t str;
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
    quic_recv_stream_handle_frame(&str, frame1);

    sleep(3);
    quic_recv_stream_handle_frame(&str, frame2);


    return NULL;
}

int quic_handle_co(void *const args) {
    (void) args;

    return 0;
}

int main() {
    pthread_t pthread;

    quic_flowctrl_t flowctrl = { };
    flowctrl.abandon = abandon;
    flowctrl.update_rwnd = update_rwnd;

    liteco_channel_init(&channel);
    liteco_runtime_init(&rt);

    quic_recv_stream_init(&str, 1, &flowctrl, &channel);

    pthread_create(&pthread, NULL, thread, NULL);

    uint8_t line[255];
    uint64_t len = quic_recv_stream_read(&str, sizeof(line), line);

    printf("%ld %s\n", len, line);

    return 0;
}
