#include "format/frame.h"
#include <malloc.h>

void common_ack() {

    uint8_t data[128];
    quic_buf_t buf;
    buf.buf = data;
    buf.pos = buf.buf;
    buf.last = buf.buf + 128;

    quic_frame_ack_t *ack = malloc(sizeof(quic_frame_ack_t) + 3 * sizeof(quic_ack_range_t));
    ack->first_byte = quic_frame_ack_type;

    ack->largest_ack = 0x1234;
    ack->delay = 0x1235;
    ack->first_range = 0x1236;

    uint64_t i;
    quic_arr_t *ranges = &ack->ranges;
    ranges->count = 3;
    for (i = 0; i < 3; i++) {
        quic_arr(ranges, i, quic_ack_range_t)->gap = 0x1237;
        quic_arr(ranges, i, quic_ack_range_t)->len = 0x1238;
    }

    quic_frame_format(&buf, ack);

    printf("%ld\n", quic_buf_size(&buf));

    for (i = 0; i < (uint64_t) (buf.pos - buf.buf); i++) {
        printf("%02x ", *((uint8_t *) buf.buf + i));
    }
    printf("\n");


    buf.pos = buf.buf;
    quic_frame_ack_t *frame = NULL;

    quic_frame_parse(frame, &buf);
    printf("%lx\n", frame->largest_ack);
    printf("%lx\n", frame->delay);
    printf("%lx\n", frame->first_range);
    ranges = &frame->ranges;
    for (i = 0; i < ranges->count; i++) {
        printf("%lx\n", quic_arr(ranges, i, quic_ack_range_t)->gap);
        printf("%lx\n", quic_arr(ranges, i, quic_ack_range_t)->len);
    }
}

void ecn_ack() {

    uint8_t data[128];
    quic_buf_t buf;
    buf.buf = data;
    buf.pos = buf.buf;
    buf.last = buf.buf + 128;

    quic_frame_ack_t *ack = malloc(sizeof(quic_frame_ack_t) + 3 * sizeof(quic_ack_range_t));
    ack->first_byte = quic_frame_ack_ecn_type;

    ack->largest_ack = 0x123456;
    ack->delay = 0x123578;
    ack->first_range = 0x123690;

    ack->ect0 = 0xabcd;
    ack->ect1 = 0xef01;
    ack->ect_ce = 0x2345;

    uint64_t i;
    quic_arr_t *ranges = &ack->ranges;
    ranges->count = 3;
    for (i = 0; i < 3; i++) {
        quic_arr(ranges, i, quic_ack_range_t)->gap = 0x1237ab;
        quic_arr(ranges, i, quic_ack_range_t)->len = 0x1238cd;
    }

    quic_frame_format(&buf, (quic_frame_t *) ack);

    printf("%ld\n", quic_buf_size(&buf));

    for (i = 0; i < (uint64_t) (buf.pos - buf.buf); i++) {
        printf("%02x ", *((uint8_t *) buf.buf + i));
    }
    printf("\n");


    buf.pos = buf.buf;
    quic_frame_ack_t *frame = NULL;

    quic_frame_parse(frame, &buf);
    printf("%lx\n", frame->largest_ack);
    printf("%lx\n", frame->delay);
    printf("%lx\n", frame->first_range);
    ranges = &frame->ranges;
    for (i = 0; i < ranges->count; i++) {
        printf("%lx\n", quic_arr(ranges, i, quic_ack_range_t)->gap);
        printf("%lx\n", quic_arr(ranges, i, quic_ack_range_t)->len);
    }

    printf("%lx\n", frame->ect0);
    printf("%lx\n", frame->ect1);
    printf("%lx\n", frame->ect_ce);
}

int main() {
    common_ack();
    ecn_ack();

    return 0;
}
