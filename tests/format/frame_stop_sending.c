#include "format/frame.h"

int main() {
    uint8_t data[128];
    quic_buf_t buf;
    buf.buf = data;
    buf.pos = buf.buf;
    buf.last = buf.buf + 128;

    quic_frame_stop_sending_t stop_sending;

    stop_sending.first_byte = quic_frame_stop_sending_type;
    stop_sending.sid = 0x123456;
    stop_sending.app_err = 0xabcdef;

    quic_frame_format(&buf, &stop_sending);

    printf("%ld\n", quic_buf_size(&buf));

    buf.pos = buf.buf;
    quic_frame_stop_sending_t *frame = NULL;
    quic_frame_parse(frame, &buf);

    printf("%lx\n", frame->sid);
    printf("%lx\n", frame->app_err);

    return 0;
}
