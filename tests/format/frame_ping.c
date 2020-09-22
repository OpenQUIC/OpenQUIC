#include "format/frame.h"

int main() {
    quic_frame_ping_t ping;

    ping.first_byte = quic_frame_ping_type;

    uint8_t data[128];
    quic_buf_t buf;
    buf.buf = data;
    buf.pos = buf.buf;
    buf.last = buf.buf + 128;

    quic_frame_format(&buf, (quic_frame_t *) &ping);

    printf("%ld\n", quic_buf_size(&buf));
    printf("%x\n", data[0]);

    buf.pos = data;
    quic_frame_t *frame;
    quic_frame_parse(frame, &buf);

    printf("%x\n", frame->first_byte);

    return 0;
}
