#include "format/frame.h"

int main() {
    uint8_t data[128];
    quic_buf_t buf;
    buf.buf = data;
    buf.pos = buf.buf;
    buf.last = buf.buf + 128;

    quic_frame_reset_stream_t reset_stream;

    reset_stream.first_byte = quic_frame_reset_stream_type;
    reset_stream.sid = 0xabcdef;
    reset_stream.app_err = 0x123456;
    reset_stream.final_size = 0x789abc;

    quic_frame_format(&buf, &reset_stream);

    printf("%ld\n", quic_buf_size(&buf));

    buf.pos = buf.buf;
    quic_frame_reset_stream_t *frame = NULL;
    quic_frame_parse(frame, &buf);

    printf("%lx\n", frame->sid);
    printf("%lx\n", frame->app_err);
    printf("%lx\n", frame->final_size);

    return 0;
}
