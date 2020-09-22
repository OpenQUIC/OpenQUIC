#include "format/frame.h"
#include <malloc.h>

int main() {
    uint8_t data[128];
    quic_buf_t buf;
    buf.buf = data;
    buf.capa = 128;
    quic_buf_setpl(&buf);

    quic_frame_crypto_t *crypto = malloc(sizeof(quic_frame_crypto_t) + 32);

    crypto->first_byte = quic_frame_crypto_type;
    crypto->off = 0x123456;
    crypto->len = 32;

    int i;
    for (i = 0; i < 32; i++) {
        *(crypto->data + i) = i;
    }

    quic_frame_format(&buf, &crypto);

    printf("%ld\n", quic_buf_size(&buf));

    quic_buf_setpl(&buf);
    quic_frame_crypto_t *frame = NULL;
    quic_frame_parse(frame, &buf);

    printf("%lx\n", crypto->off);
    printf("%lx\n", crypto->len);
    for (i = 0; i < 32; i++) {
        printf("%02x ", *(crypto->data + i));
    }
    printf("\n");

    return 0;
}
