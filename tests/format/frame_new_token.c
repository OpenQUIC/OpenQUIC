#include "format/frame.h"
#include <malloc.h>

int main() {
    uint8_t data[128];
    quic_buf_t buf;
    buf.buf = data;
    buf.capa = 128;
    quic_buf_setpl(&buf);
    
    quic_frame_new_token_t *token = malloc(sizeof(quic_frame_new_token_t) + 32);

    token->first_byte = quic_frame_new_token_type;
    token->len = 32;
    int i;
    for (i = 0; i < 32; i++) {
        *(token->data + i) = i;
    }

    quic_frame_format(&buf, token);

    printf("%ld\n", quic_buf_size(&buf));

    quic_buf_setpl(&buf);
    quic_frame_new_token_t *frame = NULL;
    quic_frame_parse(frame, &buf);

    printf("%lx\n", frame->len);
    for (i = 0; i < 32; i++) {
        printf("%02x ", *(frame->data + i));
    }
    printf("\n");

    return 0;
}
