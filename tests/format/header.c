#include "format/header.h"
#include <stdio.h>

int main() {
    uint8_t bytes[] = {
        0x80,
        0x01, 0x02, 0x03, 0x04,
        0x04,
        0x05, 0x06, 0x07, 0x08,
        0x06,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,

        0x10, 0x12, 0x13, 0x14
    };

    quic_long_header_t *header = (quic_long_header_t *) bytes;

    printf("%d %d\n", quic_long_header_dst_conn_len(header), quic_long_header_src_conn_len(header));

    printf("%x\n", *(uint8_t *) quic_long_header_payload(header));

    printf("%ld\n", quic_long_header_len(header));

    return 0;
}
