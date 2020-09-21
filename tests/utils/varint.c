#include "utils/varint.h"
#include "utils/buf.h"
#include <stdio.h>

void parse8() {
    uint8_t bytes[] = { 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c };

    printf("%d\n", quic_varint_r(bytes) == 151288809941952652UL);
}

void parse4() {
    uint8_t bytes[] = { 0x9d, 0x7f, 0x3e, 0x7d };

    printf("%d\n", quic_varint_r(bytes) == 494878333);
}

void parse2() {
    uint8_t bytes[] = { 0x7b, 0xbd };

    printf("%d\n", quic_varint_r(bytes) == 15293);
}

void parse1() {
    uint8_t bytes[] = { 0x25 };

    printf("%d\n", quic_varint_r(bytes) == 37);
}

void format1() {
    uint8_t ser;
    quic_buf_t buf;
    buf.pos = &ser;
    quic_varint_format_r(&buf, 37);
    printf("%x\n", ser);
}

void format2() {
    uint16_t ser;
    quic_buf_t buf;
    buf.pos = &ser;
    quic_varint_format_r(&buf, 15293);
    printf("%x\n", ser);
}

void format3() {
    uint32_t ser;
    quic_buf_t buf;
    buf.pos = &ser;
    quic_varint_format_r(&buf, 494878333);
    printf("%x\n", ser);
}

void format4() {
    uint64_t ser;
    quic_buf_t buf;
    buf.pos = &ser;
    quic_varint_format_r(&buf, 151288809941952652UL);
    printf("%lx\n", ser);
}

int main() {
    parse1();
    parse2();
    parse4();
    parse8();

    format1();
    format2();
    format3();
    format4();

    return 0;
}
