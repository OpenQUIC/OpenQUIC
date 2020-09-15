#include "utils/varint.h"
#include <stdio.h>

int main() {
    /*uint8_t bytes[] = { 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c };*/
    /*uint8_t bytes[] = { 0x9d, 0x7f, 0x3e, 0x7d };*/
    /*uint8_t bytes[] = { 0x7b, 0xbd };*/
    uint8_t bytes[] = { 0x25 };

    printf("%ld\n", quic_varint_r(bytes));

    return 0;
}
