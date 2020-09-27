#include "sorter.h"
#include <stdio.h>

int main() {
    quic_sorter_t sorter;

    quic_sorter_init(&sorter);

    uint8_t data1[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa0 };
    quic_sorter_write(&sorter, 12, sizeof(data1), data1);
    printf("%ld\n", quic_sorter_readable(&sorter));
    printf("%ld\n", sorter.avail_size);

    uint8_t data2[] = { 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0xc, 0x0d, 0xe };
    quic_sorter_write(&sorter, 0, sizeof(data2), data2);
    printf("%ld\n", quic_sorter_readable(&sorter));
    printf("%ld\n", sorter.avail_size);

    uint8_t data3[] = { 0x10, 0x20, 0x30, 0x04 };
    quic_sorter_write(&sorter, 8, sizeof(data3), data3);
    printf("%ld\n", quic_sorter_readable(&sorter));
    printf("%ld\n", sorter.avail_size);

    uint8_t buf[20];

    uint64_t len = quic_sorter_read(&sorter, sizeof(buf), buf);
    printf("readed: %ld\n", len);

    int i;
    for (i = 0; i < 20; i++) {
        printf("%02x ", buf[i]);
    }
    printf("\n");

    return 0;
}
