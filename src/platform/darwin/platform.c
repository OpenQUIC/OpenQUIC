#include "platform/platform.h"
#include <stdlib.h>
#include <sys/malloc.h>

void *quic_malloc(size_t size) {
    return malloc(size);
}

int quic_free(void *const ptr) {
    free(ptr);

    return 0;
}
