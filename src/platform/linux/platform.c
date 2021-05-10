/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "platform/platform.h"
#include <malloc.h>

void *quic_malloc(size_t size) {
    return malloc(size);
}

int quic_free(void *const ptr) {
    free(ptr);

    return 0;
}
