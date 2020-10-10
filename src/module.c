/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "module.h"
#include <stdbool.h>

uint32_t quic_modules_size() {
    static bool inited = false;
    static uint32_t result = 0;
    int i;

    if (!inited) {
        for (i = 0; quic_modules[i]; i++) {
            quic_modules[i]->off = result;
            result += quic_modules[i]->module_size;
        }
    }

    inited = true;
    return result;
}
