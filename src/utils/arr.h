/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_ARR_H__
#define __OPENQUIC_ARR_H__

#include <stdint.h>
#include <stddef.h>

typedef struct quic_arr_s quic_arr_t;
struct quic_arr_s {
    uint32_t count;
    size_t size;

    uint8_t data[0];
};

#define quic_arr(arr, nth, type) ((type *) (((void *) (arr)->data) + (arr)->size * (nth)))

#endif
