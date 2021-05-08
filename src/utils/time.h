/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_TIME_H__
#define __OPENQUIC_TIME_H__

#include "platform/platform.h"
#include <sys/cdefs.h>
#include <sys/time.h>
#include <stdint.h>
#include <stddef.h>

__header_always_inline uint64_t quic_now() {
    struct timeval now;
    gettimeofday(&now, NULL);
    return now.tv_sec * 1000 * 1000 + now.tv_usec;
}

#endif
