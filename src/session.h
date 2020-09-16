/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_SESSION_H__
#define __OPENQUIC_SESSION_H__

#include "utils/buf.h"
#include <stdbool.h>
#include <sys/time.h>

typedef struct quic_session_s quic_session_t;
struct quic_session_s {
    bool is_cli;
    bool recv_first;
    struct timeval last_recv_time;
    quic_buf_t handshake_dst;
    size_t conn_len;
};

#endif
