/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_PARSE_PACKET_H__
#define __OPENQUIC_PARSE_PACKET_H__

#include "session.h"
#include "utils/buf.h"
#include <sys/time.h>

int quic_handle_packet(quic_session_t *const sess, const quic_buf_t buf, struct timeval recv_time);

#endif
