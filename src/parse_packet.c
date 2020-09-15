/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "parse_packet.h"
#include "format/header.h"

int quic_handle_packet(quic_session_t *const sess, const quic_buf_t buf, struct timeval recv_time) {
    quic_header_t *header = buf.pos;
    if (sess->is_cli && !sess->recv_first && quic_header_is_long(header)) {
        quic_buf_t src = quic_long_header_src_conn(header);
        quic_buf_setpl(&src);

        if (quic_buf_cmp(&src, &sess->handshake_dst) != 0) {

        }
    }

    sess->recv_first = true;
    sess->last_recv_time = recv_time；

    return 0;
}
