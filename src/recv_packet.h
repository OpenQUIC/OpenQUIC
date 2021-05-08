/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_RECV_PACKET_H__
#define __OPENQUIC_RECV_PACKET_H__

#include "liteco.h"
#include "platform/platform.h"
#include "utils/errno.h"
#include <netinet/in.h>

typedef struct quic_recv_packet_s quic_recv_packet_t;
struct quic_recv_packet_s {
    LITECO_LINKNODE_BASE

    union {
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
    } local_addr;

    union {
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
    } remote_addr;

    uint64_t recv_time;

    liteco_udp_chan_ele_t pkt;
};

__quic_header_inline quic_err_t quic_recv_packet_recovery(quic_recv_packet_t *const recvpkt) {
    quic_free(recvpkt);

    return quic_err_success;
}

#endif
