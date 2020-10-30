/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_UDP_FD_H__
#define __OPENQUIC_UDP_FD_H__

#include "module.h"
#include "recv_packet.h"
#include "session.h"
#include "modules/udp_recver.h"
#include "utils/time.h"
#include <netinet/in.h>
#include <errno.h>

typedef struct quic_udp_fd_module_s quic_udp_fd_module_t;
struct quic_udp_fd_module_s {
    int fd;

    uint32_t mtu;

    union {
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
    } remote_addr;

    union {
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
    } local_addr;
};

extern quic_module_t quic_udp_fd_module;

static inline quic_err_t quic_udp_fd_write(quic_udp_fd_module_t *const module, const void *const data, const uint32_t len) {
    sendto(module->fd, data, len, 0, (struct sockaddr *) &module->remote_addr, sizeof(struct sockaddr_in));

    return quic_err_success;
}

static inline quic_err_t quic_udp_fd_read(quic_udp_fd_module_t *const module) {
    quic_session_t *const session = quic_module_of_session(module, quic_udp_fd_module);
    quic_udp_recver_module_t *ur_module = quic_session_module(quic_udp_recver_module_t, session, quic_udp_recver_module);

    quic_recv_packet_t *rp = malloc(sizeof(quic_recv_packet_t) + module->mtu);
    if (rp == NULL) {
        return quic_err_internal_error;
    }
    socklen_t socklen = 0;

    int ret = recvfrom(module->fd, rp->data, module->mtu, 0, (struct sockaddr *) &rp->remote_addr.v4, &socklen);

    rp->len = ret;
    rp->recv_time = quic_now();

    quic_udp_recver_push(ur_module, rp);

    return quic_err_success;
}

#define quic_session_recv_packet(session) \
    quic_udp_fd_read(quic_session_module(quic_udp_fd_module_t, (session), quic_udp_fd_module))

#endif
