/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_ADDR_H__
#define __OPENQUIC_ADDR_H__

#include "lc_udp.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

typedef union quic_addr_u quic_addr_t;
union quic_addr_u {
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
};

static inline quic_addr_t quic_ipv4(const char *const addr, const uint16_t port) {
    quic_addr_t ret = {};
    ret.v4.sin_family = AF_INET;
    ret.v4.sin_addr.s_addr = inet_addr(addr);
    ret.v4.sin_port = htons(port);
    memset(ret.v4.sin_zero, 0, sizeof(ret.v4.sin_zero));

    return ret;
}

static inline quic_addr_t quic_litecoaddr(const liteco_sockaddr_t addr) {
    quic_addr_t ret = {};
    switch (((struct sockaddr *) &addr)->sa_family) {
    case AF_INET:
        ret.v4 = addr.in;
        memset(ret.v4.sin_zero, 0, sizeof(ret.v4.sin_zero));
        break;

    case AF_INET6:
        ret.v6 = addr.in6;
        break;
    }

    return ret;
}

static inline size_t quic_addr_size(quic_addr_t addr) {
    switch (((struct sockaddr *) &addr)->sa_family) {
    case AF_INET:
        return sizeof(struct sockaddr_in);
    case AF_INET6:
        return sizeof(struct sockaddr_in6);
    default:
        return 0;
    }
}

static inline int quic_addr_cmp(const quic_addr_t addr1, const quic_addr_t addr2) {
    int addr1_family = ((struct sockaddr *) &addr1)->sa_family;
    int addr2_family = ((struct sockaddr *) &addr2)->sa_family;

    if (addr1_family < addr2_family) {
        return -1;
    }
    else if (addr1_family > addr2_family) {
        return 1;
    }
    else {
        return memcmp(&addr1, &addr2, quic_addr_size(addr1));
    }
}

typedef struct quic_path_s quic_path_t;
struct quic_path_s {
    quic_addr_t local_addr;
    quic_addr_t remote_addr;
};

static inline quic_path_t quic_path_ipv4(const char *const local_addr, const uint16_t local_port, const char *const remote_addr, const uint16_t remote_port) {
    quic_path_t path = {
        .local_addr = quic_ipv4(local_addr, local_port),
        .remote_addr = quic_ipv4(remote_addr, remote_port)
    };
    return path;
}

static inline quic_path_t quic_path_addr(const quic_addr_t local_addr, const quic_addr_t remote_addr) {
    quic_path_t path = {
        .local_addr = local_addr,
        .remote_addr = remote_addr
    };

    return path;
}

static inline int quic_path_cmp(const quic_path_t path1, const quic_path_t path2) {
    int cmpret = quic_addr_cmp(path1.local_addr, path2.local_addr);
    if (cmpret) {
        return cmpret;
    }

    return quic_addr_cmp(path1.remote_addr, path2.remote_addr);
}

#endif
