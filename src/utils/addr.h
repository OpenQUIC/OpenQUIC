/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_ADDR_H__
#define __OPENQUIC_ADDR_H__

#include "liteco.h"
#include "platform/platform.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

__quic_header_inline int quic_addr_cmp(const liteco_addr_t addr1, const liteco_addr_t addr2) {
    int addr1_family = ((struct sockaddr *) &addr1)->sa_family;
    int addr2_family = ((struct sockaddr *) &addr2)->sa_family;

    if (addr1_family < addr2_family) {
        return -1;
    }
    else if (addr1_family > addr2_family) {
        return 1;
    }
    else {
        return memcmp(&addr1, &addr2, liteco_addr_type_size(&addr1));
    }
}

typedef struct quic_path_s quic_path_t;
struct quic_path_s {
    liteco_addr_t loc_addr;
    liteco_addr_t rmt_addr;
};

__quic_header_inline quic_path_t quic_path_addr(const liteco_addr_t loc_addr, const liteco_addr_t rmt_addr) {
    quic_path_t path = {
        .loc_addr = loc_addr,
        .rmt_addr = rmt_addr
    };

    return path;
}

__quic_header_inline int quic_path_cmp(const quic_path_t path1, const quic_path_t path2) {
    int cmpret = quic_addr_cmp(path1.loc_addr, path2.loc_addr);
    if (cmpret) {
        return cmpret;
    }

    return quic_addr_cmp(path1.rmt_addr, path2.rmt_addr);
}

#endif
