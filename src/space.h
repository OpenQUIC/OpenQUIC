/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_SPACE_H__
#define __OPENQUIC_SPACE_H__

typedef enum quic_space_e quic_space_t;
enum quic_space_e {
    quic_space_initial   = 0,
    quic_space_handshake = 1,
    quic_space_app       = 2,

    quic_space_count     = 3
};

#endif
