/*
 * Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_ERRNO_H__
#define __OPENQUIC_ERRNO_H__

typedef int quic_err_t;

#define quic_err_success         0
#define quic_err_not_implemented -501
#define quic_err_bad_format      -400
#define quic_err_internal_error  500

#endif
