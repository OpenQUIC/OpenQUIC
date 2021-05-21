/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_CONTAINER_OF_H__
#define __OPENQUIC_CONTAINER_OF_H__

#define container_of(ptr, type, member) ((type *) ((char *) (ptr) - offsetof(type, member)))

#endif
