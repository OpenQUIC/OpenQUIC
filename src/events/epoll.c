/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#include "events/epoll.h"

quic_err_t quic_event_epoll_process(quic_event_epoll_t *const event, int timeout) {
    int i;
    int ready = epoll_wait(event->fd, event->events, QUIC_EVENT_EPOLL_MAX_ACTIVES_COUNT, timeout);
    if (ready == -1) {
        return quic_err_internal_error;
    }
    for (i = 0; i < ready; i++) {
        event->epoll_cb(event->events[i].data.ptr);
    }

    return quic_err_success;
}
