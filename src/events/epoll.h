/*
 * Copyright (c) 2020-2021 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 */

#ifndef __OPENQUIC_EVENT_EPOLL_H__
#define __OPENQUIC_EVENT_EPOLL_H__

#include "utils/errno.h"
#include <stddef.h>
#include <sys/epoll.h>
#include <sys/fcntl.h>

#define QUIC_EVENT_EPOLL_MAX_ACTIVES_COUNT 16

#define QUIC_INVALID_EPOLL_FD -1

typedef struct quic_event_epoll_s quic_event_epoll_t;
struct quic_event_epoll_s {
    struct epoll_event events[QUIC_EVENT_EPOLL_MAX_ACTIVES_COUNT];
    int fd;

    int (*epoll_cb) (void *args);
};

static inline quic_err_t quic_event_epoll_init(quic_event_epoll_t *const event, int (*epoll_cb) (void *args)) {
    event->fd = epoll_create(QUIC_EVENT_EPOLL_MAX_ACTIVES_COUNT);
    if (event->fd == QUIC_INVALID_EPOLL_FD) {
        return quic_err_internal_error;
    }
    event->epoll_cb = epoll_cb;

    return quic_err_success;
}

static inline quic_err_t quic_event_epoll_register_fd(quic_event_epoll_t *const event, int fd, void *const args) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    struct epoll_event e;

    e.events = EPOLLIN | EPOLLET;
    e.data.ptr = args;

    if (epoll_ctl(event->fd, EPOLL_CTL_ADD, fd, &e) == -1) {
        return quic_err_internal_error;
    }
    return quic_err_success;
}

static inline quic_err_t quic_event_epoll_unregister_fd(quic_event_epoll_t *const event, int fd) {
    struct epoll_event e;

    e.events = 0;
    e.data.ptr = NULL;
    
    epoll_ctl(event->fd, EPOLL_CTL_DEL, fd, &e);
    return quic_err_success;
}

quic_err_t quic_event_epoll_process(quic_event_epoll_t *const event, int timeout);

#endif
