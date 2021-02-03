
#include "log.h"
#include "lib.h"

int epfd, nfds;

void event_init()
{
    extern int epfd;
    epfd = epoll_create(1);
    if (epfd == -1) {
        error("epoll_create");
        exit(EXIT_FAILURE);
    }
}

void event_start()
{
    extern int epfd, nfds;
    struct epoll_event events[MAX_EVENTS];
    struct event_data * fd_data;
    for (;;) {
        nfds = epoll_wait(epfd, events, MAX_EVENTS, 5000);
        if (nfds > 0) {
            for (int i = 0; i < nfds; i++) {
                fd_data = events[i].data.ptr;
                fd_data->cb(fd_data);
            }
        } else if (nfds == 0) {
        } else {
            error("epoll_wait");
            exit(EXIT_FAILURE);
        }
    }
}

struct event_data * event_set(int fd, cb_t cb)
{
    extern int epfd;
    struct event_data * fd_data = malloc(sizeof(struct event_data));
    if (!fd_data) {
        error("malloc");
        exit(EXIT_FAILURE);
    }
    fd_data->fd = fd;
    fd_data->cb = cb;
    fd_data->to = NULL;
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = fd_data;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        error("epoll_ctl");
        exit(EXIT_FAILURE);
    }
    return fd_data;
}

void event_clear(struct event_data * fd_data)
{
    extern int epfd;
    if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd_data->fd, NULL) == -1) {
        error("epoll_ctl");
        exit(EXIT_FAILURE);
    }
}

void close_and_free(struct event_data * fd_data)
{
    close(fd_data->fd);
    if (fd_data->addr) free(fd_data->addr);
    free(fd_data);
}

void event_restart()
{
    extern int nfds;
    nfds = 0;
}
