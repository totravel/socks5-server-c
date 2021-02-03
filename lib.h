
#ifndef __LIB_H__
#define __LIB_H__

#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <netinet/in.h>

#define MAX_EVENTS 64

struct event_data {
    int fd;
    void (* cb)(struct event_data * fd_data);
    struct event_data * to;
    struct sockaddr_in * addr;
};

typedef void (* cb_t)(struct event_data * fd_data);

void event_init();
void event_start();
struct event_data * event_set(int fd, cb_t cb);
void event_clear(struct event_data * fd_data);
void close_and_free(struct event_data * fd_data);
void event_restart();

#endif /* __LIB_H__ */
