
#include <stdbool.h> // bool, true, false
#include <stdint.h> // uint8_t
#include <string.h> // memset()
#include <sys/socket.h> // recv(), send()
#include <arpa/inet.h> // inet_ntoa()
#include <signal.h>

#define DEFAULT_ADDR INADDR_ANY
#define DEFAULT_PORT 1080

#define BUF_SIZE 10240
#define MAX_USERS 10

void stop_relay_cb(struct event_data * fd_data);
void udp_relay_cb(struct event_data * fd_data);
void tcp_relay_cb(struct event_data * fd_data);
void request_cb(struct event_data * fd_data);
void auth_cb(struct event_data * fd_data);
void handshake_cb(struct event_data * fd_data);
void accept_cb(struct event_data * fd_data);
bool load_users(const char * path);
void usage(const char * name);
