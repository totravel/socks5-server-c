
#include "log.h"
#include "util.h"
#include "lib.h"
#include "proto.h"
#include "main.h"

bool verbose = false;

uint8_t method = NO_AUTHENTICATION_REQUIRED;
int nusers;
uint8_t ulens[MAX_USERS];
uint8_t plens[MAX_USERS];
char * unames[MAX_USERS];
char * passwds[MAX_USERS];

cb_t after_handshake = request_cb;

void stop_relay_cb(struct event_data * fd_data)
{
    debug("from %s", addr2str(fd_data->addr));
    debug("  to %s", addr2str(fd_data->to->addr));
    event_clear(fd_data->to);
    close_and_free(fd_data->to);
    event_clear(fd_data);
    close_and_free(fd_data);
    event_restart();
}

void stop_udp_relay_cb(struct event_data * fd_data)
{
    debug("UDP relay stopped");
    stop_relay_cb(fd_data);
}

void udp_relay_cb(struct event_data * fd_data)
{
    debug("client: %s", addr2str(fd_data->addr));
    uint8_t rx[BUF_SIZE] = {0};
    struct sockaddr_in peer_addr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    int buflen = recvfrom(fd_data->fd, rx, BUF_SIZE, 0, (struct sockaddr *)&peer_addr, &addrlen);
    if (buflen <= 0) {
        error("recvfrom");
        info("client: %s", addr2str(fd_data->addr));
        stop_udp_relay_cb(fd_data);
        return;
    }
    debug("rx: ");
    debug_mem(rx, buflen);
    debug("peer: %s", addr2str(&peer_addr));

    if (peer_addr.sin_addr.s_addr == fd_data->addr->sin_addr.s_addr
        && peer_addr.sin_port     == fd_data->addr->sin_port) {

        struct datagram * dgram = (struct datagram *)rx;
        if (dgram->frag != 0 || dgram->atyp == IPV6) {
            warn("Dropped");
            info("client: %s", addr2str(fd_data->addr));
            info("rx: ");
            info_mem(rx, buflen);
            info("peer: %s", addr2str(&peer_addr));
            return;
        }

        struct sockaddr_in dst_addr;
        memset(&dst_addr, 0, sizeof(struct sockaddr_in));
        dst_addr.sin_family      = AF_INET;
        dst_addr.sin_port        = get_dst_port(&dgram->dst, dgram->atyp);
        dst_addr.sin_addr.s_addr = get_dst_addr(&dgram->dst, dgram->atyp);
        debug("client -> %s", addr2str(&dst_addr));

        int payload_len;
        uint8_t * payload = get_payload(dgram, buflen, &payload_len);
        debug("payload: ");
        debug_mem(payload, payload_len);

        if (sendto(fd_data->fd, payload, payload_len, 0, (struct sockaddr *)&dst_addr, sizeof(struct sockaddr_in)) == -1) {
            error("sendto");
            info("client: %s", addr2str(fd_data->addr));
            info("rx: ");
            info_mem(rx, buflen);
            info("peer: %s", addr2str(&peer_addr));
            info("client -> %s", addr2str(&dst_addr));
            info("payload: ");
            info_mem(payload, payload_len);
        } else {
            debug("Payload sent successfully");
        }
    } else {
        debug("client <- %s", addr2str(&peer_addr));
        uint8_t tx[BUF_SIZE + DGRAM_IPV4_SIZE] = {0};
        struct datagram * dgram = (struct datagram *)tx;
        dgram->atyp = IPV4;
        dgram->dst.ipv4.addr = peer_addr.sin_addr.s_addr;
        dgram->dst.ipv4.port = peer_addr.sin_port;
        memcpy((uint8_t *)&dgram->dst.ipv4.port + 2, rx, buflen);
        debug("tx: ");
        debug_mem(tx, buflen + DGRAM_IPV4_SIZE);

        if (sendto(fd_data->fd, tx, buflen + DGRAM_IPV4_SIZE, 0, (struct sockaddr *)fd_data->addr, sizeof(struct sockaddr_in)) == -1) {
            error("sendto");
            info("client: %s", addr2str(fd_data->addr));
            info("rx: ");
            info_mem(rx, buflen);
            info("tx: ");
            info_mem(tx, buflen + DGRAM_IPV4_SIZE);
            info("peer: %s", addr2str(&peer_addr));
        } else {
            debug("Packet sent successfully");
        }
    }
}

void tcp_relay_cb(struct event_data * fd_data)
{
    uint8_t buf[BUF_SIZE];
    int buflen = recv(fd_data->fd, buf, BUF_SIZE, 0);
    if (buflen > 0) {
        debug("%d bytes <- %s", buflen, addr2str(fd_data->addr));
        debug_mem(buf, buflen);
        buflen = send(fd_data->to->fd, buf, buflen, 0);
        if (buflen > 0) {
            debug("%d bytes -> %s", buflen, addr2str(fd_data->to->addr));
            return;
        } else if (errno != ECONNRESET) {
            error("send");
            info("from %s", addr2str(fd_data->addr));
            info("  to %s", addr2str(fd_data->to->addr));
        }
    } else if (buflen == -1 && errno != ECONNRESET) {
        error("recv");
        info("from %s", addr2str(fd_data->addr));
        info("  to %s", addr2str(fd_data->to->addr));
    }
    debug("TCP relay stopped");
    stop_relay_cb(fd_data);
}

void request_cb(struct event_data * fd_data)
{
    debug("client: %s", addr2str(fd_data->addr));
    bool reject;
    uint8_t rx[MAX_SOCKS_REQUEST_LEN] = {0}, tx[MAX_SOCKS_REPLY_LEN] = {0};
    struct socks_request * req = (struct socks_request *)rx;
    struct socks_reply * rep = (struct socks_reply *)tx;
    rep->ver = VERSION;

    reject = true;
    int buflen = recv(fd_data->fd, rx, MAX_SOCKS_REQUEST_LEN, 0);
    if (buflen > 0) {
        debug("rx: ");
        debug_mem(rx, buflen);
        if (buflen < MIN_SOCKS_REQUEST_LEN) {
            debug("Invalid SOCKS request");
        } else {
            reject = false;
        }
    } else if (buflen == -1 && errno != ECONNRESET) {
        error("recv");
        info("client: %s", addr2str(fd_data->addr));
    }

    if (reject) {
        event_clear(fd_data);
        close_and_free(fd_data);
        debug("Connection closed");
        return;
    }

    reject = true;
    rep->rep = SUCCEEDED;
    if (req->atyp == IPV6) {
        rep->rep = ADDRESS_TYPE_NOT_SUPPORTED;
        debug("Address type not supported");
    } else {
        if (req->cmd == CONNECT) {
            in_addr_t addr = get_dst_addr(&req->dst, req->atyp);
            in_port_t port = get_dst_port(&req->dst, req->atyp);
            int dst_fd = create_and_connect(addr, port);
            if (dst_fd) {
                fd_data->cb = tcp_relay_cb;
                fd_data->to = event_set(dst_fd, tcp_relay_cb);
                fd_data->to->to = fd_data;

                fd_data->to->addr = malloc(sizeof(struct sockaddr_in));
                if (!fd_data->to->addr) {
                    error("malloc");
                    exit(EXIT_FAILURE);
                }
                fd_data->to->addr->sin_port        = port;
                fd_data->to->addr->sin_addr.s_addr = addr;

                rep->atyp = IPV4;
                get_local_addr(dst_fd, &rep->bnd.ipv4.addr, &rep->bnd.ipv4.port);
                debug("rep.bnd: %s:%hu", inet_ntoaddr(&rep->bnd.ipv4.addr), ntohs(rep->bnd.ipv4.port));
                reject = false;
            } else {
                rep->rep = GENERAL_SOCKS_SERVER_FAILURE;
                info("client: %s", addr2str(fd_data->addr));
                info("rx: ");
                info_mem(rx, buflen);
                info("tx: ");
                info_mem(tx, SOCKS_REPLY_SIZE_IPV4);
            }
        } else if (req->cmd == UDP) {
            int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (fd == -1) {
                rep->rep = GENERAL_SOCKS_SERVER_FAILURE;
                error("socket");
            } else {
                struct sockaddr_in bnd_addr;
                memset(&bnd_addr, 0, sizeof(struct sockaddr_in));
                bnd_addr.sin_family = AF_INET;
                if (bind(fd, (struct sockaddr *)&bnd_addr, sizeof(struct sockaddr_in)) == -1) {
                    rep->rep = GENERAL_SOCKS_SERVER_FAILURE;
                    error("bind");
                    close(fd);
                } else {
                    fd_data->to = event_set(fd, udp_relay_cb);
                    fd_data->to->to = fd_data;

                    struct sockaddr_in * home;
                    home = malloc(sizeof(struct sockaddr_in));
                    fd_data->to->addr = home;
                    if (!home) {
                        error("malloc");
                        exit(EXIT_FAILURE);
                    }
                    memset(home, 0, sizeof(struct sockaddr_in));
                    home->sin_family      = AF_INET;
                    home->sin_port        = get_dst_port(&req->dst, req->atyp);
                    home->sin_addr.s_addr = get_dst_addr(&req->dst, req->atyp);
                    if (!home->sin_addr.s_addr)
                        home->sin_addr.s_addr = fd_data->addr->sin_addr.s_addr;
                    debug("client: %s(UDP)", addr2str(home));
                    if (!home->sin_port) {
                        rep->rep = ADDRESS_TYPE_NOT_SUPPORTED;
                        warn("Invalid port");
                        info("client: %s", addr2str(fd_data->addr));
                        info("rx: ");
                        info_mem(rx, buflen);
                        info("tx: ");
                        info_mem(tx, SOCKS_REPLY_SIZE_IPV4);
                        info("client: %s(udp)", addr2str(home));
                        event_clear(fd_data->to);
                        close_and_free(fd_data->to);
                    } else {
                        rep->atyp = IPV4;
                        get_local_addr(fd_data->fd, &rep->bnd.ipv4.addr, NULL);
                        get_local_addr(fd, NULL, &rep->bnd.ipv4.port);
                        fd_data->cb = stop_udp_relay_cb;
                        debug("rep.bnd: %s:%hu", inet_ntoaddr(&rep->bnd.ipv4.addr), ntohs(rep->bnd.ipv4.port));
                        reject = false;
                    }
                }
            }
        } else {
            rep->rep = COMMAND_NOT_SUPPORTED;
            debug("Command not supported");
        }
    }
    debug("tx: ");
    debug_mem(tx, SOCKS_REPLY_SIZE_IPV4);

    if (send(fd_data->fd, tx, SOCKS_REPLY_SIZE_IPV4, 0) > 0) {
        debug("SOCKS Reply sent successfully");
    } else {
        reject = true;
        error("send");
        info("client: %s", addr2str(fd_data->addr));
        info("rx: ");
        info_mem(rx, buflen);
        info("tx: ");
        info_mem(tx, SOCKS_REPLY_SIZE_IPV4);
    }

    if (reject) {
        if (fd_data->to) {
            event_clear(fd_data->to);
            close_and_free(fd_data->to);
            debug("Disconnect from destination");
        }
        event_clear(fd_data);
        close_and_free(fd_data);
        debug("Connection closed");
    }
}

void auth_cb(struct event_data * fd_data)
{
    debug("client: %s", addr2str(fd_data->addr));
    extern int nusers;
    bool reject;
    uint8_t rx[MAX_AUTH_REQUEST_LEN] = {0}, tx[AUTH_STATUS_SIZE] = {0};
    struct auth_request * req = (struct auth_request *)rx;
    struct auth_status * res = (struct auth_status *)tx;
    res->ver = AUTH_VERSION;

    reject = true;
    int buflen = recv(fd_data->fd, rx, MAX_AUTH_REQUEST_LEN, 0);
    if (buflen > 0) {
        debug("rx: ");
        debug_mem(rx, buflen);
        if (buflen < MIN_AUTH_REQUEST_LEN) {
            debug("Invalid auth request");
        } else {
            reject = false;
        }
    } else if (buflen == -1 && errno != ECONNRESET) {
        error("recv");
        info("client: %s", addr2str(fd_data->addr));
    }

    if (reject) {
        event_clear(fd_data);
        close_and_free(fd_data);
        debug("Connection closed");
        return;
    }

    reject = true;
    res->status = AUTH_FAILURE;
    uint8_t ulen, plen;
    uint8_t * uname, * passwd;
    get_uname_passwd(req, &ulen, &uname, &plen, &passwd);
    if (verbose) {
        char s1[ulen + 1]; strncpy(s1, uname, ulen);
        char s2[plen + 1]; strncpy(s2, passwd, plen);
        s1[ulen] = '\0';
        s2[plen] = '\0';
        info("username: %d: %s", ulen, s1);
        info("password: %d: %s", plen, s2);
    }
    for (int i = 0; i < nusers; i++) {
        if (ulen == ulens[i]
            && plen == plens[i]
            && !strncmp(unames[i], uname, ulen)
            && !strncmp(passwds[i], passwd, plen)
        ) {
            res->status = AUTH_SUCCESS;
            fd_data->cb = request_cb;
            reject = false;
            break;
        }
    }
    debug("%s", reject ? "Incorrect username or password" : "Authentication successfully");
    debug("tx: ");
    debug_mem(tx, AUTH_STATUS_SIZE);

    if (send(fd_data->fd, tx, AUTH_STATUS_SIZE, 0) > 0) {
        debug("Status sent successfully.");
    } else {
        reject = true;
        error("send");
        info("client: %s", addr2str(fd_data->addr));
        info("rx: ");
        info_mem(rx, buflen);

        char s1[ulen + 1]; strncpy(s1, uname, ulen);
        char s2[plen + 1]; strncpy(s2, passwd, plen);
        s1[ulen] = '\0';
        s2[plen] = '\0';
        info("uname: %d: %s", ulen, s1);
        info("passwd: %d: %s", plen, s2);

        info("tx: ");
        info_mem(tx, AUTH_STATUS_SIZE);
    }

    if (reject) {
        event_clear(fd_data);
        close_and_free(fd_data);
        debug("Connection closed");
    }
}

void handshake_cb(struct event_data * fd_data)
{
    debug("client: %s", addr2str(fd_data->addr));
    extern uint8_t method;
    bool reject;
    uint8_t rx[MAX_METHOD_REQUEST_LEN] = {0}, tx[METHOD_REPLY_SIZE] = {0};
    struct method_request * req = (struct method_request *)rx;
    struct method_reply * rep = (struct method_reply *)tx;
    rep->ver = VERSION;

    reject = true;
    int buflen = recv(fd_data->fd, rx, MAX_METHOD_REQUEST_LEN, 0);
    if (buflen > 0) {
        debug("rx: ");
        debug_mem(rx, buflen);
        if (buflen < MIN_METHOD_REQUEST_LEN) {
            debug("Invalid version identifier/method selection message");
        } else {
            reject = false;
        }
    } else if (buflen == -1 && errno != ECONNRESET) {
        error("recv");
        info("client: %s", addr2str(fd_data->addr));
    }

    if (reject) {
        event_clear(fd_data);
        close_and_free(fd_data);
        debug("Connection closed");
        return;
    }

    reject = true;
    rep->method = NO_ACCEPTABLE_METHODS;
    if ((int)req->ver == VERSION) {
        if (method_exists(req, method)) {
            rep->method = method;
            fd_data->cb = after_handshake;
            reject = false;
        } else {
            debug("No acceptable methods");
        }
    } else {
        debug("Protocol version not supported");
    }
    debug("tx: ");
    debug_mem(tx, METHOD_REPLY_SIZE);

    if (send(fd_data->fd, tx, METHOD_REPLY_SIZE, 0) > 0) {
        debug("METHOD selection message sent successfully");
    } else {
        reject = true;
        error("send");
        info("client: %s", addr2str(fd_data->addr));
        info("rx: ");
        info_mem(rx, buflen);
        info("tx: ");
        info_mem(tx, METHOD_REPLY_SIZE);
    }

    if (reject) {
        event_clear(fd_data);
        close_and_free(fd_data);
        debug("Connection closed");
    }
}

void accept_cb(struct event_data * fd_data)
{
    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct sockaddr_in * client_addr = malloc(sizeof(struct sockaddr_in));
    if (!client_addr) {
        error("malloc");
        exit(EXIT_FAILURE);
    }
    int fd = accept(fd_data->fd, (struct sockaddr *)client_addr, &addrlen);
    if (fd == -1) {
        error("accept");
    } else {
        fd_data = event_set(fd, handshake_cb);
        fd_data->addr = client_addr;
        debug("Connection from %s", addr2str(fd_data->addr));
    }
}

bool load_users(const char * path)
{
    extern int nusers;
    extern uint8_t ulens[MAX_USERS];
    extern uint8_t plens[MAX_USERS];
    extern char * unames[MAX_USERS];
    extern char * passwds[MAX_USERS];
    FILE * fp = fopen(path, "r");
    if (fp == 0) {
        error("fopen");
        info("path: %s", path);
        return false;
    }
    int i = 0, ulen, plen;
    char row[MAX_ULEN + MAX_PLEN + 4]; // e.g. user1,123456\r\n\0
    char * p, * end;
    do {
        memset(row, 0, sizeof(row));
        if (fgets(row, MAX_ULEN + MAX_PLEN + 4, fp)) {
            p = strchr(row, ',');
            end = strchr(p, '\0');
            if (*(end - 1) == '\n') {
                end--;
                if (*(end - 1) == '\r')
                    end--;
            }
            ulen = ulens[i] = p - row;
            plen = plens[i] = end - p - 1;
            unames[i] = malloc(ulen);
            if (!unames[i]) {
                error("malloc");
                exit(EXIT_FAILURE);
            }
            passwds[i] = malloc(plen);
            if (!passwds[i]) {
                error("malloc");
                exit(EXIT_FAILURE);
            }
            strncpy(unames[i], row, ulen);
            strncpy(passwds[i], p + 1, plen);
            i++;
            if (verbose) {
                char s1[ulen + 1]; strncpy(s1, row, ulen);
                char s2[plen + 1]; strncpy(s2, p + 1, plen);
                s1[ulen] = '\0';
                s2[plen] = '\0';
                info("username: %d: %s", ulen, s1);
                info("password: %d: %s", plen, s2);
            }
        } else {
            break;
        }
    } while (!feof(fp));
    fclose(fp);
    nusers = i;
    debug("%d users", nusers);
    return true;
}

void usage(const char * name)
{
    printf(
        "usage: %s [options]\n"
        "options: \n"
        "  -a <address>         Local Address to bind (default: 0.0.0.0).\n"
        "  -p <port>            Port number to bind (default: 1080).\n"
        "  -u <path/to/passwd>  The path to passwd.\n"
        "  -d                   Run as a daemon.\n"
        "  -h                   Show this help message.\n", name);
}

int main(int argc, char * argv[])
{
    extern uint8_t method;
    extern int nusers;
    extern bool verbose;

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        error("signal");
        exit(EXIT_FAILURE);
    }

    bool daemon = false;
    in_addr_t addr = htonl(DEFAULT_ADDR);
    in_port_t port = htons(DEFAULT_PORT);

    int opt;
    opterr = 0;
    for (;;) {
        opt = getopt(argc, argv, ":a:p:u:dhv");
        if (opt == -1) break;
        switch (opt) {
            case 'a':
                addr = inet_addr(optarg);
                break;
            case 'p':
                port = htons(atoi(optarg));
                break;
            case 'u':
                if (!load_users(optarg)) exit(EXIT_FAILURE);
                method = USERNAME_PASSWORD;
                after_handshake = auth_cb;
                break;
            case 'd':
                daemon = true;
                break;
            case 'h':
                usage(argv[0]);
                exit(EXIT_SUCCESS);
            case 'v':
                verbose = true;
                break;
            case ':':
                printf("Missing argument after: -%c\n", optopt);
                usage(argv[0]);
                exit(EXIT_FAILURE);
            case '?':
                printf("Invalid argument: -%c\n", optopt);
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (method == USERNAME_PASSWORD) {
        puts("USERNAME/PASSWORD");
        printf("%d users\n", nusers);
    } else {
        puts("NO AUTHENTICATION REQUIRED");
    }

    int fd = create_and_listen(addr, port);
    if (!fd) exit(EXIT_FAILURE);
    printf("Listening on %s:%hu\n", inet_ntoaddr(&addr), ntohs(port));

    if (daemon) {
        pid_t pid = fork();
        if (pid == -1) {
            perror("fork");
            exit(EXIT_FAILURE);
        }
        if (pid > 0) {
            printf("PID is %d\n", pid);
            exit(EXIT_SUCCESS);
        }
    }

    event_init();
    event_set(fd, accept_cb);
    event_start();
}
