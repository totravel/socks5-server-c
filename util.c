
#include "log.h"
#include "util.h"

// 61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  aaaaaaaaaaaaaaaa
// 61 61 61 61  61 61 61 61  61 61 61                  aaaaaaa....
void memdump(uint8_t * in, int len)
{
    int i = 0, j = 0;
    if (len > 128)
        len = 128;
    while (i < len) {
        printf("%02x ", in[i]);
        if (++i % 16 == 0) {
            putchar(' ');
            do {
                putchar(isprint(in[j]) ? in[j] : '.');
            } while (++j < i);
            putchar('\n');
        } else if (i % 4 == 0) {
            putchar(' ');
        }
    }
    int k = i % 16;
    if (k) {
        do {
            printf("   ");
            if (++k % 4 == 0) putchar(' ');
        } while (k < 16);
        do {
            putchar(isprint(in[j]) ? in[j] : '.');
        } while (++j < i);
        putchar('\n');
    }
}

// struct sockaddr_in --> "aaa.aaa.aaa.aaa:ppppp"
char * addr2str(struct sockaddr_in * addr)
{
    static char s[22];
    sprintf(s, "%s:%hu", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
    return s;
}

// in_addr_t --> "aaa.aaa.aaa.aaa"
char * inet_ntoaddr(void * addr)
{
    return inet_ntoa(*(struct in_addr *)addr);
}

int create_and_listen(in_addr_t addr, in_port_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == -1) {
        error("socket");
        return 0;
    }
    struct sockaddr_in bnd_addr;
    memset(&bnd_addr, 0, sizeof(struct sockaddr_in));
    bnd_addr.sin_family      = AF_INET;
    bnd_addr.sin_port        = port;
    bnd_addr.sin_addr.s_addr = addr;
    debug("bnd: %s", addr2str(&bnd_addr));
    if (bind(fd, (struct sockaddr *)&bnd_addr, sizeof(struct sockaddr_in)) == -1) {
        error("bind");
        info("bnd: %s", addr2str(&bnd_addr));
        close(fd);
        return 0;
    }
    if (listen(fd, SOMAXCONN) == -1) {
        error("listen");
        info("bnd: %s", addr2str(&bnd_addr));
        close(fd);
        return 0;
    }
    return fd;
}

int create_and_connect(in_addr_t addr, in_port_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == -1) {
        error("socket");
        return 0;
    }
    struct sockaddr_in dst_addr;
    memset(&dst_addr, 0, sizeof(struct sockaddr_in));
    dst_addr.sin_family      = AF_INET;
    dst_addr.sin_port        = port;
    dst_addr.sin_addr.s_addr = addr;
    debug("Connecting to %s...", addr2str(&dst_addr));
    if (connect(fd, (struct sockaddr *)&dst_addr, sizeof(struct sockaddr_in)) == -1) {
        error("connect");
        info("dst: %s", addr2str(&dst_addr));
        close(fd);
        return 0;
    }
    debug("Connection established");
    return fd;
}

in_addr_t resolve_domain(char * domain)
{
    debug("Question: %s", domain);
    struct hostent * host = gethostbyname(domain);
    if (host == NULL) {
        error("gethostbyname");
        info("Couldn't resolve host '%s'", domain);
        return 0;
    }
    debug("Answer: %s", inet_ntoaddr(host->h_addr_list[0]));
    return *(in_addr_t *)host->h_addr_list[0];
}

void get_local_addr(int fd, in_addr_t * addr, in_port_t * port)
{
    struct sockaddr_in local_addr;
    socklen_t local_addrlen = sizeof(struct sockaddr_in);
    getsockname(fd, (struct sockaddr *)&local_addr, &local_addrlen);
    debug("Local Address: %s", addr2str(&local_addr));
    if (addr) *addr = local_addr.sin_addr.s_addr;
    if (port) *port = local_addr.sin_port;
}

void get_peer_addr(int fd, in_addr_t * addr, in_port_t * port)
{
    struct sockaddr_in peer_addr;
    socklen_t peer_addrlen = sizeof(struct sockaddr_in);
    getpeername(fd, (struct sockaddr *)&peer_addr, &peer_addrlen);
    debug("Peer Address: %s", addr2str(&peer_addr));
    if (addr) *addr = peer_addr.sin_addr.s_addr;
    if (port) *port = peer_addr.sin_port;
}
