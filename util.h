
#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdio.h>
#include <stdlib.h> // exit()
#include <stdint.h> // uint8_t
#include <stdbool.h> // bool, true, false
#include <string.h> // memset(), memcpy(), strcpy(), strerror()
#include <ctype.h> // isalpha(), isdigit(), isprint()
#include <unistd.h> // close()
#include <sys/socket.h> // socket(), bind(), listen(), accept(), recv(), send()
#include <arpa/inet.h> // htons(), htonl(), inet_addr()
#include <netdb.h> // gethostbyname()
#include <sys/select.h>

void memdump(uint8_t * in, int len);
char * addr2str(struct sockaddr_in * addr);
int create_and_listen(in_addr_t addr, in_port_t port);
int create_and_connect(in_addr_t addr, in_port_t port);
in_addr_t resolve_domain(char * domain);
void get_local_addr(int fd, in_addr_t * addr, in_port_t * port);
void get_peer_addr(int fd, in_addr_t * addr, in_port_t * port);
char * inet_ntoaddr(void * addr);

#endif /* __UTIL_H__ */
