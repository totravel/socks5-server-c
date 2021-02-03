
#ifndef __PROTO_H__
#define __PROTO_H__

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h> // close()
#include <arpa/inet.h>

// VERSION
#define VERSION      0x05
#define AUTH_VERSION 0x01

// Method
#define NO_AUTHENTICATION_REQUIRED 0x00
#define GSSAPI                     0x01
#define USERNAME_PASSWORD          0x02
#define NO_ACCEPTABLE_METHODS      0xff

// Status
#define AUTH_SUCCESS 0x00
#define AUTH_FAILURE 0x01

// Command
#define CONNECT 0x01
#define BIND    0x02
#define UDP     0x03

// Address type
#define IPV4    0x01
#define DOMAIN  0x03
#define IPV6    0x04

// Reply
#define SUCCEEDED                         0x00
#define GENERAL_SOCKS_SERVER_FAILURE      0x01
#define CONNECTION_NOT_ALLOWED_BY_RULESET 0x02
#define NETWORK_UNREACHABLE               0x03
#define HOST_UNREACHABLE                  0x04
#define CONNECTION_REFUSED                0x05
#define TTL_EXPIRED                       0x06
#define COMMAND_NOT_SUPPORTED             0x07
#define ADDRESS_TYPE_NOT_SUPPORTED        0x08

// Length limit
#define MAX_ULEN               255
#define MAX_PLEN               255
#define MAX_METHOD_REQUEST_LEN 257
#define MIN_METHOD_REQUEST_LEN 3
#define MAX_AUTH_REQUEST_LEN   513
#define MIN_AUTH_REQUEST_LEN   5
#define MAX_SOCKS_REQUEST_LEN  69
#define MIN_SOCKS_REQUEST_LEN  10
#define MAX_SOCKS_REPLY_LEN MAX_SOCKS_REQUEST_LEN

// Size
#define METHOD_REPLY_SIZE 2
#define AUTH_STATUS_SIZE  2
#define DGRAM_IPV4_SIZE   10
#define SOCKS_REPLY_SIZE_IPV4 MIN_SOCKS_REQUEST_LEN

// version identifier/method selection message
struct method_request {
    uint8_t ver;
    uint8_t nmethods;
    uint8_t methods[];
};

// method selection message
struct method_reply {
    uint8_t ver;
    uint8_t method;
};

struct auth_request {
    uint8_t ver;
    uint8_t ulen;
    uint8_t uname[];
};

struct auth_status {
    uint8_t ver;
    uint8_t status;
};

union dst_or_bnd {
    struct {
        in_addr_t addr;
        in_port_t port;
    } ipv4;
    struct {
        uint8_t len;
        uint8_t str[];
    } domain;
    struct {
        uint8_t addr[16];
        in_port_t port;
    } ipv6;
};

struct socks_request {
    uint8_t ver;
    uint8_t cmd;
    uint8_t rsv;
    uint8_t atyp;
    union dst_or_bnd dst;
};

struct socks_reply {
    uint8_t ver;
    uint8_t rep;
    uint8_t rsv;
    uint8_t atyp;
    union dst_or_bnd bnd;
};

struct datagram {
    uint16_t rsv;
    uint8_t frag;
    uint8_t atyp;
    union dst_or_bnd dst;
};

bool method_exists(struct method_request * method_req, uint8_t method);
void get_uname_passwd(struct auth_request * req, uint8_t * ulen, uint8_t ** uname, uint8_t * plen, uint8_t ** passwd);
in_addr_t get_dst_addr(union dst_or_bnd * dst, uint8_t atyp);
in_port_t get_dst_port(union dst_or_bnd * dst, uint8_t atyp);
uint8_t * get_payload(struct datagram * dgram, int buflen, int * len);

#endif /* __PROTO_H__ */
