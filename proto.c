
#include "log.h"
#include "util.h"
#include "proto.h"

bool method_exists(struct method_request * method_req, uint8_t method)
{
    for (int i = 0; i < method_req->nmethods; i++)
        if (method_req->methods[i] == method) return true;
    return false;
}

void get_uname_passwd(struct auth_request * req, uint8_t * ulen, uint8_t ** uname, uint8_t * plen, uint8_t ** passwd)
{
    *ulen = req->ulen;
    *uname = req->uname;
    *plen = *(req->uname + req->ulen);
    *passwd = req->uname + req->ulen + 1;
}

in_addr_t get_dst_addr(union dst_or_bnd * dst, uint8_t atyp)
{
    if (atyp == IPV4) return dst->ipv4.addr;
    char domain[64];
    size_t len = dst->domain.len;
    domain[len] = '\0';
    strncpy(domain, dst->domain.str, len);
    return resolve_domain(domain);
}

in_port_t get_dst_port(union dst_or_bnd * dst, uint8_t atyp)
{
    if (atyp == IPV4) return dst->ipv4.port;
    return *(in_port_t *)(dst->domain.str + dst->domain.len);
}

uint8_t * get_payload(struct datagram * dgram, int buflen, int * len)
{
    uint8_t * payload = dgram->atyp == IPV4 ? (uint8_t *)&dgram->dst.ipv4.port + 2 : dgram->dst.domain.str + dgram->dst.domain.len + 2;
    *len = buflen - (payload - (uint8_t *)dgram);
    return payload;
}
