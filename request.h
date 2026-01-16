#ifndef __CPROXY_REQUEST_H
#define __CPROXY_REQUEST_H

#define CPROXY_REQ_HTTP 0x1
#define CPROXY_REQ_SOCKS5 0x2

#define CPROXY_ADDR_IPV4 (0x1 << 4)
#define CPROXY_ADDR_IPV6 (0x1 << 5)
#define CPROXY_ADDR_DOMAIN (0x1 << 6)

#define CPROXY_TCP_SOCK (0x1 << 8)
#define CPROXY_UDP_SOCK (0x1 << 9)

#define CPROXY_HTTP_TUNNEL (0x1 << 12)
#define CPROXY_SOCKS5_TUNNEL (0x1 << 13)
#define CPROXY_ACTIVE_TUNNEL (0x1 << 14)

#define CPROXY_SOCKS5_INITIAL_AUTH (0x1 << 16)
#define CPROXY_SOCKS5_TARGET_CONN (0x1 << 17)

typedef struct {
    char host[263];
    uint8_t host_len;
    union {
        uint32_t ipv4_addr;
        uint8_t ipv6_addr[16];
    };
    uint16_t port;
    uint32_t flags;
    char buffer[256];
    uint8_t buffer_len;
} cproxy_request_t;

#endif