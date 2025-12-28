#ifndef __CPROXY_REQUEST_H
#define __CPROXY_REQUEST_H

#define CPROXY_HTTP_CONNECT 0x2

#define CPROXY_SOCKS5_INITIAL_AUTH 0x1
#define CPROXY_SOCKS5_TARGET_CONN 0x2
#define CPROXY_SOCKS5_TUNNEL 0x4

#define CPROXY_TCP_SOCK (0x1 << 8)
#define CPROXY_UDP_SOCK (0x1 << 9)

#define CPROXY_SOCK5_ADDR_IPV4 (0x1 << 12)
#define CPROXY_SOCK5_ADDR_IPV6 (0x1 << 13)
#define CPROXY_SOCK5_ADDR_DOMAIN (0x1 << 14)

typedef enum cproxy_request_protocol {
    CPROXY_REQ_HTTP = 1,
    CPROXY_REQ_SOCKS5 = 2
} cproxy_request_protocol;

struct cproxy_http_request_extra {
    char request[256];
};

struct cproxy_socks5_request_extra {
    union {
        uint32_t ipv4;
        uint8_t ipv6[16];
    };
    uint16_t port;
};

typedef struct {
    char host[256];
    char port[7];
    uint16_t flags;
    cproxy_request_protocol type;
    union {
        struct cproxy_http_request_extra http;
        struct cproxy_socks5_request_extra socks5;
    };
} cproxy_request_t;

#endif