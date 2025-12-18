#ifndef __CPROXY_REQUEST_H
#define __CPROXY_REQUEST_H

typedef enum cproxy_request_protocol {
    CPROXY_REQ_HTTP = 1,
    CPROXY_REQ_SOCKS5 = 2
} cproxy_request_protocol;

struct cproxy_http_request_extra {
    char path[256];
    char request[256];
    char method[8];
};

struct cproxy_socks5_request_extra {
    
};

typedef struct {
    char host[256];
    char port[7];
    uint32_t flags;
    cproxy_request_protocol type;
    union {
        struct cproxy_http_request_extra http;
        struct cproxy_socks5_request_extra socks5;
    };
} cproxy_request_t;

#endif