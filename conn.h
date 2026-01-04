#ifndef __CPROXY_CONN_H
#define __CPROXY_CONN_H

#include "request.h"

#define CONN_CLIENT 0x1
#define CONN_TARGET 0x2

#define CONN_ONCE (0x1 << 4)
#define CONN_CLOSED (0x1 << 5)

struct target_conn_data_t;
struct conn_data_t;

typedef struct target_conn_data_t {
    uint8_t type;
    int fd;
    struct conn_data_t* client;
} target_conn_data_t;

typedef struct conn_data_t {
    uint8_t type;
    uint16_t index;
    int fd;
    union {
        cproxy_request_t req;
    } data;
    target_conn_data_t target;
    struct conn_data_t* next;
} conn_data_t;

#endif