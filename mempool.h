#ifndef __CPROXY_MEMPOOL_H
#define __CPROXY_MEMPOOL_H

#include "common.h"
#include "http.h"

#define CONN_CLIENT 0x1
#define CONN_TARGET 0x2


#define CONN_ONCE 0x10

struct target_conn_data_t;
struct conn_data_t;

typedef struct target_conn_data_t {
    uint8_t type;
    int fd;
    char host[256];
    char port[7];
    struct conn_data_t* client;
} target_conn_data_t;

typedef struct conn_data_t {
    uint8_t type;
    int fd;
    uint8_t tunnel;
    union {
        cproxy_http_request_t req;
    } data;
    target_conn_data_t target;
    struct conn_data_t* next;
} conn_data_t;

typedef struct {
    size_t max_size;
    size_t size;
    conn_data_t* head;
    conn_data_t* tail;
    conn_data_t** blocks;
} memory_pool_t;

memory_pool_t* memory_pool_create(size_t size);
int memory_pool_get(memory_pool_t* memory_pool, conn_data_t** conn_data);
int memory_pool_release(memory_pool_t* memory_pool, conn_data_t** conn_data);
void memory_pool_destroy(memory_pool_t* memory_pool);

#endif