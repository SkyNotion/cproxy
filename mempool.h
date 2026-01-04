#ifndef __CPROXY_MEMPOOL_H
#define __CPROXY_MEMPOOL_H

#include "common.h"
#include "http.h"
#include "request.h"
#include "conn.h"

typedef struct {
    size_t max_size;
    size_t size;
    conn_data_t* head;
    conn_data_t* tail;
    conn_data_t* block;
} memory_pool_t;

memory_pool_t* memory_pool_create(size_t size);
int memory_pool_get(memory_pool_t* memory_pool, conn_data_t** conn_data);
int memory_pool_release(memory_pool_t* memory_pool, conn_data_t** conn_data);
void memory_pool_destroy(memory_pool_t* memory_pool);

#endif