#include "mempool.h"

memory_pool_t* memory_pool_create(size_t size){
    memory_pool_t* memory_pool = (memory_pool_t*)malloc(sizeof(memory_pool_t));
    memory_pool->blocks = (conn_data_t**)malloc(sizeof(conn_data_t*) * size);
    memory_pool->size = 0;
    memory_pool->max_size = size;
    memory_pool->head = NULL;
    for(size_t i = 0;i < size;i++){
        memory_pool->tail = (conn_data_t*)malloc(sizeof(conn_data_t));
        if(memory_pool->head != NULL){ memory_pool->head->next = memory_pool->tail; }
        memory_pool->tail->fd = 0;
        memory_pool->tail->tunnel = 0;
        memset(&memory_pool->tail->data, 0, sizeof(memory_pool->tail->data));
        memset(&memory_pool->tail->target, 0, sizeof(target_conn_data_t));
        memory_pool->blocks[i] = memory_pool->tail;
        memory_pool->head = memory_pool->tail;
    }
    memory_pool->head = memory_pool->blocks[0];
    return memory_pool;
}

int memory_pool_get(memory_pool_t* memory_pool, conn_data_t** conn_data){
    if(memory_pool->size == memory_pool->max_size ||
       memory_pool == NULL ||
       memory_pool->head == NULL){ return -1; }
    *conn_data = memory_pool->head;
    memory_pool->head = memory_pool->head->next;
    memory_pool->size--;
    (*conn_data)->type = CONN_CLIENT;
    (*conn_data)->target.type = CONN_TARGET;
    (*conn_data)->target.client = *conn_data;
    (*conn_data)->next = NULL;
    return 0;
}

int memory_pool_release(memory_pool_t* memory_pool, conn_data_t** conn_data){
    if(memory_pool == NULL ||
       conn_data == NULL ||
       memory_pool->tail == NULL){ return -1; }
    memory_pool->tail->next = *conn_data;
    memory_pool->tail = *conn_data;
    memory_pool->tail->next = NULL;
    memory_pool->tail->fd = 0;
    memory_pool->tail->tunnel = 0;
    memset(&memory_pool->tail->data, 0, sizeof(memory_pool->tail->data));
    memset(&memory_pool->tail->target, 0, sizeof(target_conn_data_t));
    return 0;
}

void memory_pool_destroy(memory_pool_t* memory_pool){
    for(size_t i = 0;i < memory_pool->max_size;i++){
        free(memory_pool->blocks[i]);
    }
    free(memory_pool->blocks);
    free(memory_pool);
}