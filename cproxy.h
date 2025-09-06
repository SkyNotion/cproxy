#ifndef CPROXY_H
#define CPROXY_H

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define C_QUEUE_DEFAULT_MEM_SIZE 64
#define C_QUEUE_DEFAULT_ADD_MEM_SIZE 16
#define C_QUEUE_MAX_LINE_LENGTH 65 // 64+1 for null line terminator \0

typedef struct epoll_event_data_t{
	int fd;
	int conn;
	int type;
	struct epoll_event_data_t* pair;
} epoll_event_data_t;

typedef struct {
	char data[C_QUEUE_MAX_LINE_LENGTH];
} c_queue_data_t;

typedef struct {
	c_queue_data_t* block;
	int lock;
	size_t head;
	size_t size;
	size_t max_size;
} c_queue_t;

typedef struct {
	epoll_event_data_t** block;
	size_t head;
	size_t size;
	size_t max_size;
} evd_queue_t;

c_queue_t* c_queue_create(){
	c_queue_t* queue = (c_queue_t*)malloc(sizeof(c_queue_t));
	if(queue == NULL){
		return NULL;
	}
	queue->block = (c_queue_data_t*)malloc(C_QUEUE_DEFAULT_MEM_SIZE*sizeof(c_queue_data_t));	
	if(queue->block == NULL){
		return NULL;
	}
	queue->lock = queue->head = queue->size = 0;
	queue->max_size = C_QUEUE_DEFAULT_MEM_SIZE;
	return queue;
}

int c_queue_lock(c_queue_t* queue){
	queue->lock++;
	queue->block = (c_queue_data_t*)realloc(queue->block, (queue->max_size = queue->size));
	queue->head = queue->max_size - 1;
	return 0;
}

int c_queue_put(c_queue_t* queue, char* data){
	if(queue->lock > 0 || strlen(data) > 64){
		return -1;
	}
	if(queue->size == queue->max_size){
		queue->max_size += C_QUEUE_DEFAULT_ADD_MEM_SIZE;
		queue->block = (c_queue_data_t*)realloc(queue->block, queue->max_size);
	}
	memcpy(queue->block[queue->size++].data, data, strlen(data)+1);
	return 0;
}

char* c_queue_get(c_queue_t* queue){
	if(queue->size == 0 || queue->lock == 0){
		return NULL;
	}
	return queue->block[(queue->head = ++queue->head % queue->max_size)].data;
}

int c_queue_destroy(c_queue_t* queue){
	if(queue == NULL){
		return -1;
	}
	free(queue->block);
	free(queue);
	queue = NULL;
	return 0;
}

evd_queue_t* evd_queue_create(size_t size){
	evd_queue_t* queue = (evd_queue_t*)malloc(sizeof(evd_queue_t));
	if(queue == NULL){
		return NULL;
	}
	queue->block = (epoll_event_data_t**)malloc(size*sizeof(epoll_event_data_t*));
	if(queue->block == NULL){
		return NULL;
	}
	queue->head = queue->size = 0;
	queue->max_size = size;
	return queue;
}

int evd_queue_put(evd_queue_t* queue, epoll_event_data_t* evd){
	if(queue->size == queue->max_size){
		return -1;
	}
	queue->block[(queue->head + queue->size++) % queue->max_size] = evd;
	return 0;
}

epoll_event_data_t* evd_queue_get(evd_queue_t* queue){
	queue->size--;
	return queue->block[(queue->head = ++queue->head % queue->max_size)];
}

int evd_queue_destroy(evd_queue_t* queue){
	if(queue == NULL){
		return -1;
	}
	free(queue->block);
	free(queue);
	queue = NULL;
	return 0;
}

#endif