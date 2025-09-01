#ifndef CPROXY_H
#define CPROXY_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <ucontext.h>

typedef struct {
	char* block;
	size_t head;
	size_t size;
	size_t max_size;
} array_queue_t;

array_queue_t* array_queue_create(size_t size){
	if(size <= 0){
		return NULL;
	}
	array_queue_t* queue = (array_queue_t*)malloc(sizeof(array_queue_t));
	if(queue == NULL){
		return NULL;
	}
	queue->block = malloc(size*sizeof(char*));
	if(queue->block == NULL){
		return NULL;
	}
	queue->head = queue->size = 0;
	queue->max_size = size;
	return queue;
}

int array_queue_put(array_queue_t* queue, char* data){
	if (queue->size == queue->max_size){
		return 1;
	}
	memcpy(&queue->block[(queue->head + queue->size++) % queue->max_size], data, strlen(data)+1);
	return 0;
}

char* array_queue_get(array_queue_t* queue){
	if(queue->size == 0){
		return NULL;
	}
	queue->size--;
	queue->head = ++queue->head % queue->max_size;
	return &queue->block[queue->head];
}

int array_queue_destroy(array_queue_t* queue){
	if(queue == NULL){
		return -1;
	}
	free(queue->block);
	free(queue);
	queue = NULL;
	return 0;
}

#endif