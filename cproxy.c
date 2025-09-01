#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>

#include "queue.h"

#define OUTPUT_STREAM stdout
#define ERROR_STREAM stderr

#define CONN_BACKLOG 1048576

const char help_msg[] = "\
Usage: cproxy [OPTIONS]\n\n\
Arguments are not mandatory\n\
\t-p\tport to listen on, default 9441\n\
\t-c\tfile to get proxies, default NONE\n";

queue_t* proxies_queue;
int epoll_fd;

int main(int argc, char** argv){
	proxies_queue = NULL;
	int port = 9441;
	char* proxy_fn = NULL;
	char arg;
	while((arg = getopt(argc, argv, "p:c:h")) != -1){
		switch(arg){
			case 'p':
				port = atoi(optarg);
				break;
			case 'c':
				proxy_fn = optarg;
				break;
			case 'h':
				fprintf(OUTPUT_STREAM, "%s", help_msg);
				return -1;
			default:
				fprintf(OUTPUT_STREAM, "%s", help_msg);
				return -1;
		}
	}

	fprintf(OUTPUT_STREAM, "Using port %d\n", port);
	if(proxy_fn != NULL){
		fprintf(OUTPUT_STREAM, "Loading proxies from %s\n", proxy_fn);
		FILE* proxy_conf = fopen(proxy_fn, "r");
		char buf[128];
		size_t line_count = 0;
		while(fgets(buf, sizeof(buf), proxy_conf) != NULL){
			line_count++;
		}
		fseek(proxy_conf, 0, SEEK_SET);
		proxies_queue = queue_create(line_count);
		while(fgets(buf, sizeof(buf), proxy_conf) != NULL){
			queue_put(proxies_queue, buf);
		}
		fprintf(OUTPUT_STREAM, "Loaded %d proxies\n", line_count);
	}

	struct sockaddr_in socket_addr, client_socket_addr;
	socket_addr.sin_family = AF_INET;
	socket_addr.sin_port = htons(port);
	socket_addr.sin_addr.s_addr = INADDR_ANY;

	int server_socket, client_socket, server_sock_opt = 1, client_socket_addr_len = sizeof(struct sockaddr_in);
	if((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		fprintf(ERROR_STREAM, "Failed to create server socket\n");
		return -1;
	}

	fprintf(OUTPUT_STREAM, "Created socket");

	if(setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &server_sock_opt, sizeof(server_sock_opt)) < 0){
		fprintf(ERROR_STREAM, "Failed to set socket options\n");
		return -1;
	}

	if(bind(server_socket, (struct sockaddr*)&socket_addr, sizeof(socket_addr)) < 0){
		fprintf(ERROR_STREAM, "Failed to bind socket\n");
		return -1;
	}

	if(listen(server_socket, CONN_BACKLOG) < 0){
		fprintf(ERROR_STREAM, "Failed to start listening for connections on socket\n");
		return -1;
	}

	epoll_fd = epoll_create(1);
	if(epoll_fd < 0){
		fprintf(ERROR_STREAM, "Failed to create epoll object\n");
		return -1;
	}
	
	

	if(proxies_queue != NULL){
		queue_destroy(proxies_queue);
	}
}