#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "cproxy.h"

#define output stdout
//#define output logout
#define error stderr

#define CONN_BACKLOG 1024
#define MAX_CONN 2048
#define DEFAULT_PORT 9441

const char help_msg[] = "Usage: cproxy [OPTIONS]\n\n"
						"Arguments are not mandatory\n"
						"  -p\tport to listen on, default 9441\n"
						"  -c\tfile to get proxies, default NONE\n";

const char CONNECT_REQUEST[] = "CONNECT";
const char CONNECT_RESPONSE[] = "HTTP/1.1 200 Connection established\r\n\r\n";
const int CONNECT_RESPONSE_SZ = strlen(CONNECT_RESPONSE);

const char HTTP_PORT[] = "80";
const char GET_METHOD[] = "GET ";
const int GET_METHOD_SZ = strlen(GET_METHOD);

FILE* logout;

char buf128[128];
char buf1024[1024];

size_t num_conn = 0;
			
struct sockaddr_in proxy_addr, 
				   conn_addr;

int port = DEFAULT_PORT,
	proxy_sock,
	conn_sock,
	epoll_fd,
	num_ev = 0,
	ev = 0,
	recv_sz = 0,
	conn_addr_len = sizeof(conn_addr),
	sock_flags,
	start = 0,
	sock_opt = 1,
	path_len;

evd_queue_t *evd_pool;
epoll_event_data_t *evd,
				   *cur_evd,
				   *pair_evd;
c_queue_t* proxies_queue;

char *req_mtd, 
	 *req_host,
	 *req_port,
	 *req_path,
	 *target_host;

struct epoll_event sock_ev,
				   sock_evs[MAX_CONN];

struct addrinfo *conn_addrinfo, 
				 conn_addrinfo_hint;

void handle_signal(int signal){
	fprintf(output, "Received signal - signal:%d\n", signal);
	if(evd != NULL){
		free(evd);
	}
	if(evd_pool != NULL){
		evd_queue_destroy(evd_pool);
	}
	if(proxies_queue != NULL){
		c_queue_destroy(proxies_queue);
	}
	close(epoll_fd);
	close(proxy_sock);
	fprintf(output, "Stopped\n");
	fclose(logout);
	exit(signal);
}

void close_conn(){
	if(cur_evd->pair != NULL){
		if(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, cur_evd->pair->fd, NULL) < 0){
			perror("Failed epoll_ctl (pair_fd)");
			goto close_fd;
		}
		if(close(cur_evd->pair->fd) == 0){
			num_conn--;
			fprintf(output, "Closed connection - pair_fd:%d\n", cur_evd->pair->fd);
			evd_queue_put(evd_pool, cur_evd->pair);
		}
	}
	close_fd:
	if(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, cur_evd->fd, NULL) < 0){
		perror("Failed epoll_ctl (fd)");			
	}
	if(close(cur_evd->fd) == 0){
		num_conn--;
		fprintf(output, "Closed connection - fd:%d\n", cur_evd->fd);
		evd_queue_put(evd_pool, cur_evd);
	}
}

epoll_event_data_t* acquire_conn(char* host, char* port){
	memset(&conn_addrinfo_hint, 0, sizeof(conn_addrinfo_hint));
	conn_addrinfo_hint.ai_family = AF_INET;
	conn_addrinfo_hint.ai_socktype = SOCK_STREAM;
	if(getaddrinfo(host, port, &conn_addrinfo_hint, &conn_addrinfo) != 0){
		perror("Failed getaddrinfo");
		return NULL;
	}

	if((conn_sock = socket(conn_addrinfo->ai_family, conn_addrinfo->ai_socktype | SOCK_NONBLOCK, conn_addrinfo->ai_protocol)) < 0){
		perror("Failed socket (acquire_conn)");
		return NULL;
	}

	connect(conn_sock, conn_addrinfo->ai_addr, conn_addrinfo->ai_addrlen);
	perror("Connection");

	freeaddrinfo(conn_addrinfo);

	pair_evd = evd_queue_get(evd_pool);
	pair_evd->fd = conn_sock;
	pair_evd->conn = 0;
	pair_evd->type = 1;
	pair_evd->pair = cur_evd;

	num_conn++;
	sock_ev.events = EPOLLOUT;
	sock_ev.data.ptr = (void*)pair_evd;
	if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_sock, &sock_ev) < 0){
		perror("Failed epoll_ctl (acquire_conn)");
		return NULL;
	}
	fprintf(output, "Acquired conn - fd:%d\n", conn_sock);
	return pair_evd;
}

void start_proxy(void){
	for(;;){
		fprintf(output, "epoll_wait\n");
		if((num_ev = epoll_wait(epoll_fd, sock_evs, MAX_CONN, -1)) < 0){
			perror("Failed epoll_wait");
			return;
		}
		fprintf(output, "*************** - conn:%d - ev:%d\n", num_conn, num_ev);
		for(ev = 0;ev < num_ev;ev++){
			if(sock_evs[ev].data.fd == proxy_sock){
				if(num_conn >= MAX_CONN){
					continue;
				}

				if((conn_sock = accept(proxy_sock, (struct sockaddr*)&conn_addr, &conn_addr_len)) < 0){
					perror("Failed accept");
					continue;
				}

				if((sock_flags = fcntl(conn_sock, F_GETFL, 0)) < 0){
					perror("Failed fcntl (F_GETFL)");
					continue;
				}

				if(fcntl(conn_sock, F_SETFL, sock_flags | O_NONBLOCK) < 0){
					perror("Failed fcntl (F_SETFL)");
					continue;
				}

				cur_evd = evd_queue_get(evd_pool);
				cur_evd->fd = conn_sock;
				cur_evd->conn = 1;
				cur_evd->pair = NULL;
				cur_evd->type = 0;
				sock_ev.events = EPOLLIN | EPOLLET;
				sock_ev.data.ptr = (void*)cur_evd;
				if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_sock, &sock_ev) < 0){
					perror("Failed epoll_ctl for new conn");
					continue;
				}
				num_conn++;
				fprintf(output, "Accepted new connection - %d\n", conn_sock);
			}else{
				cur_evd = (epoll_event_data_t*)sock_evs[ev].data.ptr;
				if(cur_evd->pair == NULL){
					recv_sz = recv(cur_evd->fd, buf1024, sizeof(buf1024), MSG_PEEK);
					fprintf(output, "Processing new conn - fd:%d - recv_sz:%d\n", cur_evd->fd, recv_sz);
					if(recv_sz <= 0){
						close_conn();
						continue;
					}
					req_mtd = strtok(buf1024, " ");
					req_host = strtok(NULL, " ");
					if(strcmp(req_mtd, CONNECT_REQUEST) == 0){
						target_host = strtok(req_host, ":");
						req_port = strtok(NULL, ":");
						fprintf(output, "Request to - %s:%s\n", target_host, req_port);
						if((cur_evd->pair = acquire_conn(target_host, req_port)) == NULL){
							close_conn();
							continue;
						}
						cur_evd->pair->type = 2;
						fprintf(output, "Consuming CONNECT request\n");
						if(recv(cur_evd->fd, buf1024, sizeof(buf1024), 0) == 0){
							close_conn();
							continue;
						}
					}else if(strncmp(req_host, "http", 4) == 0){
						target_host = strtok(&req_host[7], "/");
						fprintf(output, "Request to - %s:%s\n", target_host, HTTP_PORT);
						if((cur_evd->pair = acquire_conn(target_host, (char*)HTTP_PORT)) == NULL){
							close_conn();
							continue;
						}
						cur_evd->pair->type = 3;
					}else{
						fprintf(output, "Invalid request - buf1024:%s\n", buf1024);
						close_conn();
						continue;
					}
					handled_new_conn:
					fprintf(output, "Handled new conn - fd:%d\n", cur_evd->fd);
				}else{
					fprintf(output, "Processing existing conn - fd:%d - event:%s no:%d\n", cur_evd->fd, sock_evs[ev].events == EPOLLOUT ? "EPOLLOUT" : "EPOLLIN", sock_evs[ev].events);
					if(cur_evd->conn == 0 && sock_evs[ev].events == EPOLLOUT){
						fprintf(output, "Connected - fd:%d\n", cur_evd->fd);
						cur_evd->conn = 1;
						sock_ev.events = EPOLLIN;
						sock_ev.data.ptr = (void*)cur_evd;
						if(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, cur_evd->fd, &sock_ev) < 0){
							perror("Failed epoll_ctl (fd)");
						}
						if(cur_evd->type == 2){
							send(cur_evd->pair->fd, CONNECT_RESPONSE, CONNECT_RESPONSE_SZ, MSG_NOSIGNAL);
							fprintf(output, "Sent CONNECT_RESPONSE\n");
							cur_evd->type = 1;
						}
						sock_ev.events = EPOLLIN;
						sock_ev.data.ptr = (void*)cur_evd->pair;
						if(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, cur_evd->pair->fd, &sock_ev) < 0){
							perror("Failed epoll_ctl (pair_fd)");
						}
					}else{
						if(cur_evd->pair->conn == 0){
							fprintf(output, "Tunneling data without pair recv:%d send:%d\n", cur_evd->fd, cur_evd->pair->fd);
							if(recv(cur_evd->fd, buf128, sizeof(buf128), MSG_PEEK) <= 0){
								close_conn();
								continue;
							}
							goto handled_existing_conn;
						}
						fprintf(output, "Tunneling data recv:%d send:%d\n", cur_evd->fd, cur_evd->pair->fd);
						recv_sz = recv(cur_evd->fd, buf1024, sizeof(buf1024), 0);
						fprintf(output, "tunnel_data:%d - errno:%d\n", recv_sz, errno);

						if(cur_evd->pair->type == 3){
							cur_evd->pair->type = 1;
							start = 12;
							req_path = strtok(&buf1024[start], "/");
							path_len = strlen(req_path);
							start += path_len-4;
							req_path[path_len] = '/';
							memcpy(&buf1024[start], GET_METHOD, GET_METHOD_SZ);
							fprintf(output, "to_tunnel:`%s`\n", &buf1024[start]);
							send(cur_evd->pair->fd, &buf1024[start], recv_sz-start, MSG_NOSIGNAL);
							goto handled_existing_conn;
						}

						if(recv_sz > 0){
							send(cur_evd->pair->fd, buf1024, recv_sz, MSG_NOSIGNAL);
						}else if(recv_sz == 0 || recv_sz == -1 || errno == EBADF){
							fprintf(output, "Received close fd:%d pair_fd:%d type:%d conn:%d pair_conn:%d\n", cur_evd->fd, cur_evd->pair->fd, cur_evd->type, cur_evd->conn, cur_evd->pair->conn);
							close_conn();
							continue;
						}
					}
					handled_existing_conn:
					fprintf(output, "Handled existing conn - fd:%d\n", cur_evd->fd);
				}
			}
		}
		fprintf(output, "+++++++++++++++ - conn:%d - ev:%d - evd_pool:%d\n", num_conn, num_ev, evd_pool->size);
	}
}

int main(int argc, char** argv){
	signal(SIGTERM, handle_signal);
	signal(SIGINT, handle_signal);

	logout = fopen("log.txt", "w");

	char arg;
	while((arg = getopt(argc, argv, "p:x:")) != -1){
		switch(arg){
			case 'p':
				port = atoi(optarg);
				break;
			case 'x':
				proxies_queue = c_queue_create();
				fprintf(output, "Loading proxies from %s\n", optarg);
				FILE* proxies_f = fopen(optarg, "r");
				int proxies_count;
				while(fgets(buf128, sizeof(buf128), proxies_f) != NULL){
					c_queue_put(proxies_queue, buf128);
					proxies_count++;
				}
				c_queue_lock(proxies_queue);
				fprintf(output, "Loaded %d proxies\n", proxies_count);
				break;
			default:
				fprintf(output, "%s\n", help_msg);
				return -1;
		}
	}

	proxy_addr.sin_family = AF_INET;
	proxy_addr.sin_port = htons(port);
	proxy_addr.sin_addr.s_addr = INADDR_ANY;

	if((proxy_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		perror("Failed socket");
		return -1;
	}

	if(setsockopt(proxy_sock, SOL_SOCKET, SO_REUSEPORT, &sock_opt, sizeof(sock_opt)) < 0){
		perror("Failed setsockopt");
		return -1;
	}

	if(bind(proxy_sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) < 0){
		perror("Failed bind");
		return -1;
	}

	if(listen(proxy_sock, CONN_BACKLOG) < 0){
		perror("Failed listen");
		return -1;
	}

	sock_ev.events = EPOLLIN;
	sock_ev.data.fd = proxy_sock;

	if((epoll_fd = epoll_create(1)) < 0){
		perror("Failed epoll_create");
		return -1;
	}

	if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, proxy_sock, &sock_ev) < 0){
		perror("Failed epoll_ctl");
		return -1;
	}

	evd = (epoll_event_data_t*)malloc(MAX_CONN*sizeof(epoll_event_data_t));
	evd_pool = evd_queue_create(MAX_CONN);

	for(int i = 0;i < MAX_CONN;i++){
		evd_queue_put(evd_pool, &evd[i]);
	}

	fprintf(output, "cproxy listen on 0.0.0.0:%d\n", port);

	start_proxy();

	raise(SIGTERM);
}