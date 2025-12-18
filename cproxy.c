#include "cproxy.h"

static int t_conn = 0;

static const char* HTTP_RESPONSE_CONN_ESTABLISHED = "HTTP/1.1 200 Connection established\r\n\r\n";

static int sock_fd, epoll_fd, conn_fd, num_conn = 0, fd_flags, evt, num_evs;
static struct epoll_event ev, events[MAX_EVENTS];
static memory_pool_t* memory_pool = NULL;

static uint8_t* type;
static conn_data_t* client_conn;
static target_conn_data_t* target_conn;
static cproxy_request_t* req;

static struct addrinfo *conn_addrinfo, 
                        conn_addrinfo_hint;

static struct sockaddr_in conn_addr;
static int conn_addr_len = sizeof(conn_addr);

static int recv_sz;
static char buf4096[4096];

void handle_signal(int signal){
    fprintf(cproxy_error, "Received signal - signal:%d\n", signal);
    if(memory_pool != NULL){
        memory_pool_destroy(memory_pool);
    }
    close(epoll_fd);
    close(sock_fd);
    fprintf(cproxy_output, "Stopped\n");
    exit(signal);
}

int setsocketnonblocking(int fd){
    if((fd_flags = fcntl(fd, F_GETFL, 0)) < 0){
        perror("Failed fcntl() F_GETFL");
        return -1;
    }

    if(fcntl(fd, F_SETFL, fd_flags | O_NONBLOCK) < 0){
        perror("Failed fcntl() F_SETFL");
        return -1;
    }

    return 0;
}

void close_conn(uint8_t type){
    type = type == 0 ? CONN_TARGET | CONN_CLIENT : type;
    errno = 0;
    if(type & CONN_TARGET && target_conn->fd != 0){
        if(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, target_conn->fd, NULL) < 0){
            perror("Failed epoll_ctl() for existing connection (target)");
        }
        close(target_conn->fd);
        fprintf(cproxy_output, "Closed target connection fd:%d\n", target_conn->fd);
        target_conn = NULL;
    }

    if(type & CONN_CLIENT){
        if(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_conn->fd, NULL) < 0){
            perror("Failed epoll_ctl() for existing connection (client)");
        }
        close(client_conn->fd);
        fprintf(cproxy_output, "Closed client connection fd:%d\n", client_conn->fd);
        memory_pool_release(memory_pool, &client_conn);
        client_conn = NULL;
        num_conn--;
    }
    t_conn--;
}

int acquire_conn(){
    errno = 0;
    memset(&conn_addrinfo_hint, 0, sizeof(conn_addrinfo_hint));
    conn_addrinfo_hint.ai_family = AF_INET;
    conn_addrinfo_hint.ai_socktype = SOCK_STREAM;
    if(getaddrinfo(req->host, req->port, &conn_addrinfo_hint, &conn_addrinfo) != 0){
        perror("Failed getaddrinfo()");
        return -1;
    }

    if((target_conn->fd = socket(conn_addrinfo->ai_family, conn_addrinfo->ai_socktype | SOCK_NONBLOCK, conn_addrinfo->ai_protocol)) < 0){
        perror("Failed acquire_conn socket()");
        return -1;
    }

    connect(target_conn->fd, conn_addrinfo->ai_addr, conn_addrinfo->ai_addrlen);
    perror("Target connection status");

    ev.events = EPOLLOUT;
    ev.data.ptr = target_conn;

    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, target_conn->fd, &ev) < 0){
        perror("Failed epoll_ctl() for new target connection");
        return -1;
    }
    memcpy(target_conn->host, req->host, strlen(req->host));
    memcpy(target_conn->port, req->port, 7);
    fprintf(cproxy_output, "Acquired conn - fd:%d\n", target_conn->fd);
    return 0;
}

void send_request(){
    fprintf(cproxy_output, "Attempting send_request()\n");
    errno = 0;
    send(target_conn->fd, req->http.request, strlen(req->http.request), MSG_NOSIGNAL);

    if(errno == EPIPE){ close_conn(0); return; }

    ev.events = EPOLLIN;
    ev.data.ptr = target_conn;

    if(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, target_conn->fd, &ev) < 0){
        perror("Failed epoll_ctl() for existing target connection");
        close_conn(0);
    }
}

void tunnel_data(int write_fd, int read_fd, uint8_t type){
    fprintf(cproxy_output, "Attempting tunnel_data() write_fd:%d read_fd:%d type:%d\n", write_fd,
                                                                                        read_fd,
                                                                                        type);
    errno = 0;
    do{
        recv_sz = recv(read_fd, buf4096, 4096, 0);
        if(errno == EAGAIN){ break; }
        send(write_fd, buf4096, recv_sz, MSG_NOSIGNAL);
        fprintf(cproxy_output, "recv_sz:%d errno:%d\n", recv_sz, errno);
    }while(recv_sz > 0);

    if(recv_sz == -1){ perror("Error"); }

    if(type == ( CONN_TARGET | CONN_ONCE ) || type & CONN_TARGET && recv_sz == 0){ close_conn(CONN_TARGET); }
    else if(recv_sz == 0 || errno == EPIPE){ close_conn(0); }
}

int process_connection(){
    type = (uint8_t*)events[evt].data.ptr;
    switch(*type){
        case CONN_CLIENT:
            fprintf(cproxy_output, "Attempting CONN_CLIENT\n");
            client_conn = (conn_data_t*)events[evt].data.ptr;
            target_conn = &client_conn->target;
            req = &client_conn->data.req;
            if(client_conn->tunnel == 1){ tunnel_data(target_conn->fd, client_conn->fd, CONN_CLIENT); }
            else{
                fprintf(cproxy_output, "Parsing request\n");
                if(parse_http_request(client_conn->fd, req) < 0){ close_conn(0); return -1; }
                fprintf(cproxy_output, "%s: method:`%s`\n", __FUNCTION__, req->http.method);
                fprintf(cproxy_output, "%s: path:`%s`\n", __FUNCTION__, req->http.path);
                fprintf(cproxy_output, "%s: host:`%s`\n", __FUNCTION__, req->host);
                fprintf(cproxy_output, "%s: port:`%s`\n", __FUNCTION__, req->port);
                fprintf(cproxy_output, "%s: flags:`%s`\n", __FUNCTION__, 
                                        req->flags & HTTP_REQ_KEEPALIVE_CONN ? "HTTP_REQ_KEEPALIVE_CONN" : NULL);
                fprintf(cproxy_output, "%s: request:`%s`\n", __FUNCTION__, req->http.request);
                if(acquire_conn() < 0){ close_conn(0); }
            }
            break;
        case CONN_TARGET:
            fprintf(cproxy_output, "Attempting CONN_TARGET\n");
            target_conn = (target_conn_data_t*)events[evt].data.ptr;
            client_conn = target_conn->client;
            req = &client_conn->data.req;
            if(strcmp(req->http.method, HTTP_REQUEST_CONNECT) == 0 && client_conn->tunnel == 0){
                send(client_conn->fd, HTTP_RESPONSE_CONN_ESTABLISHED,
                                      strlen(HTTP_RESPONSE_CONN_ESTABLISHED), 0);

                ev.events = EPOLLIN;
                ev.data.ptr = target_conn;
            
                if(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, target_conn->fd, &ev) < 0){
                    perror("Failed epoll_ctl() for connected target connection");
                    close_conn(0);
                    return -1;
                }

                fprintf(cproxy_output, "CONN_CLIENT - HTTP_RESPONSE_CONN_ESTABLISHED\n");
                client_conn->tunnel = 1;
                return -1;
            }
            else if(client_conn->tunnel == 1){ tunnel_data(client_conn->fd, target_conn->fd, CONN_TARGET); }
            else{ 
                if(events[evt].events == EPOLLOUT){ send_request(); }
                else{ tunnel_data(client_conn->fd, target_conn->fd, CONN_TARGET | CONN_ONCE); }
            }
            break;
    }
    return 0;
}

int accept_new_connection(){
    fprintf(cproxy_output, "Attempting new connection\n");
    if(num_conn == MAX_CONN){
        fprintf(cproxy_error, "Maximum number of connection hit num_conn:%d max:%d\n", num_conn, MAX_CONN);
        return -1;
    }

    if((conn_fd = accept(sock_fd, (struct sockaddr*)&conn_addr, (socklen_t*)&conn_addr_len)) < 0){
        perror("Failed accept()");
        return -1;
    }

    fprintf(cproxy_output, "Setting setsocketnonblocking() for new connection\n");
    if(setsocketnonblocking(conn_fd) < 0){
        fprintf(cproxy_error, "Failed setsocketnonblocking() for new connection\n");
        close(conn_fd);
        return -1;
    }

    fprintf(cproxy_output, "Setting memory_pool_get() for new connection\n");
    if(memory_pool_get(memory_pool, &client_conn) < 0){
        fprintf(cproxy_error, "Failed memory_pool_get() for new connection\n");
        close(conn_fd);
        return -1;
    }

    client_conn->fd = conn_fd;
    ev.events = EPOLLIN;
    ev.data.ptr = client_conn;

    perror("Setting epoll_ctl() for new connection");
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_fd, &ev) < 0){
        perror("Failed epoll_ctl() for new connection");
        close(conn_fd);
        return -1;
    }
    num_conn++;
    t_conn++;
    fprintf(cproxy_output, "Accepted new connection - %d\n", conn_fd);
    return 0;
}

void run_event_loop(){
    for(;;){
        fprintf(cproxy_output, "Calling epoll_wait\n");
        if((num_evs = epoll_wait(epoll_fd, events, MAX_EVENTS, -1)) < 0){
            perror("Failed epoll_wait()");
            return;
        }

        fprintf(cproxy_output, "****************** Start - num_evs:%d num_conn:%d t_conn:%d\n", num_evs, num_conn, t_conn);
        for(evt = 0;evt < num_evs;evt++){
            if(events[evt].data.fd == sock_fd){
                if(accept_new_connection() < 0){ continue; }
            }else{
                if(process_connection() < 0){ continue; }
            }
        }
        fprintf(cproxy_output, "****************** Done - num_evs:%d num_conn:%d t_conn:%d\n", num_evs, num_conn, t_conn);
    }
}

int main(int argc, char* argv[]){
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);

    uint16_t listening_port = 9441;

    int arg;
    while((arg = getopt(argc, argv, "p:")) != -1){
        switch(arg){
            case 'p':
                listening_port = (uint16_t)atoi(optarg);
                break;
            default:
                fprintf(cproxy_output, "Usage: cproxy [options]\n"
                                       "Arguments are not mandatory\n"
                                       "  -p port to listen on, default 9441\n");
                return 1;
        }
    }

    memory_pool = memory_pool_create(MAX_CONN);

    struct sockaddr_in sock_addr;
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = INADDR_ANY;
    sock_addr.sin_port = htons(listening_port);

    if((sock_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0){
        perror("Failed socket()");
        return -1;
    }

    int sock_opt = 1;
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &sock_opt, sizeof(sock_opt)) < 0){
        perror("Failed setsockopt()");
        return -1;
    }

    if(bind(sock_fd, (struct sockaddr*)&sock_addr, sizeof(sock_addr)) < 0){
        perror("Failed bind()");
        return -1;
    }

    if(listen(sock_fd, CONN_BACKLOG) < 0){
        perror("Failed listen()");
        return -1;
    }

    ev.events = EPOLLIN;
    ev.data.fd = sock_fd;

    if((epoll_fd = epoll_create1(0)) < 0){
        perror("Failed epoll_create1()");
        return -1;
    }

    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_fd, &ev) < 0){
        perror("Failed epoll_ctl()");
        return -1;
    }

    fprintf(cproxy_output, "cproxy listening on 0.0.0.0:%d\n", listening_port);

    run_event_loop();

    raise(SIGTERM);
}