#include "cproxy.h"

static const char HTTP_CONN_ESTABLISHED[] = "HTTP/1.1 200 Connection established\r\n\r\n";

static int sock_fd, epoll_fd, dns_fd, conn_fd, fd_flags, evt, num_evs;
static struct epoll_event ev, events[MAX_EVENTS];
static memory_pool_t* memory_pool = NULL;

static uint8_t* type;
static conn_data_t* client_conn;
static target_conn_data_t* target_conn;
static cproxy_request_t* req;
static struct dns_response dns_resp;

static struct sockaddr* addr;
static struct sockaddr_in conn_addr;
static struct sockaddr_in6 conn_addr6;
static socklen_t conn_addr_len;

static int num_client = 0, num_target = 0;

static int recv_sz;
static int addr_family, socktype;

static char buffer[BUFFER_SIZE];

void handle_signal(int signal){
    CPROXY_ERROR_LOG("Received signal - signal:%d\n", signal);
    if(memory_pool != NULL){
        memory_pool_destroy(memory_pool);
    }
    close(dns_fd);
    close(epoll_fd);
    close(sock_fd);
    CPROXY_INFO_LOG("Stopped\n");
    exit(signal);
}

int setsocketnonblocking(int fd){
    if((fd_flags = fcntl(fd, F_GETFL, 0)) < 0){
        ERRNO_LOG("Failed fcntl() F_GETFL");
        return -1;
    }

    if(fcntl(fd, F_SETFL, fd_flags | O_NONBLOCK) < 0){
        ERRNO_LOG("Failed fcntl() F_SETFL");
        return -1;
    }

    return 0;
}

void close_conn(){
    if(!(target_conn->type & CONN_CLOSED) && target_conn->fd != 0){
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, target_conn->fd, NULL);
        close(target_conn->fd);
        target_conn->type |= CONN_CLOSED;
        target_conn = NULL;
        num_target--;
    }

    if(!(client_conn->type & CONN_CLOSED)){
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_conn->fd, NULL);
        close(client_conn->fd);
        client_conn->type |= CONN_CLOSED; 
        memory_pool_release(memory_pool, &client_conn);
        client_conn = NULL;
        num_client--;
    }
}

int acquire_conn(){
    errno = 0;
    if(req->flags & CPROXY_UDP_SOCK){
        DEBUG_LOG("USING UDP\n");
        socktype = SOCK_DGRAM;
        ev.events = EPOLLOUT;
    }else{
        DEBUG_LOG("USING TCP\n");
        socktype = SOCK_STREAM;
        req->flags |= CPROXY_TCP_SOCK;
        ev.events = EPOLLOUT;
    }
    if(req->flags & CPROXY_ADDR_IPV4){
        conn_addr.sin_addr.s_addr = req->ipv4_addr;
        conn_addr.sin_port = req->port;
        conn_addr_len = sizeof(conn_addr);
        addr = (struct sockaddr*)&conn_addr;
        addr_family = conn_addr.sin_family;

    CPROXY_INFO_LOG("Attempt new connection - " \
                    "fd->%d address->%d.%d.%d.%d:%d\n", target_conn->fd,
                    (uint8_t)(conn_addr.sin_addr.s_addr),
                    (uint8_t)((conn_addr.sin_addr.s_addr >> 8) & 0xff),
                    (uint8_t)((conn_addr.sin_addr.s_addr >> 16) & 0xff),
                    (uint8_t)((conn_addr.sin_addr.s_addr >> 24) & 0xff),
                    ntohs(conn_addr.sin_port));
    }else if(req->flags & CPROXY_ADDR_IPV6){
        DEBUG_LOG("IPV6 ADDRESS\n");
        memcpy(conn_addr6.sin6_addr.s6_addr, req->ipv6_addr, 16);
        conn_addr6.sin6_port = req->port;
        conn_addr_len = sizeof(conn_addr6);
        addr = (struct sockaddr*)&conn_addr6;
        addr_family = conn_addr6.sin6_family;
    }else{
        if(send_dns_req(client_conn->index, (const char*)req->host, req->host_len) < 0){
            return -1;
        }
        DEBUG_LOG("SENT DNS REQUEST: %s\n", req->host);
        return 0;
    }

    if((target_conn->fd = socket(addr_family, socktype | SOCK_NONBLOCK, 0)) < 0){
        ERRNO_LOG("Failed acquire_conn socket()");
        return -1;
    }

    if(req->flags & CPROXY_UDP_SOCK){
        DEBUG_LOG("Registering UDP conn");
        goto register_conn;
    }

    connect(target_conn->fd, addr, conn_addr_len);
    DEBUG_LOG("Attempt connection\n");

    ERRNO_LOG("Status");

register_conn:
    ev.data.ptr = target_conn;

    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, target_conn->fd, &ev) < 0){
        ERRNO_LOG("Failed epoll_ctl() (new)");
        return -1;
    }
    num_target++;

    if(errno != EINPROGRESS){
        return -1;
    }

    return 0;
}

void send_request(){
    errno = 0;
    send(target_conn->fd, req->buffer, req->buffer_len, MSG_NOSIGNAL);

    if(errno == EPIPE || errno == EBADF || errno == ECONNRESET){
        close_conn();
        return;
    }

    ev.events = EPOLLIN;
    ev.data.ptr = target_conn;

    if(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, target_conn->fd, &ev) < 0){
        close_conn();
    }
}

void tunnel_data(int write_fd, int read_fd){
    errno = 0;
    do{
        recv_sz = recv(read_fd, buffer, BUFFER_SIZE, 0);
        if(errno == EAGAIN){
            break;
        }
        send(write_fd, buffer, recv_sz, MSG_NOSIGNAL);
    }while(recv_sz > 0);

    if(recv_sz == 0 || (errno != 0 && errno != EAGAIN)){
        close_conn();
    }
}

int process_connection(){
    type = (uint8_t*)events[evt].data.ptr;
    switch(*type & 0xf){
        case CONN_CLIENT:
            DEBUG_LOG("type:%d CONN_CLIENT events:%d\n", *type, events[evt].events);
            client_conn = (conn_data_t*)events[evt].data.ptr;
            target_conn = &client_conn->target;
            req = &client_conn->data.req;
            if(events[evt].events & (EPOLLERR | EPOLLHUP)){
                close_conn();
            }
            if(req->flags & CPROXY_ACTIVE_TUNNEL){
                tunnel_data(target_conn->fd, client_conn->fd);
            }else if((req->flags & CPROXY_REQ_SOCKS5) &&
                    !(req->flags & CPROXY_ACTIVE_TUNNEL)){
                if(socks5_handshake(client_conn->fd, req) < 0){
                    close_conn();
                    return -1;
                }

                DEBUG_LOG("Parsed socks5 " \
                          "host:`%s` host_len:%d ipv4_addr:%d.%d.%d.%d " \
                          "port:%d flags:%d buffer:`%s` buffer_len:%d\n",
                          req->host, req->host_len, (uint8_t)(req->ipv4_addr),
                          (uint8_t)((req->ipv4_addr >> 8) & 0xff),
                          (uint8_t)((req->ipv4_addr >> 16) & 0xff),
                          (uint8_t)((req->ipv4_addr >> 24) & 0xff),
                          ntohs(req->port), req->flags, req->buffer, req->buffer_len);

                if(acquire_conn() < 0){
                    close_conn();
                }
            }else{
                if((recv_sz = recv(client_conn->fd, buffer, 
                    BUFFER_SIZE, MSG_PEEK)) == 0){
                    close_conn();
                    return -1;
                }

                if(buffer[0] == '\x05'){
                    req->flags &= 0xfff0ffff;
                    req->flags |= CPROXY_SOCKS5_INITIAL_AUTH;
                    if(socks5_handshake(client_conn->fd, req) < 0){
                        close_conn();
                        return -1;
                    }
                    return 0;
                }

                if(parse_http_request(client_conn->fd, req) < 0){
                    close_conn();
                    return -1;
                }

                DEBUG_LOG("Parsed http " \
                          "host:`%s` host_len:%d ipv4_addr:%d.%d.%d.%d " \
                          "port:%d flags:%d buffer:`%s` buffer_len:%d\n",
                          req->host, req->host_len, (uint8_t)(req->ipv4_addr),
                          (uint8_t)((req->ipv4_addr >> 8) & 0xff),
                          (uint8_t)((req->ipv4_addr >> 16) & 0xff),
                          (uint8_t)((req->ipv4_addr >> 24) & 0xff),
                          ntohs(req->port), req->flags, req->buffer, req->buffer_len);

                if(acquire_conn() < 0){
                    close_conn();
                }
            }
            break;
        case CONN_TARGET:
            DEBUG_LOG("type:%d CONN_TARGET event:%d\n", *type, events[evt].events);
            target_conn = (target_conn_data_t*)events[evt].data.ptr;
            client_conn = target_conn->client;
            req = &client_conn->data.req;
            if(events[evt].events & (EPOLLERR | EPOLLHUP)){
                close_conn();
            }
            if(req->flags & CPROXY_ACTIVE_TUNNEL){
                tunnel_data(client_conn->fd, target_conn->fd);
            }else if((req->flags & (CPROXY_HTTP_TUNNEL | CPROXY_SOCKS5_TUNNEL)) &&
                     !(req->flags & CPROXY_ACTIVE_TUNNEL)){
                errno = 0;
                if(req->flags & CPROXY_REQ_HTTP){
                    send(client_conn->fd, HTTP_CONN_ESTABLISHED,
                        CONSTSTRLEN(HTTP_CONN_ESTABLISHED), MSG_NOSIGNAL);
                    if(errno == EPIPE){
                        close_conn();
                    }
                    DEBUG_LOG("CONN_CLIENT - HTTP_CONN_ESTABLISHED\n");
                }else if(req->flags & CPROXY_REQ_SOCKS5){
                    if(socks5_handshake(client_conn->fd, req) < 0){
                        close_conn();
                        return -1;
                    }
                    DEBUG_LOG("CONN_CLIENT - SOCKS5_REQUEST_GRANTED\n");
                }

                ev.events = EPOLLIN;
                ev.data.ptr = target_conn;
            
                if(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, target_conn->fd, &ev) < 0){
                    ERRNO_LOG("Failed epoll_ctl() for connected target connection");
                    close_conn();
                    return -1;
                }

                req->flags |= CPROXY_ACTIVE_TUNNEL;
            }else if((req->flags & CPROXY_REQ_SOCKS5) && 
                     (req->flags & CPROXY_UDP_SOCK)){
                DEBUG_LOG("SOCKS5 UDP CONN\n");
            }else if(events[evt].events == EPOLLOUT){
                send_request();
                req->flags |= CPROXY_ACTIVE_TUNNEL;
            }
            break;
        default:
            DEBUG_LOG("Unknown type:%d\n", *type);
            break;
    }
    return 0;
}

int accept_new_connection(){
    if(num_client == MAX_CONN){
        ERROR_LOG("Maximum number of connection hit num_client:%d max:%d\n", num_client, MAX_CONN);
        return -1;
    }

    conn_addr_len = sizeof(conn_addr);
    if((conn_fd = accept(sock_fd, (struct sockaddr*)&conn_addr, &conn_addr_len)) < 0){
        ERRNO_LOG("Failed accept()");
        return -1;
    }

    if(setsocketnonblocking(conn_fd) < 0){
        ERROR_LOG("Failed setsocketnonblocking() for new connection\n");
        close(conn_fd);
        return -1;
    }

    if(memory_pool_get(memory_pool, &client_conn) < 0){
        ERROR_LOG("Failed memory_pool_get() for new connection\n");
        close(conn_fd);
        return -1;
    }

    client_conn->fd = conn_fd;
    ev.events = EPOLLIN;
    ev.data.ptr = client_conn;

    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_fd, &ev) < 0){
        ERRNO_LOG("Failed epoll_ctl() for new connection");
        close(conn_fd);
        return -1;
    }
    num_client++;
    CPROXY_INFO_LOG("Accepted new connection - " \
                    "fd->%d address->%d.%d.%d.%d:%d\n", conn_fd,
                    (uint8_t)(conn_addr.sin_addr.s_addr),
                    (uint8_t)((conn_addr.sin_addr.s_addr >> 8) & 0xff),
                    (uint8_t)((conn_addr.sin_addr.s_addr >> 16) & 0xff),
                    (uint8_t)((conn_addr.sin_addr.s_addr >> 24) & 0xff),
                    ntohs(conn_addr.sin_port));
    return 0;
}

void run_event_loop(){
    for(;;){
        errno = 0;
        DEBUG_LOG("Calling epoll_wait\n");
        if((num_evs = epoll_wait(epoll_fd, events, MAX_EVENTS, -1)) < 0){
            ERRNO_LOG("Failed epoll_wait()");
            if(errno == EINTR){
                 continue;
            }
            return;
        }

        DEBUG_LOG("****************** Start - num_evs:%d" \
                  " mempool_max:%zu mempool_size:%zu" \
                  " num_conn:%d num_client:%d num_target:%d\n",
                  num_evs, memory_pool->max_size, memory_pool->size,
                  (num_client + num_target), num_client, num_target);

        for(evt = 0;evt < num_evs;evt++){
            if(events[evt].data.fd == sock_fd){
                DEBUG_LOG("Processing new conn request\n");
                if(accept_new_connection() < 0){ 
                    continue; 
                }
            }else if(events[evt].data.fd == dns_fd){
                DEBUG_LOG("Processing dns response\n");
                if(recv_dns_resp(&dns_resp) < 0){
                    ERROR_LOG("Failed recv_dns_resp()\n");
                    continue;
                }

                if(dns_resp.id >= memory_pool->max_size){
                    ERRNO_LOG("Failed dns - id > mempool_size\n");
                    continue;
                }

                client_conn = &memory_pool->block[dns_resp.id];
                if(client_conn->type == 0){
                    ERRNO_LOG("Failed dns - client_conn->type = 0\n");
                    continue;
                }

                DEBUG_LOG("Received host->%s ipv4->%d.%d.%d.%d\n", dns_resp.host,
                    (uint8_t)(dns_resp.ipv4),
                    (uint8_t)((dns_resp.ipv4 >> 8) & 0xff),
                    (uint8_t)((dns_resp.ipv4 >> 16) & 0xff),
                    (uint8_t)((dns_resp.ipv4 >> 24) & 0xff));

                target_conn = &client_conn->target;
                req = &client_conn->data.req;
                req->ipv4_addr = dns_resp.ipv4;

                req->flags &= 0xffffff0f;
                req->flags |= CPROXY_ADDR_IPV4;

                if(acquire_conn() < 0){
                    close_conn();
                }
            }else{
                DEBUG_LOG("Processing conn\n");
                if(process_connection() < 0){ 
                    continue; 
                }
            }
        }

        DEBUG_LOG("****************** Done - num_evs:%d" \
                  " mempool_max:%zu mempool_size:%zu" \
                  " num_conn:%d num_client:%d num_target:%d\n",
                  num_evs, memory_pool->max_size, memory_pool->size,
                  (num_client + num_target), num_client, num_target);
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
                CPROXY_INFO_LOG("Usage: cproxy [options]\n"
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
        ERRNO_LOG("Failed socket()");
        return -1;
    }

    int sock_opt = 1;
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &sock_opt, sizeof(sock_opt)) < 0){
        ERRNO_LOG("Failed setsockopt()");
        return -1;
    }

    if(bind(sock_fd, (struct sockaddr*)&sock_addr, sizeof(sock_addr)) < 0){
        ERRNO_LOG("Failed bind()");
        return -1;
    }

    if(listen(sock_fd, CONN_BACKLOG) < 0){
        ERRNO_LOG("Failed listen()");
        return -1;
    }

    ev.events = EPOLLIN;
    ev.data.fd = sock_fd;

    if((epoll_fd = epoll_create1(0)) < 0){
        ERRNO_LOG("Failed epoll_create1()");
        return -1;
    }

    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_fd, &ev) < 0){
        ERRNO_LOG("Failed epoll_ctl()");
        return -1;
    }

    if((dns_fd = init_dns_resolver(epoll_fd)) < 0){
        ERROR_LOG("Failed init_dns_resolver()\n");
        return -1;
    }

    conn_addr.sin_family = AF_INET;
    conn_addr6.sin6_family = AF_INET6;

    CPROXY_INFO_LOG("cproxy listening on 0.0.0.0:%d\n", listening_port);

    run_event_loop();

    raise(SIGTERM);
}