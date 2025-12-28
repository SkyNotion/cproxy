#include "cproxy.h"

static const char* HTTP_RESPONSE_CONN_ESTABLISHED = "HTTP/1.1 200 Connection established\r\n\r\n";

static int sock_fd, epoll_fd, conn_fd, fd_flags, evt, num_evs;
static struct epoll_event ev, events[MAX_EVENTS];
static memory_pool_t* memory_pool = NULL;

static uint8_t* type;
static conn_data_t* client_conn;
static target_conn_data_t* target_conn;
static cproxy_request_t* req;

static struct addrinfo *conn_addrinfo = NULL, 
                        conn_addrinfo_hint;

static struct sockaddr* addr;
static struct sockaddr_in conn_addr;
static struct sockaddr_in6 conn_addr6;
static socklen_t conn_addr_len;

static int num_client = 0, num_target = 0, num_in_epollout = 0;

static int recv_sz;
static int addr_family, socktype;

#define BUFFER_16K_SIZE (16 * 1024)
static char buf16k[BUFFER_16K_SIZE];

void handle_signal(int signal){
    CPROXY_ERROR_LOG("Received signal - signal:%d\n", signal);
    if(memory_pool != NULL){
        memory_pool_destroy(memory_pool);
    }
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

void close_conn(uint8_t type){
    errno = 0;
    type = type == 0 ? (CONN_TARGET | CONN_CLIENT) : type;
    if(type & CONN_TARGET && !(target_conn->type & CONN_CLOSED) && target_conn->fd != 0){
        if(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, target_conn->fd, NULL) < 0){
            ERRNO_LOG("Failed epoll_ctl() for existing connection (target)");
        }
        close(target_conn->fd);
        DEBUG_LOG("Closed target connection fd:%d\n", target_conn->fd);
        target_conn->type |= CONN_CLOSED;
        target_conn = NULL;
        num_target--;
    }

    if(type & CONN_CLIENT && !(client_conn->type & CONN_CLOSED)){
        if(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_conn->fd, NULL) < 0){
            ERRNO_LOG("Failed epoll_ctl() for existing connection (client)");
        }
        close(client_conn->fd);
        DEBUG_LOG("Closed client connection fd:%d\n", client_conn->fd);
        client_conn->type |= CONN_CLOSED; 
        memory_pool_release(memory_pool, &client_conn);
        client_conn = NULL;
        num_client--;
    }

    ERRNO_LOG("close_conn");
}

int acquire_conn(){
    errno = 0;
    if(req->flags & CPROXY_UDP_SOCK){
        socktype = SOCK_DGRAM;
        ev.events = EPOLLOUT;
    }else{
        socktype = SOCK_STREAM;
        req->flags |= CPROXY_TCP_SOCK;
        ev.events = EPOLLOUT;
    }
    if(req->flags & CPROXY_SOCK5_ADDR_IPV4){
        conn_addr.sin_family = AF_INET;
        conn_addr.sin_addr.s_addr = req->socks5.ipv4;
        conn_addr.sin_port = req->socks5.port;
        conn_addr_len = sizeof(conn_addr);
        addr = (struct sockaddr*)&conn_addr;
        addr_family = conn_addr.sin_family;
    }else if(req->flags & CPROXY_SOCK5_ADDR_IPV6){
        conn_addr6.sin6_family = AF_INET6;
        memcpy(conn_addr6.sin6_addr.s6_addr, req->socks5.ipv6, 16);
        conn_addr6.sin6_port = req->socks5.port;
        conn_addr_len = sizeof(conn_addr6);
        addr = (struct sockaddr*)&conn_addr6;
        addr_family = conn_addr6.sin6_family;
    }else{
        memset(&conn_addrinfo_hint, 0, sizeof(conn_addrinfo_hint));
        conn_addrinfo_hint.ai_family = AF_UNSPEC;
        conn_addrinfo_hint.ai_socktype = socktype;
        /* NOTE: getaddrinfo is a blocking operation */
        if(getaddrinfo(req->host, req->port, &conn_addrinfo_hint, &conn_addrinfo) != 0){
            ERRNO_LOG("Failed getaddrinfo()");
            return -1;
        }
        conn_addr_len = conn_addrinfo->ai_addrlen;
        addr = conn_addrinfo->ai_addr;
        addr_family = conn_addrinfo->ai_family;
        DEBUG_LOG("USING HOSTS: %s:%s\n", req->host, req->port);
    }

    if((target_conn->fd = socket(addr_family, socktype | SOCK_NONBLOCK, 0)) < 0){
        if(!(req->flags & CPROXY_SOCK5_ADDR_IPV4) && !(req->flags & CPROXY_SOCK5_ADDR_IPV6)){
            freeaddrinfo(conn_addrinfo);
        }
        ERRNO_LOG("Failed acquire_conn socket()");
        return -1;
    }

    if(req->flags & CPROXY_UDP_SOCK){
        DEBUG_LOG("Registering UDP conn");
        goto register_conn;
    }

    connect(target_conn->fd, addr, conn_addr_len);
    ERRNO_LOG("Target connection status");

    if(!(req->flags & CPROXY_SOCK5_ADDR_IPV4) && !(req->flags & CPROXY_SOCK5_ADDR_IPV6)){
        freeaddrinfo(conn_addrinfo);
    }

register_conn:

    ev.data.ptr = target_conn;

    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, target_conn->fd, &ev) < 0){
        ERRNO_LOG("Failed epoll_ctl() for new target connection");
        return -1;
    }
    num_target++;
    num_in_epollout++;
    DEBUG_LOG("Acquired conn - fd:%d\n", target_conn->fd);
    if(errno == ENETDOWN || errno == ENETUNREACH || errno == ENETRESET){
        return -1;
    }
    return 0;
}

void send_request(){
    errno = 0;
    DEBUG_LOG("Attempting send_request()\n");
    send(target_conn->fd, req->http.request, strlen(req->http.request), MSG_NOSIGNAL);

    if(errno == EPIPE || errno == EBADF || errno == ECONNRESET){
        close_conn(0);
        return;
    }

    ev.events = EPOLLIN;
    ev.data.ptr = target_conn;

    if(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, target_conn->fd, &ev) < 0){
        ERRNO_LOG("Failed epoll_ctl() for existing target connection");
        close_conn(0);
    }
}

void tunnel_data(int write_fd, int read_fd, uint8_t type){
    errno = 0;
    DEBUG_LOG("Attempting tunnel_data() " \
              "write_fd:%d read_fd:%d type:%d\n", 
              write_fd, read_fd, type);

    do{
        recv_sz = recv(read_fd, buf16k, BUFFER_16K_SIZE, 0);
        DEBUG_LOG("recv_sz:%d errno:%d\n", recv_sz, errno);
        if(errno == EAGAIN){
            break;
        }
        send(write_fd, buf16k, recv_sz, MSG_NOSIGNAL);
    }while(recv_sz > 0);

    if(type == (CONN_TARGET | CONN_ONCE) ||
       recv_sz == 0 ||
       (errno != 0 && errno != EAGAIN)){ 
       //errno == EPIPE ||
       //errno == EBADF ||
       //errno == ECONNRESET ||
       //errno == ENOTCONN ||
       //errno == ECONNABORTED){
        close_conn(0);
    }
}

int process_connection(){
    type = (uint8_t*)events[evt].data.ptr;
    DEBUG_LOG("type_ptr:%p type:%d\n", type, *type);
    switch(*type & 0xf){
        case CONN_CLIENT:
            DEBUG_LOG("Attempting CONN_CLIENT\n");
            client_conn = (conn_data_t*)events[evt].data.ptr;
            target_conn = &client_conn->target;
            req = &client_conn->data.req;

            if(client_conn->tunnel == 1){
                tunnel_data(target_conn->fd, client_conn->fd, CONN_CLIENT);
            }else if(req->type == CPROXY_REQ_SOCKS5 && client_conn->tunnel == 0){
                if(socks5_handshake(client_conn->fd, CPROXY_SOCKS5_TARGET_CONN, req) < 0){
                    close_conn(0);
                    return -1;
                }

                if(acquire_conn() < 0){
                    close_conn(0);
                }
            }else{
                recv_sz = recv(client_conn->fd, buf16k, BUFFER_16K_SIZE, MSG_PEEK);

                if(recv_sz == 0){
                    close_conn(0);
                    return -1;
                }

                if((uint8_t)buf16k[0] == 0x05){
                    req->type = CPROXY_REQ_SOCKS5;
                    req->flags = 0;
                    if(socks5_handshake(client_conn->fd, CPROXY_SOCKS5_INITIAL_AUTH, req) < 0){
                        close_conn(0);
                        return -1;
                    }
                    return 0;
                }

                DEBUG_LOG("Parsing request client_conn->tunnel:%d\n", client_conn->tunnel);
                if(parse_http_request(client_conn->fd, req) < 0){
                    close_conn(0);
                    return -1;
                }
                DEBUG_LOG("%s: host:`%s`\n", __FUNCTION__, req->host);
                DEBUG_LOG("%s: port:`%s`\n", __FUNCTION__, req->port);
                DEBUG_LOG("%s: flags:`%d`\n", __FUNCTION__, req->flags);
                DEBUG_LOG("%s: request:`%s`\n", __FUNCTION__, req->http.request);
                if(acquire_conn() < 0){
                    close_conn(0);
                }
                req->type = CPROXY_REQ_HTTP;
            }
            break;
        case CONN_TARGET:
            DEBUG_LOG("Attempting CONN_TARGET\n");
            target_conn = (target_conn_data_t*)events[evt].data.ptr;
            client_conn = target_conn->client;
            req = &client_conn->data.req;
            if((req->flags & (CPROXY_HTTP_CONNECT | CPROXY_SOCKS5_TARGET_CONN)) &&
               client_conn->tunnel == 0){
                errno = 0;
                if(req->type == CPROXY_REQ_HTTP){
                    send(client_conn->fd, HTTP_RESPONSE_CONN_ESTABLISHED,
                        strlen(HTTP_RESPONSE_CONN_ESTABLISHED), MSG_NOSIGNAL);
                    DEBUG_LOG("CONN_CLIENT - HTTP_RESPONSE_CONN_ESTABLISHED\n");
                }else{
                    if(socks5_handshake(client_conn->fd, CPROXY_SOCKS5_TUNNEL, req) < 0){
                        close_conn(0);
                        return -1;
                    }
                    DEBUG_LOG("CONN_CLIENT - SOCKS5_RESPONSE_REQUEST_GRANTED\n");
                }

                if(errno == EPIPE){
                    close_conn(0);
                }

                ev.events = EPOLLIN;
                ev.data.ptr = target_conn;
            
                if(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, target_conn->fd, &ev) < 0){
                    ERRNO_LOG("Failed epoll_ctl() for connected target connection");
                    close_conn(0);
                    return -1;
                }

                client_conn->tunnel = 1;
                num_in_epollout--;
            }else if(req->flags & CPROXY_UDP_SOCK){
                DEBUG_LOG("SOCKS5 UDP CONN\n");
            }else if(client_conn->tunnel == 1){ 
                tunnel_data(client_conn->fd, target_conn->fd, CONN_TARGET); 
            }else{
                if(events[evt].events == EPOLLOUT){
                    send_request(); 
                }else{
                    tunnel_data(client_conn->fd, target_conn->fd, CONN_TARGET | CONN_ONCE);
                }
            }
            break;
        default:
            DEBUG_LOG("default case type_ptr:%p type:%d fd:%d event:%d\n", type, *type, events[evt].data.fd, events[evt].events);
            break;
    }
    return 0;
}

int accept_new_connection(){
    DEBUG_LOG("Attempting new connection\n");
    if(num_client == MAX_CONN){
        ERROR_LOG("Maximum number of connection hit num_client:%d max:%d\n", num_client, MAX_CONN);
        return -1;
    }

    conn_addr_len = sizeof(conn_addr);
    if((conn_fd = accept(sock_fd, (struct sockaddr*)&conn_addr, &conn_addr_len)) < 0){
        ERRNO_LOG("Failed accept()");
        return -1;
    }

    DEBUG_LOG("Setting setsocketnonblocking() for new connection\n");
    if(setsocketnonblocking(conn_fd) < 0){
        ERROR_LOG("Failed setsocketnonblocking() for new connection\n");
        close(conn_fd);
        return -1;
    }

    DEBUG_LOG("Setting memory_pool_get() for new connection\n");
    if(memory_pool_get(memory_pool, &client_conn) < 0){
        ERROR_LOG("Failed memory_pool_get() for new connection\n");
        close(conn_fd);
        return -1;
    }

    client_conn->fd = conn_fd;
    ev.events = EPOLLIN;
    ev.data.ptr = client_conn;

    ERRNO_LOG("Setting epoll_ctl() for new connection");
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_fd, &ev) < 0){
        ERRNO_LOG("Failed epoll_ctl() for new connection");
        close(conn_fd);
        return -1;
    }
    num_client++;
    DEBUG_LOG("Accepted new connection - %d\n", conn_fd);
    return 0;
}

void run_event_loop(){
    for(;;){
        DEBUG_LOG("Calling epoll_wait\n");
        if((num_evs = epoll_wait(epoll_fd, events, MAX_EVENTS, -1)) < 0){
            ERRNO_LOG("Failed epoll_wait()");
            return;
        }

        DEBUG_LOG("****************** Start - num_evs:%d" \
                  " mempool_max:%zu mempool_size:%zu num_in_epollout:%d" \
                  " num_conn:%d num_client:%d num_target:%d\n",
                  num_evs, memory_pool->max_size, memory_pool->size, num_in_epollout,
                  (num_client + num_target), num_client, num_target);

        for(evt = 0;evt < num_evs;evt++){
            if(events[evt].data.fd == sock_fd){
                DEBUG_LOG("accept_new_connection()\n");
                if(accept_new_connection() < 0){ 
                    continue; 
                }
            }else{
                DEBUG_LOG("process_connection()\n");
                if(process_connection() < 0){ 
                    continue; 
                }
            }
        }

        DEBUG_LOG("****************** Done - num_evs:%d" \
                  " mempool_max:%zu mempool_size:%zu num_in_epollout:%d" \
                  " num_conn:%d num_client:%d num_target:%d\n",
                  num_evs, memory_pool->max_size, memory_pool->size, num_in_epollout,
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

    CPROXY_INFO_LOG("cproxy listening on 0.0.0.0:%d\n", listening_port);

    run_event_loop();

    raise(SIGTERM);
}