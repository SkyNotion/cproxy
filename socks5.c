#include "socks5.h"

static const uint8_t SOCKS5_RESP_NO_AUTH[] = {0x05, 0x00};
static const uint8_t SOCKS5_RESP_SUCCESS[] = {0x05, 0x00, 0x00};

static char buffer[SOCKS5_BUFFER_SIZE];

static int recv_sz, val;

int socks5_handshake(int fd, cproxy_request_t* req){
    errno = 0;
    switch(req->flags & 0xf0000){
        case CPROXY_SOCKS5_INITIAL_AUTH:
            CPROXY_INFO_LOG("Initiating socks5 handshake\n");
            if((recv_sz = recv(fd, buffer, SOCKS5_BUFFER_SIZE, 0)) == 0){
                return -1;
            }
            send(fd, (char*)SOCKS5_RESP_NO_AUTH, sizeof(SOCKS5_RESP_NO_AUTH), MSG_NOSIGNAL);
            if(errno == EPIPE || 
               errno == EBADF ||
               errno == ECONNRESET){
                return -1;
            }
            req->flags &= 0xfff0ffff;
            req->flags |= CPROXY_SOCKS5_TARGET_CONN;
            break;
        case CPROXY_SOCKS5_TARGET_CONN:
            recv_sz = recv(fd, buffer, SOCKS5_BUFFER_SIZE, 0);
            if(recv_sz == 0 || recv_sz < 6){
                return -1;
            }
            switch((uint8_t)buffer[3]){
                case SOCKS5_IPV4_ADDRESS:
                    if(recv_sz != 10){
                        return -1;
                    }
                    req->flags |= CPROXY_ADDR_IPV4;
                    memcpy(&req->ipv4_addr, &buffer[4], sizeof(uint32_t));
                    memcpy(&req->port, &buffer[8], sizeof(uint16_t));
                    break;
                case SOCKS5_IPV6_ADDRESS:
                    if(recv_sz != 22){
                        return -1;
                    }
                    req->flags |= CPROXY_ADDR_IPV6;
                    memcpy(req->ipv6_addr, &buffer[4], 16);
                    memcpy(&req->port, &buffer[20], sizeof(uint16_t));
                    break;
                case SOCKS5_DOMAIN_NAME:
                    val = (uint8_t)buffer[4];
                    if(recv_sz != (7 + val)){
                        return -1;
                    }
                    req->flags |= CPROXY_ADDR_DOMAIN;
                    memcpy(req->host, &buffer[5], val);
                    req->host_len = val;
                    memcpy(&req->port, &buffer[5 + val], sizeof(uint16_t));
                    break;
                default:
                    return -1;
            }
            req->flags &= 0xfff0ffff;
            req->flags |= CPROXY_SOCKS5_TUNNEL;
            if((uint8_t)buffer[1] == SOCKS5_UDP_CONN){
                req->flags |= CPROXY_UDP_SOCK;
            }
            break;
        default:
            if(req->flags & CPROXY_SOCKS5_TUNNEL){
                val = sizeof(SOCKS5_RESP_SUCCESS);
                memcpy(buffer, SOCKS5_RESP_SUCCESS, sizeof(SOCKS5_RESP_SUCCESS));
                switch(req->flags & 0xf0){
                    case CPROXY_ADDR_IPV4:
                        buffer[val++] = (char)SOCKS5_IPV4_ADDRESS;
                        memcpy(&buffer[val], &req->ipv4_addr, 4);
                        val += 4;
                        break;
                    case CPROXY_ADDR_IPV6:
                        buffer[val++] = (char)SOCKS5_IPV6_ADDRESS;
                        memcpy(&buffer[val], req->ipv6_addr, 16);
                        val += 16;
                        break;
                    case CPROXY_ADDR_DOMAIN:
                        buffer[val++] = (char)SOCKS5_DOMAIN_NAME;
                        buffer[val++] = (char)req->host_len;
                        memcpy(&buffer[val], req->host, req->host_len);
                        val += req->host_len;
                        break;
                    default:
                        return -1;
                }
                memcpy(&buffer[val++], &req->port, 2);
                send(fd, buffer, ++val, MSG_NOSIGNAL);
                if(errno == EPIPE){
                    return -1;
                }
                return 0;
            }
            return -1;
    }
    return 0;
}