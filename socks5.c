#include "socks5.h"

static char buffer[BUFFER_SIZE];
static int recv_sz, val;

static char SOCKS5_RESP_NO_AUTH[] = "\x05\x00";
static uint8_t SOCKS5_RESP_SUCCESS[] = {0x05, 0x00, 0x00};

int socks5_handshake(int fd, uint8_t step, cproxy_request_t* req){
    errno = 0;
    DEBUG_LOG("Entering socks5_handshake()\n");
    switch(step){
        case CPROXY_SOCKS5_INITIAL_AUTH:
            recv_sz = recv(fd, buffer, BUFFER_SIZE, 0);
            if(recv_sz == 0){
                return -1;
            }
            DEBUG_LOG("VER:%d\n", (uint8_t)buffer[0]);
            DEBUG_LOG("NAUTH:%d\n", (uint8_t)buffer[1]);
            send(fd, SOCKS5_RESP_NO_AUTH, 2, MSG_NOSIGNAL);
            if(errno == EPIPE || errno == EBADF || errno == ECONNRESET){
                return -1;
            }
            DEBUG_LOG("Sent CPROXY_SOCKS5_INITIAL_AUTH response\n");
            break;
        case CPROXY_SOCKS5_TARGET_CONN:
            recv_sz = recv(fd, buffer, BUFFER_SIZE, 0);
            if(recv_sz == 0 || recv_sz < 6){
                return -1;
            }
            DEBUG_LOG("recv_sz:%d\n", recv_sz);
            DEBUG_LOG("VER:%d\n", (uint8_t)buffer[0]);
            DEBUG_LOG("CMD:%d\n", (uint8_t)buffer[1]);
            DEBUG_LOG("RSV:%d\n", (uint8_t)buffer[2]);
            DEBUG_LOG("DSTADDR TYPE:%d\n", (uint8_t)buffer[3]);
            switch((uint8_t)buffer[3]){
                case SOCKS5_IPV4_ADDRESS:
                    if(recv_sz != 10){
                        return -1;
                    }
                    DEBUG_LOG("SOCKS5_IPV4_ADDRESS\n");
                    req->flags |= CPROXY_SOCK5_ADDR_IPV4;
                    memcpy(&req->socks5.ipv4, &buffer[4], sizeof(uint32_t));
                    memcpy(&req->socks5.port, &buffer[8], sizeof(uint16_t));
                    snprintf(req->port, sizeof(req->port), "%d", req->socks5.port);

                    DEBUG_LOG("DSTADDR ADDR->%d\n", req->socks5.ipv4);
                    DEBUG_LOG("DSTADDR ADDR->%d.%d.%d.%d\n",
                        (uint8_t)(req->socks5.ipv4),
                        (uint8_t)((req->socks5.ipv4 >> 8) & 0xff),
                        (uint8_t)((req->socks5.ipv4 >> 16) & 0xff),
                        (uint8_t)((req->socks5.ipv4 >> 24) & 0xff));
                    DEBUG_LOG("DSTPORT:%s\n", req->port);
                    break;
                case SOCKS5_IPV6_ADDRESS:
                    if(recv_sz != 22){
                        return -1;
                    }
                    DEBUG_LOG("SOCKS5_IPV6_ADDRESS\n");
                    req->flags |= CPROXY_SOCK5_ADDR_IPV6;
                    memcpy(req->socks5.ipv6, &buffer[4], 16);
                    memcpy(&req->socks5.port, &buffer[20], sizeof(uint16_t));
                    snprintf(req->port, sizeof(req->port), "%d", req->socks5.port);



                    DEBUG_LOG("DSTPORT:%s\n", req->port);
                    break;
                case SOCKS5_DOMAIN_NAME:
                    val = (uint8_t)buffer[4];
                    if(recv_sz != (7 + val)){
                        return -1;
                    }
                    DEBUG_LOG("SOCKS5_DOMAIN_NAME\n");
                    req->flags |= CPROXY_SOCK5_ADDR_DOMAIN;
                    memcpy(req->host, &buffer[5], val);
                    req->host[val] = '\0';
                    memcpy(&req->socks5.port, &buffer[5 + val], sizeof(uint16_t));
                    snprintf(req->port, sizeof(req->port), "%d", ntohs(req->socks5.port));

                    DEBUG_LOG("DSTADDR ADDR->%s\n", req->host);
                    DEBUG_LOG("DSTPORT:%s\n", req->port);
                    break;
                default:
                    return -1;
            }
            req->flags |= CPROXY_SOCKS5_TARGET_CONN;
            if((uint8_t)buffer[1] == SOCKS5_UDP_CONN){
                req->flags |= CPROXY_UDP_SOCK;
            }
            break;
        case CPROXY_SOCKS5_TUNNEL:
            DEBUG_LOG("%s:CPROXY_SOCKS5_TUNNEL\n", __FUNCTION__);
            val = sizeof(SOCKS5_RESP_SUCCESS);
            memcpy(buffer, SOCKS5_RESP_SUCCESS, sizeof(SOCKS5_RESP_SUCCESS));
            switch(req->flags & 0xf000){
                case CPROXY_SOCK5_ADDR_IPV4:
                    DEBUG_LOG("USING CPROXY_SOCK5_ADDR_IPV4\n");
                    buffer[val++] = (char)SOCKS5_IPV4_ADDRESS;
                    memcpy(&buffer[val], &req->socks5.ipv4, 4);
                    val += 4;
                    break;
                case CPROXY_SOCK5_ADDR_IPV6:
                    DEBUG_LOG("USING CPROXY_SOCK5_ADDR_IPV6\n");
                    buffer[val++] = (char)SOCKS5_IPV6_ADDRESS;
                    memcpy(&buffer[val], req->socks5.ipv6, 16);
                    val += 16;
                    break;
                case CPROXY_SOCK5_ADDR_DOMAIN:
                    DEBUG_LOG("USING CPROXY_SOCK5_ADDR_DOMAIN\n");
                    buffer[val++] = (char)SOCKS5_DOMAIN_NAME;
                    buffer[val++] = (char)strlen(req->host);
                    memcpy(&buffer[val], req->host, strlen(req->host));
                    val += strlen(req->host);
                    break;
                default:
                    return -1;
            }
            memcpy(&buffer[val++], &req->socks5.port, 2);
            send(fd, buffer, ++val, MSG_NOSIGNAL);
            if(errno == EPIPE){
                return -1;
            }
            DEBUG_LOG("%s:CPROXY_SOCKS5_TUNNEL->SENT val:%d\n", __FUNCTION__, val);
            break;
    }
    return 0;
}