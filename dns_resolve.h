#ifndef __CPROXY_DNS_RESOLVE_H
#define __CPROXY_DNS_RESOLVE_H

#include "common.h"

#define DNS_ADDRESS "8.8.8.8" // Google's public dns

#define DNS_BUFFER_SIZE 512

struct dns_header{
    uint16_t ID;
    uint16_t FLAGS;
    uint16_t NOQ;
    uint16_t NOANS;
    uint16_t NOATH;
    uint16_t NOADD;
};

struct dns_response{
    uint16_t id;
    char* host;
    uint32_t ipv4;
};

int init_dns_resolver(int epoll_fd);
int send_dns_req(uint16_t id, const char* host, uint8_t host_len);
int recv_dns_resp(struct dns_response *dns_resp);

#endif