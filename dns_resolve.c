#include "dns_resolve.h"

static const uint8_t header[] = {0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t in_dns_question[] = {0x00, 0x01, 0x00, 0x01};

static char buffer[DNS_BUFFER_SIZE];
static char hostname[258];

static int dns_fd;
static struct sockaddr_in dns_addr;
static socklen_t dns_addr_len;

static int pos, lpos, inc, sz, data_sz;
static uint16_t TYPE, CLASS;
static struct dns_header DNS_HEADER;

int init_dns_resolver(int epoll_fd){
    if((dns_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0)) < 0){
        ERRNO_LOG("Failed - init_dns_resolver - socket()");
        return -1;
    }

    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(53);

    if(inet_aton(DNS_ADDRESS, &dns_addr.sin_addr) == 0){
        ERRNO_LOG("Failed - init_dns_resolver - inet_aton()");
        return -1;
    }

    dns_addr_len = sizeof(dns_addr);

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = dns_fd;

    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, dns_fd, &ev) < 0){
        ERRNO_LOG("Failed - init_dns_resolver - epoll_ctl()");
        return -1;
    }

    return dns_fd;
}

int send_dns_req(uint16_t id, const char* host, uint8_t host_len){
    id = htons(id);
    memcpy(buffer, &id, sizeof(uint16_t));
    memcpy(&buffer[2], header, sizeof(header));
    pos = 2 + sizeof(header);
    lpos = sz = 0;
    for(inc = 0;inc < host_len;inc++){
        if(inc == (host_len - 1)){
            inc++;
        }

        if(host[inc] == 0x2e || inc == host_len){
            sz = inc - lpos;
            buffer[pos++] = (char)sz;
            memcpy(&buffer[pos], &host[lpos], sz);
            pos += sz;
            lpos = ++inc;
        }
    }
    buffer[pos++] = '\x00';
    memcpy(&buffer[pos], in_dns_question, sizeof(in_dns_question));
    pos += sizeof(in_dns_question);
    if(sendto(dns_fd, (const void*)buffer, pos, MSG_NOSIGNAL,
              (const struct sockaddr*)&dns_addr, dns_addr_len) < 0){
        ERRNO_LOG("Failed - send_dns_req - sendto()");
        return -1;   
    }
    return pos;
}

void parse_dns_answer(struct dns_response *dns_resp){
    pos = 0;
    do{
        sz = lpos + pos;
        inc = (uint8_t)buffer[sz];
        if(inc == 0){
            pos++;
            break;
        }else if((inc & 0xc0) == 0xc0){
            pos += 2;
            break;
        }
        pos += inc;
    }while(inc != 0);
    lpos += pos;

    memcpy(&TYPE, &buffer[lpos], 2);
    lpos += 2;
    TYPE = ntohs(TYPE);

    memcpy(&CLASS, &buffer[lpos], 2);
    lpos += 6;
    CLASS = ntohs(CLASS);

    memcpy(&sz, &buffer[lpos], 2);
    lpos += 2;
    sz = ntohs(sz);

    if(TYPE != 1 || CLASS != 1){
        lpos += sz;
        return;
    }
    memcpy(&dns_resp->ipv4, &buffer[lpos], sz);
}

int recv_dns_resp(struct dns_response *dns_resp){
    errno = 0;
    data_sz = recvfrom(dns_fd, (void*)buffer, DNS_BUFFER_SIZE, 0,
                           (struct sockaddr*)&dns_addr, &dns_addr_len);

    if(errno == EAGAIN || data_sz <= (int)sizeof(struct dns_header)){
        ERRNO_LOG("Failed - recv_dns_resp");
        return -1;
    }
    lpos = pos = 0;
    memcpy(&DNS_HEADER, buffer, sizeof(struct dns_header));

    DNS_HEADER.ID = ntohs(DNS_HEADER.ID);
    DNS_HEADER.FLAGS = ntohs(DNS_HEADER.FLAGS);
    DNS_HEADER.NOANS = ntohs(DNS_HEADER.NOANS);

    if(DNS_HEADER.NOANS == 0){
        ERROR_LOG("Failed - recv_dns_resp - NUMBER OF ANSWERS = 0\n");
        return -1;
    }
    lpos = sizeof(struct dns_header);

    do{
        sz = lpos + pos;
        inc = (uint8_t)buffer[sz];
        if(inc == 0){
            pos++;
            break;
        }
        buffer[sz] = '.';
        memcpy(&hostname[pos], &buffer[sz], ++inc);
        pos += inc;
    }while(inc != 0);
    hostname[pos - 1] = '\0';
    lpos += (pos + 4);
    dns_resp->ipv4 = 0;

    do{
        parse_dns_answer(dns_resp);
        if(dns_resp->ipv4 != 0){
            break;
        }
    }while(lpos < data_sz);
    dns_resp->id = DNS_HEADER.ID;
    // remove the dot that prefixes the domain, e.g .example.com becomes example.com
    dns_resp->host = &hostname[1];
    return 1;
}
