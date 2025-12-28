#ifndef __CPROXY_SOCKS5_H
#define __CPROXY_SOCKS5_H

#include "common.h"
#include "request.h"

#define BUFFER_SIZE 4096

#define SOCKS5_IPV4_ADDRESS 0x01
#define SOCKS5_IPV6_ADDRESS 0x04
#define SOCKS5_DOMAIN_NAME 0x03

#define SOCKS5_UDP_CONN 0x03

int socks5_handshake(int fd, uint8_t step, cproxy_request_t* req);

#endif