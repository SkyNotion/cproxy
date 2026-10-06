/*
 * MIT License
 *
 * Copyright (c) 2026 Mesh Anthony
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __CPROXY_DNS_RESOLVE_H
#define __CPROXY_DNS_RESOLVE_H

#include "common.h"

#define DNS_ADDRESS "8.8.8.8" // Google's public dns
//#define DNS_ADDRESS "1.1.1.1" // Cloudflare's public dns

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