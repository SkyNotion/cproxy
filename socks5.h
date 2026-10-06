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

#ifndef __CPROXY_SOCKS5_H
#define __CPROXY_SOCKS5_H

#include "common.h"
#include "request.h"

#define SOCKS5_VERSION_NUMBER 0x05

#define SOCKS5_BUFFER_SIZE 280

#define SOCKS5_IPV4_ADDRESS 0x01
#define SOCKS5_IPV6_ADDRESS 0x04
#define SOCKS5_DOMAIN_NAME 0x03
#define SOCKS5_UDP_CONN 0x03

int socks5_handshake(int fd, cproxy_request_t* req);

#endif