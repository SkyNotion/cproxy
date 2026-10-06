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

#ifndef __CPROXY_CONN_H
#define __CPROXY_CONN_H

#include "request.h"

#define CONN_CLIENT 0x1
#define CONN_TARGET 0x2

#define CONN_CLOSED (0x1 << 4)
#define CONN_PENDING (0x1 << 5)
#define CONN_ACTIVE (0x1 << 6)

#define CONN_EVENT_EPOLLIN (0x1 << 8)
#define CONN_EVENT_EPOLLOUT (0x1 << 9)

struct target_conn_data_t;
struct conn_data_t;

typedef struct target_conn_data_t {
    uint32_t flags;
    int fd;
    struct conn_data_t* client;
} target_conn_data_t;

typedef struct conn_data_t {
    uint32_t flags;
    uint16_t index;
    int fd;
    union {
        cproxy_request_t req;
    } data;
    target_conn_data_t target;
    struct conn_data_t* next;
} conn_data_t;

#endif