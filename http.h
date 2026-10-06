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

#ifndef __CPROXY_HTTP_H
#define __CPROXY_HTTP_H

#include <ctype.h>
#include "common.h"
#include "request.h"

#define HTTP_HEADER_NAME_BUFFER_SIZE 256
#define HTTP_PORT_BUFFER_SIZE 6

#define HTTP_SECTION_DONE 0
#define HTTP_SECTION_REQUEST_STRING 1
#define HTTP_SECTION_HEADERS 2
#define HTTP_SECTION_BODY 3

#define HTTP_REQUEST_CONNECT "CONNECT"

#define HTTP_HEADER_STR_HOST "host"
#define HTTP_HEADER_STR_PROXY_AUTHORIZATION "proxy-authorization"
#define HTTP_HEADER_STR_PROXY_CONNECTION "proxy-connection"

#define HTTP_HEADER_HOST 1
#define HTTP_HEADER_PROXY_AUTHORIZATION 2
#define HTTP_HEADER_PROXY_CONNECTION 3

#define ASCII_ZERO_HEX 0x30

int parse_http_request(int fd, cproxy_request_t* req);

#endif