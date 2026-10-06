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

#ifndef __CPROXY_COMMON_H
#define __CPROXY_COMMON_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define cproxy_output stdout
#define cproxy_error stderr

#define CONN_BACKLOG 1024
#define MAX_CONN (2 * 1024)

#define CONSTSTRLEN(s) ((sizeof(s)/sizeof(char)) - 1)
#define MIN(a, b) (a < b ? a : b)

#define DELIMETER_SPACE '\x20'
#define DELIMETER_CR '\x0d'
#define DELIMETER_LF '\x0a'
#define DELIMETER_COLON '\x3a'
#define DELIMETER_FORWARDSLASH '\x2f'
#define DELIMETER_DOT '\x2e'
#define DELIMETER_OPEN_SQUARE_BRACKET '\x5b'
#define DELIMETER_CLOSE_SQUARE_BRACKET '\x5d'

#ifdef _DEBUG
    #define DEBUG_LOG(...) fprintf(cproxy_output, __VA_ARGS__)
    #define ERROR_LOG(...) fprintf(cproxy_error, __VA_ARGS__)
    #define ERRNO_LOG(x) perror(x)
#else
    #define DEBUG_LOG(...) ((void)0)
    #define ERROR_LOG(...) ((void)0)
    #define ERRNO_LOG(x) ((void)0)
#endif

#define CPROXY_INFO_LOG(...) fprintf(cproxy_output, __VA_ARGS__)
#define CPROXY_ERROR_LOG(...) fprintf(cproxy_error, __VA_ARGS__)

#endif