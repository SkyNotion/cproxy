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