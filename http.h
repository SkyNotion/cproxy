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