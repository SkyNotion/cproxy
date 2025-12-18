#ifndef __CPROXY_HTTP_H
#define __CPROXY_HTTP_H

#include <ctype.h>
#include "common.h"
#include "request.h"

#define DELIMETER_SPACE '\x20'
#define DELIMETER_CR '\x0d'
#define DELIMETER_LF '\x0a'
#define DELIMETER_COLON '\x3a'
#define DELIMETER_FORWARDSLASH '\x2f'

#define BUFFER_SIZE 4096

#define HTTP_REQUEST_CONNECT "CONNECT"

#define HTTP_HEADER_HOST "host"
#define HTTP_HEADER_PROXY_CONNECTION "proxy-connection"

#define HTTP_HEADER_VALUE_KEEPALIVE "keep-alive"

#define HTTP_REQ_KEEPALIVE_CONN 0x1

void send_http_bad_request(int fd);
int parse_http_request_path(cproxy_request_t* req);
int parse_http_request_string(cproxy_request_t* req);
int parse_http_request_headers(cproxy_request_t* req);
int parse_http_request(int fd, cproxy_request_t* req);

#endif