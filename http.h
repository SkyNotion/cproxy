#ifndef __CPROXY_HTTP_H
#define __CPROXY_HTTP_H

#include <ctype.h>
#include "common.h"
#include "request.h"

#define HTTP_BUFFER_SIZE 4096

#define DELIMETER_SPACE '\x20'
#define DELIMETER_CR '\x0d'
#define DELIMETER_LF '\x0a'
#define DELIMETER_COLON '\x3a'
#define DELIMETER_FORWARDSLASH '\x2f'
#define DELIMETER_DOT '\x2e'

#define HTTP_REQUEST_CONNECT "CONNECT"
#define HTTP_HEADER_HOST "host"

int parse_http_request(int fd, cproxy_request_t* req);

#endif