#ifndef __CPROXY_COMMON_H
#define __CPROXY_COMMON_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>

#define cproxy_output stdout
#define cproxy_error stderr

#define CONN_BACKLOG 1024
#define MAX_CONN 2048 /* Clients */

#endif