#ifndef __CPROXY_H
#define __CPROXY_H

#include <signal.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>

#include "common.h"
#include "http.h"
#include "socks5.h"
#include "mempool.h"
#include "request.h"

#define MAX_EVENTS (MAX_CONN + 1)

#endif