#ifndef __CPROXY_H
#define __CPROXY_H

#include <signal.h>

#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>

#include "common.h"
#include "conn.h"
#include "http.h"
#include "socks5.h"
#include "mempool.h"
#include "request.h"
#include "dns_resolve.h"

#define BUFFER_SIZE (64 * 1024)

#define MAX_EVENTS (MAX_CONN + 2) // 1 for listening socket, 1 for dns resolver

#endif