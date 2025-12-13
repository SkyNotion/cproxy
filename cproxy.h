#ifndef __CPROXY_H
#define __CPROXY_H

#include <signal.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "common.h"
#include "http.h"
#include "mempool.h"

#define MAX_EVENTS 8

#endif