SRC = cproxy.c http.c mempool.c socks5.c dns_resolve.c

CFLAGS = -Wall -Wextra

EXEC = cproxy

cproxy: ${SRC}
	${CC} -O2 ${CFLAGS} -o ${EXEC} ${SRC}

debug:
	make clean
	${CC} -ggdb -D_DEBUG ${CFLAGS} -o ${EXEC} ${SRC}

clean:
	rm -f cproxy