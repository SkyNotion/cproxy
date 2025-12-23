SRC = cproxy.c http.c mempool.c

CFLAGS = -Wall -Wextra

EXEC = cproxy

cproxy: ${SRC}
	${CC} -O2 ${CFLAGS} -o ${EXEC} ${SRC}

debug:
	${CC} -ggdb -D_DEBUG ${CFLAGS} -o ${EXEC} ${SRC}

clean:
	rm -f cproxy