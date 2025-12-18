SRC = cproxy.c http.c mempool.c

cproxy: ${SRC}
	${CC} -O1 ${CFLAGS} ${SRC} -o cproxy

debug:
	${CC} -ggdb -D_DEBUG ${CFLAGS} ${SRC} -o cproxy

clean:
	rm -f cproxy