### CPROXY

A mini http and socks5 proxy written `c`, This was written to be deployed on a Linux Container (podman pod or docker container). 

It uses a LT(Level triggered) approach for epoll events.

## BUILDING

```bash
# clone repo
git clone https://github.com/SkyNotion/cproxy.git
cd cproxy

# to compile
make

# to run
# ./cproxy -p PORT (default: 9441)
./cproxy -p 9441 
```

## ISSUES
* The `getaddrinfo` POSIX function used to resolve hostnames is a blocking function, It may block when try to resolve a hostname. Usually it doesn't but it's a problem.

## NOTE 

It would be optimized as it gets updated.