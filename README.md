### CPROXY

A mini http (socks coming later) proxy written `c`, This was written to be deployed on a Linux Container (podman pod or docker container). 

It uses a combination of LT(Level triggered) and ET(Edge triggered) for epoll events, Would get fully ET(Edge triggered) approach to work later.

## Building

```bash
# clone repo
git clone https://github.com/SkyNotion/cproxy.git
cd cproxy

# to compile
gcc cproxy.c -o cproxy

# to run
./cproxy -p 9441
```

## NOTE 

It would be optimized as it gets updated

Rotating proxies not ready yet