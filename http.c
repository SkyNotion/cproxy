#include "http.h"

static char buffer[BUFFER_SIZE], http_header_buffer[128];
static int recv_sz, inc, crlf_count, start_pos, rpos, parsed, byte_count;

static const char* HTTP_1_1_SUFFIX = " HTTP/1.1\r\n"; 
static const char* HTTP_SUFFIX = "\r\n\r\n"; 
static const char* HTTP_RESPONSE_BAD_REQUEST = "HTTP/1.1 400 Bad Request\r\n\r\n";
static const char* HTTP_PORT_80 = "80";

inline void send_http_bad_request(int fd){
    DEBUG_LOG("Entering send_http_bad_request()\n");
    send(fd, HTTP_RESPONSE_BAD_REQUEST, strlen(HTTP_RESPONSE_BAD_REQUEST), MSG_NOSIGNAL);
}

inline int parse_http_request_path(cproxy_request_t* req){
    DEBUG_LOG("Entering parse_http_request_path()\n");
    parsed = start_pos = 0;
    if(req->flags & CPROXY_HTTP_CONNECT){
        req->http.request[++rpos] = DELIMETER_FORWARDSLASH;
        do {
            inc++;
            if(buffer[inc] == DELIMETER_SPACE){
                parsed++;
                return 0;
            }
        }while(inc < recv_sz);
        return -1;
    }
    do{
        switch(buffer[inc]){
            case DELIMETER_FORWARDSLASH:
                if(parsed == 2){
                    start_pos = inc;
                }
                parsed++;
                break;
            case DELIMETER_SPACE:
                byte_count = inc - start_pos;
                if(byte_count > 255){
                    return -1;
                }

                if(req->flags & CPROXY_HTTP_CONNECT){
                    return 0;
                }

                memcpy(&req->http.request[++rpos], &buffer[start_pos], byte_count);
                rpos += byte_count;
                memcpy(&req->http.request[rpos], HTTP_1_1_SUFFIX, strlen(HTTP_1_1_SUFFIX));
                rpos += strlen(HTTP_1_1_SUFFIX);

                return 0;
            case DELIMETER_CR:
                return -1;
            case DELIMETER_LF:
                return -1;
        }
        inc++;
    }while(inc < recv_sz && buffer[inc - 1] != DELIMETER_SPACE && inc < 300);
    return -1;
}

inline int parse_http_request_string(cproxy_request_t* req){
    DEBUG_LOG("Entering parse_http_request_string()\n");
    memset(req->http.request, 0, sizeof(req->http.request)/sizeof(char));
    rpos = parsed = start_pos = 0;
    req->flags = 0;
    do{
        switch(buffer[inc]){
            case DELIMETER_SPACE:
                byte_count = rpos = inc++ - start_pos;
                if(byte_count > 7){
                    return -1;
                }
                if(strncmp(&buffer[start_pos], HTTP_REQUEST_CONNECT, byte_count) != 0){
                    memcpy(req->http.request, &buffer[start_pos], byte_count);
                    req->http.request[byte_count] = DELIMETER_SPACE;
                }else{
                    req->flags |= CPROXY_HTTP_CONNECT;
                }
                if(parse_http_request_path(req) < 0){
                    return -1;
                }
                break;
            case DELIMETER_LF:
                if(buffer[inc++ - 1] != DELIMETER_CR || !parsed){
                    return -1;
                }
                crlf_count++;
                return 0;
        }
        inc++;
    }while(inc < recv_sz);
    return -1;
}

inline int parse_http_request_headers(cproxy_request_t* req){
    DEBUG_LOG("Entering parse_http_request_headers()\n");
    memset(http_header_buffer, 0, sizeof(http_header_buffer)/sizeof(char));
    memset(req->host, 0, sizeof(req->host)/sizeof(char));
    start_pos = inc;
    do{
        switch(buffer[inc]){
            case DELIMETER_LF:
                if(buffer[inc - 1] != DELIMETER_CR){
                    return -1;
                }
                if(strcmp(http_header_buffer, HTTP_HEADER_HOST) == 0){
                    byte_count = inc - start_pos - 1;
                    if(byte_count > 127){
                        return -1;
                    }
                    buffer[inc - 1] = '\0';
                    if(strlen(req->host) > 0){
                        memcpy(req->port, &buffer[start_pos], byte_count);
                    }else{
                        memcpy(req->host, &buffer[start_pos], byte_count);
                        req->host[byte_count] = '\0';
                        memcpy(req->port, HTTP_PORT_80, strlen(HTTP_PORT_80));
                        req->port[strlen(HTTP_PORT_80)] = '\0';
                    }

                    if(!(req->flags & CPROXY_HTTP_CONNECT)){
                        memcpy(&req->http.request[rpos], http_header_buffer, strlen(http_header_buffer));
                        rpos += strlen(http_header_buffer);
                        req->http.request[rpos++] = DELIMETER_COLON;
                        req->http.request[rpos++] = DELIMETER_SPACE;
                        memcpy(&req->http.request[rpos], req->host, strlen(req->host));
                        rpos += strlen(req->host);
                        memcpy(&req->http.request[rpos], HTTP_SUFFIX, strlen(HTTP_SUFFIX));
                        rpos += strlen(HTTP_SUFFIX);
                        req->http.request[rpos] = '\0';
                    }

                    memset(http_header_buffer, 0, sizeof(http_header_buffer)/sizeof(char));
                }
                start_pos = ++inc;
                continue;
            case DELIMETER_COLON:
                byte_count = inc++ - start_pos;
                if(byte_count > 127){
                    return -1;
                }
                if(strlen(http_header_buffer) > 0 && strcmp(http_header_buffer, HTTP_HEADER_HOST) == 0){
                    memcpy(req->host, &buffer[start_pos], byte_count);
                    req->host[byte_count] = '\0';
                    start_pos = inc;
                    continue;
                }
                memcpy(http_header_buffer, &buffer[start_pos], byte_count);
                http_header_buffer[byte_count] = '\0';
                start_pos = ++inc;
                continue;
            default:
                buffer[inc] = (char)tolower((int)buffer[inc]);
                break;
        }
        inc++;
    }while(inc < recv_sz);
    return 0;
}

int parse_http_request(int fd, cproxy_request_t* req){
    errno = 0;
    DEBUG_LOG("Entering parse_http_request()\n");
    crlf_count = 0;
    do {
        inc = 0;
        recv_sz = recv(fd, buffer, BUFFER_SIZE, 0);
        if(errno == EAGAIN){
            break;
        }
        while(inc < recv_sz){
            switch(crlf_count){
                case 0:
                    if(parse_http_request_string(req) < 0){
                        ERROR_LOG("%s: Failed parse_http_request_string()\n", __FUNCTION__);
                        send_http_bad_request(fd);
                        return -1;
                    }
                    break;
                case 1:
                    if(parse_http_request_headers(req) < 0){
                        ERROR_LOG("%s: Failed parse_http_request_headers()\n", __FUNCTION__);
                        send_http_bad_request(fd);
                        return -1;
                    }
                    break;
                default:
                    ERROR_LOG("%s: Unexpected behaviour - crlf_count:%d\n", __FUNCTION__, crlf_count);
                    return -1;
            }
        }
    }while(errno != EAGAIN && recv_sz > 0);

    if(recv_sz == 0){
        return -1;
    }

    return 0;
}