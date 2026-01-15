#include "http.h"

static const char HTTP_1_1_SUFFIX[] = " HTTP/1.1\r\n"; 
static const char HTTP_SUFFIX[] = "\r\n\r\n"; 
static const char HTTP_RESPONSE_BAD_REQUEST[] = "HTTP/1.1 400 Bad Request\r\n\r\n";

static char buffer[HTTP_BUFFER_SIZE], header_buffer[128], port_buffer[6];

static int recv_sz, inc, crlf_count, 
           start_pos, parsed, byte_count, 
           header_buffer_len, val;

static uint8_t is_http_host, dot_count, not_digit, spos;

inline void send_http_bad_request(int fd){
    send(fd, HTTP_RESPONSE_BAD_REQUEST,
        CONSTSTRLEN(HTTP_RESPONSE_BAD_REQUEST), MSG_NOSIGNAL);
}

inline int parse_http_request_path(cproxy_request_t* req){
    parsed = start_pos = 0;
    if(req->flags & CPROXY_HTTP_TUNNEL){
        req->buffer[++req->buffer_len] = DELIMETER_FORWARDSLASH;
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

                if(req->flags & CPROXY_HTTP_TUNNEL){
                    return 0;
                }
                memcpy(&req->buffer[++req->buffer_len], &buffer[start_pos], byte_count);
                req->buffer_len += byte_count;
                memcpy(&req->buffer[req->buffer_len], HTTP_1_1_SUFFIX, CONSTSTRLEN(HTTP_1_1_SUFFIX));
                req->buffer_len += CONSTSTRLEN(HTTP_1_1_SUFFIX);
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
    req->buffer_len = 0;
    parsed = start_pos = 0;
    do{
        switch(buffer[inc]){
            case DELIMETER_SPACE:
                req->buffer_len = byte_count = inc++ - start_pos;
                if(byte_count > 7){
                    return -1;
                }
                if(strncmp(&buffer[start_pos], HTTP_REQUEST_CONNECT, byte_count) != 0){
                    memcpy(req->buffer, &buffer[start_pos], byte_count);
                    req->buffer[byte_count] = DELIMETER_SPACE;
                    req->buffer_len = byte_count;
                }else{
                    req->flags |= CPROXY_HTTP_TUNNEL;
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
    header_buffer_len = 0;
    req->host_len = 0;
    is_http_host = dot_count = not_digit = 0;
    start_pos = inc;
    do{
        switch(buffer[inc]){
            case DELIMETER_LF:
                if(buffer[inc - 1] != DELIMETER_CR){
                    return -1;
                }
                if(strncmp(header_buffer, HTTP_HEADER_HOST, header_buffer_len) == 0){
                    byte_count = inc - start_pos - 1;
                    if(byte_count > 127){
                        return -1;
                    }

                    if(req->port != 0){
                        break;
                    }

                    if(req->host_len > 0){
                        if(get_addr_type(req) < 0){
                            return -1;
                        }
                        memcpy(port_buffer, &buffer[start_pos], byte_count);
                        port_buffer[byte_count] = '\0';
                        req->port = htons(atoi(port_buffer));
                    }else{
                        memcpy(req->host, &buffer[start_pos], byte_count);
                        req->host_len = byte_count;
                        if(get_addr_type(req) < 0){
                            return -1;
                        }
                        req->port = htons(80);
                    }
                    if(!(req->flags & CPROXY_HTTP_TUNNEL)){
                        memcpy(&req->buffer[req->buffer_len], header_buffer, header_buffer_len);
                        req->buffer_len += header_buffer_len;
                        req->buffer[req->buffer_len++] = DELIMETER_COLON;
                        req->buffer[req->buffer_len++] = DELIMETER_SPACE;
                        memcpy(&req->buffer[req->buffer_len], req->host, req->host_len);
                        req->buffer_len += req->host_len;
                        memcpy(&req->buffer[req->buffer_len], HTTP_SUFFIX, CONSTSTRLEN(HTTP_SUFFIX));
                        req->buffer_len += CONSTSTRLEN(HTTP_SUFFIX);
                    }
                    header_buffer_len = 0;
                }
                start_pos = ++inc;
                continue;
            case DELIMETER_COLON:
                byte_count = inc++ - start_pos;
                if(byte_count > 127){
                    return -1;
                }
                if(header_buffer_len > 0 && 
                    strncmp(header_buffer, HTTP_HEADER_HOST, header_buffer_len) == 0){
                    is_http_host = 1;
                    memcpy(req->host, &buffer[start_pos], byte_count);
                    req->host_len = byte_count;
                    start_pos = inc;
                    continue;
                }
                memcpy(header_buffer, &buffer[start_pos], byte_count);
                header_buffer_len = byte_count;
                start_pos = ++inc;
                is_http_host = 0;
                if(strncmp(header_buffer, HTTP_HEADER_HOST, header_buffer_len) == 0){
                    is_http_host = 1;
                }
                continue;
            case DELIMETER_DOT:
                if(is_http_host == 1){
                    dot_count++;
                }
                break;
            case DELIMETER_CR:
                break;
            default:
                if(is_http_host == 1 && isdigit((int)buffer[inc]) == 0){
                    not_digit++;
                }
                buffer[inc] = (char)tolower((int)buffer[inc]);
                break;
        }
        inc++;
    }while(inc < recv_sz);
    return 0;
}

inline int get_addr_type(cproxy_request_t* req){
    if(not_digit == 0 && dot_count == 3){
        req->flags |= CPROXY_ADDR_IPV4;
        val = 0;
        dot_count = spos = 0;
        req->ipv4_addr = 0;
        req->host[req->host_len] = '\0';
        do{
            if(req->host[val] == DELIMETER_DOT){
                req->host[val] = '\0';
                req->ipv4_addr |= (atoi(&req->host[spos]) << (8 * dot_count++));
                req->host[val] = '.';
                spos = val + 1; 
            }
            val++;
        }while(dot_count < 3);
        req->ipv4_addr |= (atoi(&req->host[spos]) << 24);
    }else if(not_digit > 0 && dot_count > 0){
        req->flags |= CPROXY_ADDR_DOMAIN;
    }else{
        return -1;
    }

    return 0;
}

int parse_http_request(int fd, cproxy_request_t* req){
    errno = 0;
    crlf_count = 0;
    do{
        inc = 0;
        recv_sz = recv(fd, buffer, HTTP_BUFFER_SIZE, 0);
        if(errno == EAGAIN){
            break;
        }
        while(inc < recv_sz){
            switch(crlf_count){
                case 0:
                    if(parse_http_request_string(req) < 0){
                        send_http_bad_request(fd);
                        return -1;
                    }
                    break;
                case 1:
                    if(parse_http_request_headers(req) < 0){
                        send_http_bad_request(fd);
                        return -1;
                    }
                    break;
                default:
                    return -1;
            }
        }
    }while(errno != EAGAIN && recv_sz > 0);

    if(recv_sz == 0){
        return -1;
    }

    req->flags |= CPROXY_REQ_HTTP;
    return 0;
}