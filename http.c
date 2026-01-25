#include "http.h"

static const char HTTP_1_1_SUFFIX[] = " HTTP/1.1\r\n"; 

static const char HTTP_RESPONSE_BAD_REQUEST[] = "HTTP/1.1 400 Bad Request\r\n\r\n";

static char buffer[REQUEST_BUFFER_SIZE + 1], 
            header_buffer[HTTP_HEADER_NAME_BUFFER_SIZE],
            port_buffer[HTTP_PORT_BUFFER_SIZE],
            ipv6_block[4];

static int recv_sz, inc, start_pos, parsed, byte_count, 
           header_buffer_len, pos, temp_inc,
           num_after_blocks, dot_count, zsection,
           not_digit, colon_count;
 
static uint8_t section, header, total_blocks;

static uint8_t ascii_to_hex_lut[] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8,9,0,0,0,
    0,0,0,0,10,11,12,13,14,15,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,10,11,12,13,
    14,15,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

static inline void send_http_bad_request(int fd){
    DEBUG_LOG("%s\n", __FUNCTION__);
    send(fd, HTTP_RESPONSE_BAD_REQUEST,
        CONSTSTRLEN(HTTP_RESPONSE_BAD_REQUEST), MSG_NOSIGNAL);
}

static inline int parse_http_request_path(cproxy_request_t* req){
    DEBUG_LOG("%s\n", __FUNCTION__);
    parsed = start_pos = 0;
    if(req->flags & CPROXY_HTTP_TUNNEL){
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

static inline int parse_http_request_string(cproxy_request_t* req){
    DEBUG_LOG("%s\n", __FUNCTION__);
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
                    req->buffer = (char*)malloc(REQUEST_BUFFER_SIZE);
                    req->flags |= CPROXY_ALLOCATED_BUFFER;
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
                section = HTTP_SECTION_HEADERS;
                return 0;
        }
        inc++;
    }while(inc < recv_sz);
    return -1;
}

static inline int is_header(const char* header_name){
    DEBUG_LOG("%s\n", __FUNCTION__);
    return strncmp(header_buffer, header_name, header_buffer_len);
}

static inline void parse_ipv6_hex(cproxy_request_t* req){
    DEBUG_LOG("%s\n", __FUNCTION__);
    req->ipv6_addr[15 - byte_count] = (ascii_to_hex_lut[(uint8_t)ipv6_block[0]]*16)+ascii_to_hex_lut[(uint8_t)ipv6_block[1]];
    req->ipv6_addr[15 - byte_count - 1] = (ascii_to_hex_lut[(uint8_t)ipv6_block[2]]*16)+ascii_to_hex_lut[(uint8_t)ipv6_block[3]];
}

static inline void parse_zero_section(){
    DEBUG_LOG("%s\n", __FUNCTION__);
    temp_inc = inc + 2;
    num_after_blocks = 0;
    if(buffer[temp_inc] == DELIMETER_CLOSE_SQUARE_BRACKET){
        goto _set_byte_count;
    }
    do{
        if(buffer[temp_inc++] == DELIMETER_COLON){
            num_after_blocks++;
        }
    }while(buffer[temp_inc] != DELIMETER_CLOSE_SQUARE_BRACKET && (temp_inc - inc) < 39);
_set_byte_count:
    if(buffer[temp_inc] == DELIMETER_CLOSE_SQUARE_BRACKET &&
       buffer[temp_inc - 1] != DELIMETER_COLON){
        num_after_blocks++;
    }
    zsection = 8 - (total_blocks + num_after_blocks);
    total_blocks += zsection;
    byte_count += (zsection * 2);
    inc++;
}

static inline int get_addr_type(cproxy_request_t* req){
    DEBUG_LOG("%s\n", __FUNCTION__);
    if(not_digit == 0 && dot_count == 3){
        req->flags |= CPROXY_ADDR_IPV4;
        req->ipv4_addr = 0;
        req->host[req->host_len] = '\0';
        parsed = pos = 0;
        dot_count = 0;
        do{
            if(req->host[parsed] == DELIMETER_DOT){
                req->host[parsed] = '\0';
                req->ipv4_addr |= (atoi(&req->host[pos]) << (8 * dot_count++));
                req->host[parsed] = '.';
                pos = parsed + 1; 
            }
            parsed++;
        }while(dot_count < 3);
        req->ipv4_addr |= (atoi(&req->host[pos]) << 24);
        dot_count = parsed - (inc - pos);
    }else if(not_digit > 0 && dot_count > 0){
        req->flags |= CPROXY_ADDR_DOMAIN;
    }else if(req->flags & CPROXY_ADDR_IPV6){
        if(req->host_len > 0){
            return 0;
        }
        memset(req->ipv6_addr, 0, sizeof(req->ipv6_addr));
        start_pos = inc++;
        pos = inc;
        parsed = byte_count = 0;
        zsection = dot_count = total_blocks = 0;
        do{
            if(buffer[inc] == DELIMETER_COLON){
                if(dot_count == 0 &&
                   zsection == 0 &&
                   buffer[inc - 1] == DELIMETER_OPEN_SQUARE_BRACKET &&
                   buffer[inc + 1] == DELIMETER_COLON){
                   parse_zero_section();
                   pos = ++inc;
                   continue;
                }
                total_blocks++;
                dot_count = inc - pos;
                memset(ipv6_block, 0x30, sizeof(ipv6_block));
                memcpy(&ipv6_block[4 - dot_count], &buffer[pos], dot_count);
                parse_ipv6_hex(req);
                byte_count += 2;
                parsed += 5;
                if(zsection == 0 &&
                   buffer[inc + 1] == DELIMETER_COLON){
                    parse_zero_section();
                }
                pos = inc + 1;
            }
            inc++;
        }while(parsed < 39 && buffer[inc] != DELIMETER_CLOSE_SQUARE_BRACKET);
        if(buffer[inc] == DELIMETER_CLOSE_SQUARE_BRACKET &&
           buffer[inc - 1] != DELIMETER_COLON){
            total_blocks++;
            dot_count = inc - pos;
            memset(ipv6_block, 0x30, sizeof(ipv6_block));
            memcpy(&ipv6_block[4 - dot_count], &buffer[pos], dot_count);
            parse_ipv6_hex(req);
        }

        if(total_blocks != 8){
            return -1;
        }
    }else{
        return -1;
    }
    return 0;
}

static inline int parse_http_request_headers(cproxy_request_t* req){
    DEBUG_LOG("%s\n", __FUNCTION__);
    req->port = 0;
    req->host_len = 0;
    dot_count = not_digit = colon_count = header_buffer_len = 0;
    start_pos = inc;
    header = 0;
    do{
        switch(buffer[inc]){
            case DELIMETER_LF:
                if(buffer[inc - 1] != DELIMETER_CR){
                    return -1;
                }

                if(buffer[inc - 2] == DELIMETER_LF){
                    section = HTTP_SECTION_BODY;
                    break;
                }

                parsed = 1;
                byte_count = inc - start_pos - 1;
                switch(header){
                    case HTTP_HEADER_HOST:
                        if(byte_count > 256){
                            return -1;
                        }
    
                        if(req->port != 0){
                            return -1;
                        }

                        if(colon_count > 1){
                            colon_count = inc - colon_count - 1;
                            if(colon_count > (HTTP_PORT_BUFFER_SIZE - 1)){
                                return -1;
                            }
                            memcpy(port_buffer,
                                   &buffer[start_pos + byte_count - colon_count], colon_count);
                            port_buffer[colon_count++] = '\0';
                            req->port = htons(atoi(port_buffer));
                        }else{
                            req->port = htons(80);
                            colon_count = 0;
                        }

                        req->host_len = byte_count - colon_count;
                        memcpy(req->host, &buffer[start_pos], req->host_len);

                        if(get_addr_type(req) < 0){
                            return -1;
                        }
                        parsed = 1;
                        break;
                    case HTTP_HEADER_PROXY_AUTHORIZATION:
                        parsed = 0;
                        break;
                    case HTTP_HEADER_PROXY_CONNECTION:
                        parsed = 0;
                        break;
                }

                if(parsed == 1 && !(req->flags & CPROXY_HTTP_TUNNEL)){
                    memcpy(&req->buffer[req->buffer_len], header_buffer, header_buffer_len);
                    req->buffer_len += header_buffer_len;
                    req->buffer[req->buffer_len++] = DELIMETER_COLON;
                    req->buffer[req->buffer_len++] = DELIMETER_SPACE;
                    memcpy(&req->buffer[req->buffer_len], &buffer[start_pos], byte_count);
                    req->buffer_len += byte_count;
                    req->buffer[req->buffer_len++] = DELIMETER_CR;
                    req->buffer[req->buffer_len++] = DELIMETER_LF;
                }

                colon_count = 0;
                header_buffer_len = 0;
                start_pos = ++inc;
                continue;
            case DELIMETER_COLON:
                if(colon_count > 0){
                    colon_count = ++inc;
                    continue;
                }

                byte_count = inc++ - start_pos;
                if(byte_count > HTTP_HEADER_NAME_BUFFER_SIZE){
                    return -1;
                }
                colon_count++;
                memcpy(header_buffer, &buffer[start_pos], byte_count);
                header_buffer_len = byte_count;
                start_pos = ++inc;
                if(is_header(HTTP_HEADER_STR_HOST) == 0){
                    header = HTTP_HEADER_HOST;
                }else if(is_header(HTTP_HEADER_STR_PROXY_AUTHORIZATION) == 0){
                    header = HTTP_HEADER_PROXY_AUTHORIZATION;
                }else if(is_header(HTTP_HEADER_STR_PROXY_CONNECTION) == 0){
                    header = HTTP_HEADER_PROXY_CONNECTION;
                }else{
                    header = 0;
                }
                continue;
            case DELIMETER_DOT:
                if(header == HTTP_HEADER_HOST){
                    dot_count++;
                    break;
                }
                break;
            case DELIMETER_CR:
                break;
            case DELIMETER_OPEN_SQUARE_BRACKET:
                if(header == HTTP_HEADER_HOST){
                    req->flags |= CPROXY_ADDR_IPV6;
                    if(get_addr_type(req) < 0){
                        return -1;
                    }  
                }
                break;
            default:
                if(header == HTTP_HEADER_HOST && 
                   isdigit((int)buffer[inc]) == 0){
                    not_digit++;
                }

                if(colon_count == 0){
                    buffer[inc] = (char)tolower((int)buffer[inc]);
                }
                break;
        }
        inc++;
    }while(inc < recv_sz && section == HTTP_SECTION_HEADERS);
    if(section == HTTP_SECTION_HEADERS && req->host_len == 0){
        return -1;
    }

    if(!(req->flags & CPROXY_HTTP_TUNNEL)){
        req->buffer[req->buffer_len++] = DELIMETER_CR;
        req->buffer[req->buffer_len++] = DELIMETER_LF;
    }

    if(inc < recv_sz){
        memcpy(&req->buffer[req->buffer_len], &buffer[inc], recv_sz - inc);
        req->buffer_len += (recv_sz - inc);
    }

    section = HTTP_SECTION_DONE;
    return 0;
}

int parse_http_request(int fd, cproxy_request_t* req){
    DEBUG_LOG("%s\n", __FUNCTION__);
    errno = 0;
    section = HTTP_SECTION_REQUEST_STRING;
    inc = 0;

    recv_sz = recv(fd, buffer, REQUEST_BUFFER_SIZE - 4, 0);
    if(errno == EAGAIN){
        return -1;
    }

    while(inc < recv_sz && section != HTTP_SECTION_DONE){
        switch(section){
            case HTTP_SECTION_REQUEST_STRING:
                if(parse_http_request_string(req) < 0){
                    send_http_bad_request(fd);
                    return -1;
                }
                DEBUG_LOG("Parsed http request string\n");
                break;
            case HTTP_SECTION_HEADERS:
                if(parse_http_request_headers(req) < 0){
                    send_http_bad_request(fd);
                    return -1;
                }
                DEBUG_LOG("Parsed http request headers\n");
                break;
            case HTTP_SECTION_BODY:
                DEBUG_LOG("Parsed http request body\n");
                break;
            default:
                return -1;
        }
    }

    if(recv_sz == 0){
        return -1;
    }

    req->flags |= CPROXY_REQ_HTTP;
    return 0;
}