#ifndef API_H
#define API_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define ADMIN_API_PORT 5555
#define LOOPBACK_IPV4 "127.0.0.1"
#define LOOPBACK_IPV6 "::1"
#define USER_DB_PATH "users.csv"

struct admin_req_header {
    uint32_t id;
    uint8_t  cmd;
    uint16_t len;
} __attribute__((packed));

struct admin_resp_header {
    uint32_t id;
    uint8_t  status;
    uint16_t len;
} __attribute__((packed));

enum admin_cmd {
    /**
     * @brief get metrics methods
     */
    ADMIN_GET_CONCURRENT_CONN   = 0x01,
    ADMIN_GET_HIST_CONN         = 0x02,
    ADMIN_GET_BYTES_TRANSFERRED = 0x03,
    /**
     * @brief admin user management methods
     */
    ADMIN_SET_USER_ROLE         = 0x10,
    ADMIN_ADD_USER              = 0x11,
    ADMIN_DELETE_USER           = 0x12,
    /**
     * @brief get user connections
     */
    ADMIN_GET_USER_CONNECTIONS  = 0x20,

    ADMIN_QUIT                  = 0xFF,
};

void admin_send_request(int sockfd,uint32_t id,uint8_t cmd,const char *payload);

#endif