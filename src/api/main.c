#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ADMIN_API_PORT 5555
#define BACKLOG        5

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
    ADMIN_SET_USER_PASSWORD     = 0x10,
    ADMIN_ADD_USER              = 0x11,
    ADMIN_DELETE_USER           = 0x12,

    ADMIN_QUIT                  = 0xFF,
};

struct admin_connection {
    int fd;                     

    struct admin_req_header  req_h;
    struct admin_resp_header resp_h;

/**
 * @brief request payload
 */
    uint8_t *req_body;
/**
 * @brief response payload
 */
    uint8_t *resp_body;

    uint16_t req_body_received;
    uint16_t resp_body_len;

/**
 * @brief parsed command 
 */
    enum admin_cmd cmd;
};


int main(int argc, char const *argv[])  {
    
    return 0;
}
