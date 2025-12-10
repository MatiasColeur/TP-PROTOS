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

static void admin_prepare_error(struct admin_connection *conn,
                                uint8_t status,
                                const char *msg) {
    size_t msg_len = msg != NULL ? strlen(msg) : 0;

    conn->resp_h.id     = conn->req_h.id;  // mismo id (ya en network order)
    conn->resp_h.status = status;
    conn->resp_h.len    = htons((uint16_t)msg_len);

    conn->resp_body_len = (uint16_t)msg_len;
    conn->resp_body = NULL;

    if (msg_len > 0) {
        conn->resp_body = malloc(msg_len);
        if (conn->resp_body == NULL) {
            // Si no hay memoria, mandamos sin payload
            conn->resp_h.len    = htons(0);
            conn->resp_body_len = 0;
            return;
        }
        memcpy(conn->resp_body, msg, msg_len);
    }
}

static void admin_prepare_ok_uint64(struct admin_connection *conn,
                                    uint64_t value) {
    // Payload textual: "<valor>\n"
    char buf[64];
    int len = snprintf(buf, sizeof(buf), "%llu\n",
                       (unsigned long long)value);
    if (len < 0) {
        admin_prepare_error(conn, 1, "internal_error");
        return;
    }

    conn->resp_h.id     = conn->req_h.id;
    conn->resp_h.status = 0;
    conn->resp_h.len    = htons((uint16_t)len);

    conn->resp_body_len = (uint16_t)len;
    conn->resp_body     = malloc(conn->resp_body_len);
    if (conn->resp_body == NULL) {
        admin_prepare_error(conn, 1, "no_memory");
        return;
    }
    memcpy(conn->resp_body, buf, conn->resp_body_len);
}

static void admin_prepare_ok_msg(struct admin_connection *conn,
                                 const char *msg) {
    size_t msg_len = msg != NULL ? strlen(msg) : 0;

    conn->resp_h.id     = conn->req_h.id;
    conn->resp_h.status = 0;
    conn->resp_h.len    = htons((uint16_t)msg_len);

    conn->resp_body_len = (uint16_t)msg_len;
    conn->resp_body     = NULL;

    if (msg_len > 0) {
        conn->resp_body = malloc(msg_len);
        if (conn->resp_body == NULL) {
            admin_prepare_error(conn, 1, "no_memory");
            return;
        }
        memcpy(conn->resp_body, msg, msg_len);
    }
}

// ----------- Passive socket -----------

static int create_server_socket(uint16_t port) {
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // Sólo loopback (::1)
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port   = htons(port);
    addr.sin6_addr   = in6addr_loopback;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        exit(EXIT_FAILURE);
    }

    if (listen(fd, BACKLOG) < 0) {
        perror("listen");
        close(fd);
        exit(EXIT_FAILURE);
    }

    printf("[INF] Admin API listening on [::1]:%u\n", port);
    return fd;
}

// ----------- API Server -----------

int main(int argc, char const *argv[])  {
    
    return 0;
}
