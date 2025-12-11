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

#include "../../include/shared.h"

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
    ADMIN_SET_USER_ROLE         = 0x10,
    ADMIN_ADD_USER              = 0x11,
    ADMIN_DELETE_USER           = 0x12,
    /**
     * @brief get user connections
     */
    ADMIN_GET_USER_CONNECTIONS  = 0x20,

    ADMIN_QUIT                  = 0xFF,
};

struct admin_connection {
    int fd; // socket del admin

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

    uint16_t req_body_len;
    uint16_t resp_body_len;

    /**
     * @brief parsed command
     */
    enum admin_cmd cmd;
};

// ----------- Request/Response Preparation -----------

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


// ----------- Helpers de manejo de requests -----------

static bool read_request_header(struct admin_connection *conn) {
    if (!read_exact(conn->fd, &conn->req_h, sizeof(conn->req_h))) {
        return false; // error o EOF
    }

    conn->cmd         = (enum admin_cmd) conn->req_h.cmd;
    conn->req_body_len = ntohs(conn->req_h.len);

    return true;
}

static bool read_request_body(struct admin_connection *conn) {
    if (conn->req_body_len == 0) {
        conn->req_body = NULL;
        return true;
    }

    conn->req_body = malloc(conn->req_body_len);
    if (conn->req_body == NULL) {
        // consumimos y descartamos el body del socket para no dejar basura
        uint8_t tmp[256];
        uint16_t remaining = conn->req_body_len;
        while (remaining > 0) {
            size_t chunk = remaining > sizeof(tmp) ? sizeof(tmp) : remaining;
            if (!read_exact(conn->fd, tmp, chunk)) {
                break;
            }
            remaining -= (uint16_t)chunk;
        }
        admin_prepare_error(conn, 1, "no_memory");
        return false;
    }

    if (!read_exact(conn->fd, conn->req_body, conn->req_body_len)) {
        free(conn->req_body);
        conn->req_body = NULL;
        return false;
    }

    return true;
}

static bool send_response(struct admin_connection *conn) {
    if (!write_exact(conn->fd, &conn->resp_h, sizeof(conn->resp_h))) {
        return false;
    }

    uint16_t resp_len = ntohs(conn->resp_h.len);
    if (resp_len > 0 && conn->resp_body != NULL) {
        if (!write_exact(conn->fd, conn->resp_body, resp_len)) {
            return false;
        }
    }

    return true;
}

// ----------- Procesamiento de comandos -----------

static void process_metrics_request(struct admin_connection *conn) {
    switch (conn->cmd) {
        case ADMIN_GET_CONCURRENT_CONN:
            admin_prepare_ok_uint64(conn,
                metrics_get_concurrent_connections());
            break;
        case ADMIN_GET_HIST_CONN:
            admin_prepare_ok_uint64(conn,
                metrics_get_historic_connections());
            break;
        case ADMIN_GET_BYTES_TRANSFERRED:
            admin_prepare_ok_uint64(conn,
                metrics_get_bytes_transferred());
            break;
        default:
            admin_prepare_error(conn, 1, "invalid_metric_cmd");
            break;
    }
}

static void process_user_mgmt_request(struct admin_connection *conn) {
    if (conn->req_body == NULL || conn->req_body_len == 0) {
        admin_prepare_error(conn, 1, "missing_body");
        return;
    }

    char *body = malloc(conn->req_body_len + 1);
    if (body == NULL) {
        admin_prepare_error(conn, 1, "no_memory");
        return;
    }
    memcpy(body, conn->req_body, conn->req_body_len);
    body[conn->req_body_len] = '\0';

    char username[128] = {0};
    char password[128] = {0};
    char role_str[32]  = {0};
    uint8_t role       = 0;
    int rc             = 0;

    switch (conn->cmd) {
        case ADMIN_SET_USER_ROLE:
            // Body: "username role\n" donde role puede ser "admin"/"user" o un número
            if (sscanf(body, "%127s %31s", username, role_str) != 2) {
                admin_prepare_error(conn, 1, "bad_format");
                free(body);
                return;
            }
            if (strcmp(role_str, "admin") == 0) {
                role = 1;
            } else if (strcmp(role_str, "user") == 0) {
                role = 0;
            } else {
                // También podés permitir número
                role = (uint8_t) atoi(role_str);
            }
            rc = users_set_role(username, role);
            if (rc == 0) {
                admin_prepare_ok_msg(conn, "OK\n");
            } else {
                admin_prepare_error(conn, 1, "set_user_role_failed");
            }
            break;

        case ADMIN_ADD_USER:
            // Body: "username password role\n"
            if (sscanf(body, "%127s %127s %31s", username, password, role_str) != 3) {
                admin_prepare_error(conn, 1, "bad_format");
                free(body);
                return;
            }
            if (strcmp(role_str, "admin") == 0) {
                role = 1;
            } else if (strcmp(role_str, "user") == 0) {
                role = 0;
            } else {
                role = (uint8_t) atoi(role_str);
            }
            rc = users_add(username, password, role);
            if (rc == 0) {
                admin_prepare_ok_msg(conn, "OK\n");
            } else {
                admin_prepare_error(conn, 1, "add_user_failed");
            }
            break;

        case ADMIN_DELETE_USER:
            // Body: "username\n"
            if (sscanf(body, "%127s", username) != 1) {
                admin_prepare_error(conn, 1, "bad_format");
                free(body);
                return;
            }
            rc = users_delete(username);
            if (rc == 0) {
                admin_prepare_ok_msg(conn, "OK\n");
            } else {
                admin_prepare_error(conn, 1, "delete_user_failed");
            }
            break;

        default:
            admin_prepare_error(conn, 1, "invalid_user_cmd");
            break;
    }

    free(body);
}

static void process_user_connections_request(struct admin_connection *conn) {
    if (conn->req_body == NULL || conn->req_body_len == 0) {
        admin_prepare_error(conn, 1, "missing_body");
        return;
    }

    char *body = malloc(conn->req_body_len + 1);
    if (body == NULL) {
        admin_prepare_error(conn, 1, "no_memory");
        return;
    }
    memcpy(body, conn->req_body, conn->req_body_len);
    body[conn->req_body_len] = '\0';

    char username[128] = {0};
    if (sscanf(body, "%127s", username) != 1) {
        admin_prepare_error(conn, 1, "bad_format");
        free(body);
        return;
    }

    uint64_t count = 0;
    int rc = users_get_connection_count(username, &count);
    if (rc == 0) {
        admin_prepare_ok_uint64(conn, count);
    } else {
        admin_prepare_error(conn, 1, "user_connections_failed");
    }

    free(body);
}

static void process_request(struct admin_connection *conn) {
    conn->resp_body     = NULL;
    conn->resp_body_len = 0;

    switch (conn->cmd) {
        case ADMIN_GET_CONCURRENT_CONN:
        case ADMIN_GET_HIST_CONN:
        case ADMIN_GET_BYTES_TRANSFERRED:
            process_metrics_request(conn);
            break;

        case ADMIN_SET_USER_ROLE:
        case ADMIN_ADD_USER:
        case ADMIN_DELETE_USER:
            process_user_mgmt_request(conn);
            break;

        case ADMIN_GET_USER_CONNECTIONS:
            process_user_connections_request(conn);
            break;

        case ADMIN_QUIT:
            admin_prepare_ok_msg(conn, "bye\n");
            break;

        default:
            admin_prepare_error(conn, 1, "unknown_cmd");
            break;
    }
}

// ----------- Manejo de una conexión de admin -----------

static void handle_admin_client(int client_fd) {
    struct admin_connection conn;
    memset(&conn, 0, sizeof(conn));
    conn.fd = client_fd;

    for (;;) {

        if (!read_request_header(&conn)) {
            break;
        }

        printf("[INF] Request cmd=0x%02X len=%u\n",
               conn.cmd, conn.req_body_len);

        conn.req_body   = NULL;
        conn.resp_body  = NULL;

        if (!read_request_body(&conn)) {
            
            if (conn.req_body) {
                free(conn.req_body);
                conn.req_body = NULL;
            }
            break;
        }

        process_request(&conn);

        // 4) Enviar respuesta
        if (!send_response(&conn)) {
            fprintf(stderr, "[WRN] Failed to send response\n");
            if (conn.req_body)  free(conn.req_body);
            if (conn.resp_body) free(conn.resp_body);
            break;
        }

        if (conn.req_body) {
            free(conn.req_body);
            conn.req_body = NULL;
        }
        if (conn.resp_body) {
            free(conn.resp_body);
            conn.resp_body = NULL;
        }

        if (conn.cmd == ADMIN_QUIT) {
            printf("[INF] Admin sent QUIT\n");
            break;
        }
    }
}

// ----------- API Server -----------

int main(int argc, char const *argv[]) {
    (void)argc;
    (void)argv;

    // Ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);

    int server_fd = create_server_socket(ADMIN_API_PORT);

    for (;;) {
        struct sockaddr_storage client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client = accept(server_fd,
                            (struct sockaddr *)&client_addr,
                            &client_len);
        if (client < 0) {
            perror("accept");
            continue;
        }

        printf("[INF] New admin connection (fd=%d)\n", client);

        handle_admin_client(client);

        printf("[INF] Closing admin connection (fd=%d)\n", client);
        close(client);
    }

    close(server_fd);
    return 0;
}
