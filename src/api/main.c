#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../../include/user_mgmt.h"
#include "../../include/shared.h"
#include "../../include/metrics.h"
#include "../../include/api.h"

#define BACKLOG        5

/* ----------- Protocolo ----------- */

struct admin_connection {
    int fd; // socket del admin

    struct admin_req_header  req_h;
    struct admin_resp_header resp_h;

    uint8_t *req_body;
    uint8_t *resp_body;

    uint16_t req_body_len;
    uint16_t resp_body_len;

    enum admin_cmd cmd;
};

/* ----------- Helpers de respuesta ----------- */

static void admin_prepare_error(struct admin_connection *conn,
                                uint8_t status,
                                const char *msg) {
    size_t msg_len = msg != NULL ? strlen(msg) : 0;

    conn->resp_h.id     = conn->req_h.id;  // mismo id (ya en network order)
    conn->resp_h.status = status;
    conn->resp_h.len    = htons((uint16_t)msg_len);

    conn->resp_body_len = (uint16_t)msg_len;
    conn->resp_body     = NULL;

    if (msg_len > 0) {
        conn->resp_body = malloc(msg_len);
        if (conn->resp_body == NULL) {
            conn->resp_h.len    = htons(0);
            conn->resp_body_len = 0;
            return;
        }
        memcpy(conn->resp_body, msg, msg_len);
    }
}

static void admin_prepare_ok_uint64(struct admin_connection *conn,
                                    uint64_t value) {
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

/* ----------- IO de requests ----------- */

static bool read_request_header(struct admin_connection *conn) {
    if (!read_exact(conn->fd, &conn->req_h, sizeof(conn->req_h))) {
        return false; // error o EOF
    }

    conn->cmd          = (enum admin_cmd)conn->req_h.cmd;
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

/* ----------- Procesamiento de comandos ----------- */

static void process_metrics_request(struct admin_connection *conn) {
    uint64_t value;

    switch (conn->cmd) {
        case ADMIN_GET_CONCURRENT_CONN: {
            value = metrics_get_concurrent_connections();
            if (value == (uint64_t)-1) {
                admin_prepare_error(conn, 1, "metrics_read_error");
            } else {
                admin_prepare_ok_uint64(conn, value);
            }
            break;
        }

        case ADMIN_GET_HIST_CONN: {
            value = metrics_get_total_connections();
            if (value == (uint64_t)-1) {
                admin_prepare_error(conn, 1, "metrics_read_error");
            } else {
                admin_prepare_ok_uint64(conn, value);
            }
            break;
        }

        case ADMIN_GET_BYTES_TRANSFERRED: {
            value = metrics_get_bytes();
            if (value == (uint64_t)-1) {
                admin_prepare_error(conn, 1, "metrics_read_error");
            } else {
                admin_prepare_ok_uint64(conn, value);
            }
            break;
        }

        default:
            admin_prepare_error(conn, 1, "invalid_metric_cmd");
            break;
    }
}


/* ----------- Roles / usuarios ----------- */

static bool parse_role_string(const char *role_str,
                              char *out_role,
                              size_t out_size) {
    if (!out_role || out_size == 0) return false;

    if (strcmp(role_str, "admin") == 0) {
        strncpy(out_role, "admin", out_size - 1);
    } else if (strcmp(role_str, "user") == 0) {
        strncpy(out_role, "user", out_size - 1);
    } else {
        strncpy(out_role, role_str, out_size - 1);
    }
    out_role[out_size - 1] = '\0';
    return true;
}

/**
 * ADMIN_SET_USER_ROLE / ADMIN_ADD_USER / ADMIN_DELETE_USER
 */
static void process_user_mgmt_request(struct admin_connection *conn) {
    if (conn->req_body == NULL || conn->req_body_len == 0) {
        admin_prepare_error(conn, 1, "missing_body");
        return;
    }

    char *body = malloc(conn->req_body_len + 1);
    if (!body) {
        admin_prepare_error(conn, 1, "no_memory");
        return;
    }

    memcpy(body, conn->req_body, conn->req_body_len);
    body[conn->req_body_len] = '\0';

    char username[128] = {0};
    char password[128] = {0};
    char role_str[64]  = {0};
    int ok;

    switch (conn->cmd) {

    // SET_USER_ROLE: "username role"
    case ADMIN_SET_USER_ROLE: {
        if (sscanf(body, "%127s %63s", username, role_str) != 2) {
            admin_prepare_error(conn, 1, "bad_format");
            break;
        }

        const user_record *rec = user_store_find(username);
        if (!rec) {
            admin_prepare_error(conn, 1, "user_not_found");
            break;
        }

        user_record updated = *rec;

        if (!parse_role_string(role_str, updated.role, sizeof updated.role)) {
            admin_prepare_error(conn, 1, "invalid_role");
            break;
        }

        ok = user_store_update(username, &updated);
        if (!ok) {
            admin_prepare_error(conn, 1, "set_user_role_failed");
            break;
        }

        if (!user_store_save(USER_DB_PATH)) {
            admin_prepare_error(conn, 1, "save_failed");
            break;
        }

        admin_prepare_ok_msg(conn, "OK\n");
        break;
    }

    // ADD_USER: "username password role"
    case ADMIN_ADD_USER: {
        if (sscanf(body, "%127s %127s %63s", username, password, role_str) != 3) {
            admin_prepare_error(conn, 1, "bad_format");
            break;
        }

        user_record rec = (user_record){0};

        strncpy(rec.user, username, sizeof rec.user - 1);
        strncpy(rec.pass_hash, password, sizeof rec.pass_hash - 1); // sin hash

        if (!parse_role_string(role_str, rec.role, sizeof rec.role)) {
            admin_prepare_error(conn, 1, "invalid_role");
            break;
        }

        ok = user_store_add(&rec);
        if (!ok) {
            admin_prepare_error(conn, 1, "add_user_failed_or_exists");
            break;
        }

        if (!user_store_save(USER_DB_PATH)) {
            admin_prepare_error(conn, 1, "save_failed");
            break;
        }

        admin_prepare_ok_msg(conn, "OK\n");
        break;
    }

    // DELETE_USER: "username"
    case ADMIN_DELETE_USER: {
        if (sscanf(body, "%127s", username) != 1) {
            admin_prepare_error(conn, 1, "bad_format");
            break;
        }

        ok = user_store_delete(username);
        if (!ok) {
            admin_prepare_error(conn, 1, "delete_user_failed");
            break;
        }

        if (!user_store_save(USER_DB_PATH)) {
            admin_prepare_error(conn, 1, "save_failed");
            break;
        }

        admin_prepare_ok_msg(conn, "OK\n");
        break;
    }

    default:
        admin_prepare_error(conn, 1, "invalid_user_cmd");
        break;
    }

    free(body);
}

/**
 * ADMIN_GET_USER_CONNECTIONS: por ahora stub
 */
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
    free(body);

    FILE *f = fopen(ACCESS_FILE, "r");
    if (f == NULL) {
        admin_prepare_error(conn, 1, "log_open_failed");
        return;
    }

    char line[MAX_LINE];
    uint8_t *buffer = NULL;
    size_t buf_len  = 0;
    size_t buf_cap  = 0;
    uint64_t matches = 0;

    while (fgets(line, sizeof(line), f) != NULL) {

        const char *p = strstr(line, "] - ");
        if (p == NULL) {
            continue;
        }
        p += strlen("] - ");

        char user_in_line[128];
        int i = 0;
        while (p[i] != ':' &&
               p[i] != '\0' &&
               i < (int)sizeof(user_in_line) - 1) {

            user_in_line[i] = p[i];
            i++;
        }
        user_in_line[i] = '\0';

        if (strcmp(user_in_line, username) != 0) {
            continue;
        }

        // Matcheó el usuario → agregamos esta línea al buffer
        size_t line_len = strlen(line);

        if (buf_len + line_len > buf_cap) {
            size_t new_cap = buf_cap == 0 ? 1024 : buf_cap * 2;
            while (new_cap < buf_len + line_len) {
                new_cap *= 2;
            }
            uint8_t *tmp = realloc(buffer, new_cap);
            if (tmp == NULL) {
                fclose(f);
                free(buffer);
                admin_prepare_error(conn, 1, "no_memory");
                return;
            }
            buffer = tmp;
            buf_cap = new_cap;
        }

        memcpy(buffer + buf_len, line, line_len);
        buf_len += line_len;
        matches++;
    }

    fclose(f);

    if (matches == 0) {
        free(buffer);
        admin_prepare_error(conn, 1, "no_entries_for_user");
        return;
    }

    conn->resp_h.id     = conn->req_h.id;
    conn->resp_h.status = 0;
    conn->resp_h.len    = htons((uint16_t)buf_len);

    conn->resp_body_len = (uint16_t)buf_len;
    conn->resp_body     = buffer;  // se libera en el caller después de send_response()
}

/* ----------- Dispatcher ----------- */

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

/* ----------- Socket pasivo ----------- */

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

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port   = htons(port);
    addr.sin6_addr   = in6addr_loopback; // ::1

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

/* ----------- Manejo de un admin ----------- */

static void handle_admin_client(int client_fd) {
    struct admin_connection conn;
    memset(&conn, 0, sizeof(conn));
    conn.fd = client_fd;

    for (;;) {
        if (!read_request_header(&conn)) {
            break; // cierre o error
        }

        printf("[INF] Request cmd=0x%02X len=%u\n",
               conn.cmd, conn.req_body_len);

        conn.req_body  = NULL;
        conn.resp_body = NULL;

        if (!read_request_body(&conn)) {
            if (conn.req_body) free(conn.req_body);
            break;
        }

        process_request(&conn);

        if (!send_response(&conn)) {
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

/* ----------- main ----------- */

int main(int argc, char const *argv[]) {
    (void)argc;
    (void)argv;

    signal(SIGPIPE, SIG_IGN);

    if (!user_store_load(USER_DB_PATH)) {
        fprintf(stderr, "[ERR] Failed to load user database from %s: %s\n",
                USER_DB_PATH, strerror(errno));
        exit(EXIT_FAILURE);
    }

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
