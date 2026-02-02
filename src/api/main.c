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
#include "../../include/socks5.h"
#include "../../include/auth.h"
#include "../../include/parser_arguments.h"
#include "../../include/util.h"

#define BACKLOG        5

/* ----------- Parsing argumentos -----------*/

static const ArgParserConfig API_CFG = {
    .version_str = "Admin API v1.0",
    .help_str =
        "Usage: %s [OPTIONS]\n"
        "  -l <addr>   Dirección donde escucha la Admin API (default: ::1)\n"
        "  -p <port>   Puerto donde escucha la Admin API (default: 8080)\n"
        "  -h / -v     Ayuda o versión\n",

    .def_socks_addr = LOOPBACK_IPV6,   // usamos socks_addr como "bind addr" de la API
    .def_socks_port = ADMIN_API_PORT,  // usamos socks_port como "bind port" de la API

    .def_aux_addr = NULL,
    .def_aux_port = 0,

    .enable_aux        = false,
    .enable_users      = false,
    .enable_dissectors = false,
};



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
    uint8_t raw_buf[ADMIN_HEADER_SIZE];

    if (!read_exact(conn->fd, raw_buf, ADMIN_HEADER_SIZE)) {
        return false; // Error de I/O o conexión cerrada
    }

    // 3. Deserializar: Bytes -> Struct (Maneja ntohs/ntohl internamente)
    if (admin_deserialize_req(raw_buf, ADMIN_HEADER_SIZE, &conn->req_h) < 0) {
        return false; // Error de protocolo (buffer muy chico, etc)
    }

    conn->cmd = (enum admin_cmd)conn->req_h.cmd;
    
    conn->req_body_len = conn->req_h.len; 

    return true;
}

static bool read_request_body(struct admin_connection *conn) {
    if (conn->req_body_len == 0) {
        conn->req_body = NULL;
        return true;
    }

    // Asignación de memoria
    conn->req_body = malloc(conn->req_body_len);
    if (conn->req_body == NULL) {
        // === Manejo de OOM (Out of Memory) ===
        // Si no hay memoria, debemos "consumir" los bytes del socket para no desincronizar
        // el protocolo, aunque luego devolvamos error.
        uint8_t tmp[256];
        uint16_t remaining = conn->req_body_len;
        while (remaining > 0) {
            size_t chunk = remaining > sizeof(tmp) ? sizeof(tmp) : remaining;
            if (!read_exact(conn->fd, tmp, chunk)) {
                break; // Si falla la lectura, cortamos
            }
            remaining -= (uint16_t)chunk;
        }
        
        return false;
    }

    // Lectura del cuerpo
    // El cuerpo usualmente son datos crudos o strings, no requieren endianness swap
    // a menos que definas estructuras complejas dentro.
    if (!read_exact(conn->fd, conn->req_body, conn->req_body_len)) {
        free(conn->req_body);
        conn->req_body = NULL;
        return false;
    }

    return true;
}

static bool send_response(struct admin_connection *conn) {
    uint8_t header_buf[ADMIN_HEADER_SIZE];
    uint8_t *p = header_buf;
    uint32_t net_id = htonl(conn->resp_h.id);
    memcpy(p, &net_id, 4);
    p += 4;

    *p++ = conn->resp_h.status;

    uint16_t net_len = htons(conn->resp_h.len);
    memcpy(p, &net_len, 2);
    p += 2;

    // === ENVIAR HEADER ===
    if (!write_exact(conn->fd, header_buf, ADMIN_HEADER_SIZE)) {
        return false;
    }

    // === ENVIAR BODY ===
    if (conn->resp_h.len > 0 && conn->resp_body != NULL) {
        if (!write_exact(conn->fd, conn->resp_body, conn->resp_h.len)) {
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

static bool parse_role(const char *role_str, client_role *out_role) {
    if (out_role == NULL || role_str == NULL) return false;

    if (strcmp(role_str, "admin") == 0 || strcmp(role_str, "1") == 0) {
        *out_role = ROLE_ADMIN;
        return true;
    }
    if (strcmp(role_str, "user") == 0 || strcmp(role_str, "0") == 0) {
        *out_role = ROLE_USER;
        return true;
    }

    return false; // unknown role token
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
    client_role parsed_role = ROLE_USER;
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

        if (!parse_role(role_str, &parsed_role)) {
            admin_prepare_error(conn, 1, "invalid_role");
            break;
        }

        snprintf(updated.role, sizeof updated.role, "%d", parsed_role);

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
        char output[65];
        get_sha3(password,output);
        strncpy(rec.user, username, sizeof rec.user - 1);
        strncpy(rec.pass_hash, output , sizeof rec.pass_hash - 1); // sin hash

        if (!parse_role(role_str, &parsed_role)) {
            admin_prepare_error(conn, 1, "invalid_role");
            break;
        }

        snprintf(rec.role, sizeof rec.role, "%d", parsed_role);

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

        // timestamp \t username \t A \t src_ip \t src_port \t dst_ip \t dst_port \t status
        char line_copy[MAX_LINE];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        line_copy[sizeof(line_copy) - 1] = '\0';

        char *saveptr = NULL;
        char *token = strtok_r(line_copy, "\t", &saveptr); // timestamp
        token = strtok_r(NULL, "\t", &saveptr);            // username
        if (token == NULL) {
            continue;
        }

        if (strcmp(token, username) != 0) {
            continue;
        }

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
    conn->resp_body     = buffer; 
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

static void sockaddr_to_string(const struct sockaddr *sa, char *out, size_t outlen) {
    if (out == NULL || outlen == 0) return;

    char ip[INET6_ADDRSTRLEN];
    uint16_t port = 0;

    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)sa;
        inet_ntop(AF_INET, &a->sin_addr, ip, sizeof(ip));
        port = ntohs(a->sin_port);
        snprintf(out, outlen, "%s:%u", ip, port);
        return;
    }

    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)sa;
        inet_ntop(AF_INET6, &a6->sin6_addr, ip, sizeof(ip));
        port = ntohs(a6->sin6_port);
        snprintf(out, outlen, "[%s]:%u", ip, port);
        return;
    }

    snprintf(out, outlen, "<unknown family %d>", sa->sa_family);
}

static void print_bound_endpoint(int fd) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);

    if (getsockname(fd, (struct sockaddr *)&ss, &slen) != 0) {
        perror("getsockname");
        return;
    }

    char buf[128];
    sockaddr_to_string((struct sockaddr *)&ss, buf, sizeof(buf));
    printf("[INF] Admin API listening on %s\n", buf);
}


static int create_server_socket(const char *listen_addr, uint16_t port) {
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

    // 1) Intentar IPv6 literal
    if (inet_pton(AF_INET6, listen_addr, &addr.sin6_addr) == 1) {
        // ok
    }
    // 2) Intentar IPv4 literal -> lo convertimos a IPv4-mapped ::ffff:a.b.c.d
    else {
        struct in_addr v4;
        if (inet_pton(AF_INET, listen_addr, &v4) == 1) {
            // ::ffff:a.b.c.d
            addr.sin6_addr = in6addr_any;
            addr.sin6_addr.s6_addr[10] = 0xff;
            addr.sin6_addr.s6_addr[11] = 0xff;
            memcpy(&addr.sin6_addr.s6_addr[12], &v4, 4);
        } else {
            fprintf(stderr, "[ERR] Invalid listen address: %s\n", listen_addr);
            close(fd);
            exit(EXIT_FAILURE);
        }
    }

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
    
    print_bound_endpoint(fd);

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

int main(int argc, const char *argv[]) {
    signal(SIGPIPE, SIG_IGN);

    ProgramArgs args;
    if (parse_arguments_ex(argc, argv, &args, &API_CFG) < 0) {
        return EXIT_FAILURE;
    }
    if (validate_arguments_ex(&args, &API_CFG) < 0) {
        args_destroy(&args, &API_CFG);
        return EXIT_FAILURE;
    }

    if (!user_store_load(USER_DB_PATH)) {
        fprintf(stderr, "[ERR] Failed to load user database from %s: %s\n",
                USER_DB_PATH, strerror(errno));
        args_destroy(&args, &API_CFG);
        return EXIT_FAILURE;
    }

    const char *listen_addr = args.socks_addr;
    uint16_t listen_port     = args.socks_port;

    int server_fd = create_server_socket(listen_addr, listen_port);

    for (;;) {
        struct sockaddr_storage client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
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
    args_destroy(&args, &API_CFG);
    return 0;
}
