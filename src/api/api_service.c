#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../../include/api_service.h"          
#include "../../include/user_mgmt.h"
#include "../../include/metrics.h"
#include "../../include/api.h"
#include "../../include/util.h"
#include "../../include/shared.h"
#include "../../include/auth.h"

/* =========================================================================
   1. DEFINICIÓN DE ESTADOS Y ESTRUCTURAS (Privadas)
   ========================================================================= */

typedef enum {
    API_STATE_READ_HEADER,
    API_STATE_READ_BODY,
    API_STATE_PROCESS,
    API_STATE_WRITE,
    API_STATE_CLOSE,
    API_STATE_ERROR
} api_state_t;

struct admin_connection {
    int fd;
    api_state_t state;

    // Buffers Entrada
    struct admin_req_header req_h;
    uint8_t raw_header_buf[ADMIN_HEADER_SIZE];
    size_t  req_header_read_bytes;
    uint8_t *req_body;
    uint16_t req_body_len;
    size_t   req_body_read_bytes;
    enum admin_cmd cmd;

    // Buffers Salida
    struct admin_resp_header resp_h;
    uint8_t raw_resp_header_buf[ADMIN_HEADER_SIZE];
    uint8_t *resp_body;
    uint16_t resp_body_len;
    size_t   write_offset;
    bool     header_sent;
};

// Prototipos locales
static void api_read(struct selector_key *key);
static void api_write(struct selector_key *key);
static void api_close(struct selector_key *key);
static void process_request(struct admin_connection *conn);

// Handler para clientes activos
static const struct fd_handler api_handlers = {
    .handle_read   = api_read,
    .handle_write  = api_write,
    .handle_close  = api_close,
    .handle_block  = NULL,
};

/* =========================================================================
   2. HELPERS DE RESPUESTA
   ========================================================================= */

static void admin_prepare_error(struct admin_connection *conn, uint8_t status, const char *msg) {
    size_t msg_len = msg != NULL ? strlen(msg) : 0;
    conn->resp_h.id     = conn->req_h.id;
    conn->resp_h.status = status;
    conn->resp_h.len    = (uint16_t)msg_len; // Host order (corregido)
    conn->resp_body_len = (uint16_t)msg_len;
    conn->resp_body     = msg_len > 0 ? malloc(msg_len) : NULL;
    
    if (msg_len > 0 && conn->resp_body) {
        memcpy(conn->resp_body, msg, msg_len);
    } else if (msg_len > 0) {
        conn->resp_h.len = 0; // Fallo malloc
    }
}

static void admin_prepare_ok_uint64(struct admin_connection *conn, uint64_t value) {
    char buf[64];
    int len = snprintf(buf, sizeof(buf), "%llu\n", (unsigned long long)value);
    if (len < 0) { admin_prepare_error(conn, 1, "internal_error"); return; }

    conn->resp_h.id     = conn->req_h.id;
    conn->resp_h.status = 0;
    conn->resp_h.len    = (uint16_t)len;
    conn->resp_body_len = (uint16_t)len;
    conn->resp_body     = malloc(conn->resp_body_len);

    if (conn->resp_body == NULL) { admin_prepare_error(conn, 1, "no_memory"); return; }
    memcpy(conn->resp_body, buf, conn->resp_body_len);
}

static void admin_prepare_ok_msg(struct admin_connection *conn, const char *msg) {
    size_t msg_len = msg != NULL ? strlen(msg) : 0;
    conn->resp_h.id     = conn->req_h.id;
    conn->resp_h.status = 0;
    conn->resp_h.len    = (uint16_t)msg_len;
    conn->resp_body_len = (uint16_t)msg_len;
    conn->resp_body     = msg_len > 0 ? malloc(msg_len) : NULL;

    if (msg_len > 0 && conn->resp_body) {
        memcpy(conn->resp_body, msg, msg_len);
    } else if (msg_len > 0) {
        admin_prepare_error(conn, 1, "no_memory");
    }
}

/* =========================================================================
   3. PROCESAMIENTO DE COMANDOS
   ========================================================================= */

static void process_metrics_request(struct admin_connection *conn) {
    uint64_t value = -1;
    switch (conn->cmd) {
        case ADMIN_GET_CONCURRENT_CONN: value = metrics_get_concurrent_connections(); break;
        case ADMIN_GET_HIST_CONN:       value = metrics_get_total_connections(); break;
        case ADMIN_GET_BYTES_TRANSFERRED: value = metrics_get_bytes(); break;
        default: admin_prepare_error(conn, 1, "invalid_metric_cmd"); return;
    }
    
    if (value == (uint64_t)-1) admin_prepare_error(conn, 1, "metrics_read_error");
    else admin_prepare_ok_uint64(conn, value);
}

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
            process_user_mgmt_request(conn); // Descomentar al mover la función
            break;
        case ADMIN_GET_USER_CONNECTIONS:
            process_user_connections_request(conn); // Descomentar al mover
            break;
        case ADMIN_QUIT:
            admin_prepare_ok_msg(conn, "bye\n");
            break;
        default:
            admin_prepare_error(conn, 1, "unknown_cmd");
            break;
    }
}

/* =========================================================================
   4. SELECTOR CALLBACKS (IO)
   ========================================================================= */

static void api_read(struct selector_key *key) {
    struct admin_connection *conn = (struct admin_connection *)key->data;
    ssize_t n;

    switch (conn->state) {
        case API_STATE_READ_HEADER:
            n = recv(key->fd, conn->raw_header_buf + conn->req_header_read_bytes, 
                     ADMIN_HEADER_SIZE - conn->req_header_read_bytes, 0);
            if (n <= 0) {
                if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
                goto close_conn;
            }
            conn->req_header_read_bytes += n;
            if (conn->req_header_read_bytes == ADMIN_HEADER_SIZE) {
                if (admin_deserialize_req(conn->raw_header_buf, ADMIN_HEADER_SIZE, &conn->req_h) < 0) goto close_conn;
                conn->cmd = (enum admin_cmd)conn->req_h.cmd;
                conn->req_body_len = conn->req_h.len;
                
                if (conn->req_body_len > 0) {
                    conn->req_body = malloc(conn->req_body_len);
                    if (!conn->req_body) goto close_conn;
                    conn->req_body_read_bytes = 0;
                    conn->state = API_STATE_READ_BODY;
                    api_read(key); // Intentar leer body inmediatamente
                } else {
                    conn->state = API_STATE_PROCESS;
                    api_read(key); // Procesar inmediatamente
                }
            }
            break;

        case API_STATE_READ_BODY:
            n = recv(key->fd, conn->req_body + conn->req_body_read_bytes, 
                     conn->req_body_len - conn->req_body_read_bytes, 0);
            if (n <= 0) {
                if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
                goto close_conn;
            }
            conn->req_body_read_bytes += n;
            if (conn->req_body_read_bytes == conn->req_body_len) {
                conn->state = API_STATE_PROCESS;
                api_read(key);
            }
            break;

        case API_STATE_PROCESS:
            process_request(conn);
            // Serialización manual del header para evitar chequeos de tamaño
            {
                uint8_t *p = conn->raw_resp_header_buf;
                uint32_t net_id = htonl(conn->resp_h.id);
                memcpy(p, &net_id, 4); p += 4;
                *p++ = conn->resp_h.status;
                uint16_t net_len = htons(conn->resp_h.len);
                memcpy(p, &net_len, 2);
            }
            conn->state = API_STATE_WRITE;
            conn->write_offset = 0;
            conn->header_sent = false;
            selector_set_interest(key->s, key->fd, OP_WRITE);
            api_write(key);
            break;
            
        default: break;
    }
    return;

close_conn:
    selector_unregister_fd(key->s, key->fd);
}

static void api_write(struct selector_key *key) {
    struct admin_connection *conn = (struct admin_connection *)key->data;
    ssize_t n;

    if (conn->state != API_STATE_WRITE) return;

    // 1. Enviar Header
    if (!conn->header_sent) {
        n = send(key->fd, conn->raw_resp_header_buf + conn->write_offset, 
                 ADMIN_HEADER_SIZE - conn->write_offset, MSG_NOSIGNAL);
        if (n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            goto close_conn;
        }
        conn->write_offset += n;
        if (conn->write_offset == ADMIN_HEADER_SIZE) {
            conn->header_sent = true;
            conn->write_offset = 0;
        } else return;
    }

    // 2. Enviar Body
    if (conn->header_sent && conn->resp_h.len > 0) {
        n = send(key->fd, conn->resp_body + conn->write_offset, 
                 conn->resp_h.len - conn->write_offset, MSG_NOSIGNAL);
        if (n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            goto close_conn;
        }
        conn->write_offset += n;
        if (conn->write_offset < conn->resp_h.len) return;
    }

    // 3. Limpieza y Transición
    if (conn->req_body) { free(conn->req_body); conn->req_body = NULL; }
    if (conn->resp_body) { free(conn->resp_body); conn->resp_body = NULL; }

    if (conn->cmd == ADMIN_QUIT) {
        selector_unregister_fd(key->s, key->fd); // Cierre limpio
        return;
    }

    conn->state = API_STATE_READ_HEADER;
    conn->req_header_read_bytes = 0;
    selector_set_interest(key->s, key->fd, OP_READ);
    return;

close_conn:
    print_error("Error writing to client (fd %d)", key->fd);
    selector_unregister_fd(key->s, key->fd);
}

static void api_close(struct selector_key *key) {
    struct admin_connection *conn = (struct admin_connection *)key->data;
    if (conn) {
        if (conn->req_body) free(conn->req_body);
        if (conn->resp_body) free(conn->resp_body);
        free(conn);
        key->data = NULL;
    }
    if (key->fd != -1) close(key->fd);
    print_info("Connection closed (fd %d)", key->fd);
}

// Esta es la función pública (expuesta en .h)
void api_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int client_fd = accept(key->fd, (struct sockaddr *)&client_addr, &client_addr_len);
    
    if (client_fd == -1 || selector_fd_set_nio(client_fd) == -1) {
        if (client_fd != -1) close(client_fd);
        return;
    }

    struct admin_connection *state = malloc(sizeof(struct admin_connection));
    if (!state) { close(client_fd); return; }
    memset(state, 0, sizeof(*state));
    state->fd = client_fd;

    if (selector_register(key->s, client_fd, &api_handlers, OP_READ, state) != SELECTOR_SUCCESS) {
        free(state);
        close(client_fd);
        return;
    }
    print_info("New admin connection registered (fd=%d)", client_fd);
}

// Estructura pública
const struct fd_handler api_passive_handler = {
    .handle_read   = api_passive_accept,
    .handle_write  = NULL,
    .handle_close  = NULL, 
    .handle_block  = NULL,
};