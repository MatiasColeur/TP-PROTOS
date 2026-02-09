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
#include "../../include/selector.h"

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


/*------------ Estados del Selector -------------*/
typedef enum {
    API_STATE_READ_HEADER,  // Esperando los 7 bytes del header
    API_STATE_READ_BODY,    // Esperando N bytes del payload (si len > 0)
    API_STATE_PROCESS,      // Tengo todo, ejecutar comando (transición inmediata)
    API_STATE_WRITE,        // Tengo respuesta en buffer, intentando enviarla
    API_STATE_CLOSE,        // Enviar bytes restantes y cerrar (para QUIT)
    API_STATE_ERROR         // Hubo error, cerrar forzosamente
} api_state_t;


/* ----------- Protocolo ----------- */

/* Modifica tu struct admin_connection en el .c */
struct admin_connection {
    int fd;
    api_state_t state;

    // --- Buffers de Entrada (Request) ---
    struct admin_req_header  req_h;
    uint8_t raw_header_buf[ADMIN_HEADER_SIZE]; // Buffer temporal para los 7 bytes del header
    size_t  req_header_read_bytes;             // Cuántos bytes del header llevo leídos (0..7)
    
    uint8_t *req_body;                         // Buffer dinámico del body
    uint16_t req_body_len;                     // Longitud total esperada
    size_t   req_body_read_bytes;              // Cuántos bytes del body llevo leídos

    enum admin_cmd cmd;

    // --- Buffers de Salida (Response) ---
    struct admin_resp_header resp_h;
    uint8_t raw_resp_header_buf[ADMIN_HEADER_SIZE]; // Buffer serializado del header a enviar
    
    uint8_t *resp_body;                        // Buffer con la respuesta
    uint16_t resp_body_len;
    
    size_t   write_offset;                     // Cursor general para escritura (Header + Body)
    bool     header_sent;                      // Flag para saber si ya mandé el header
};

static void api_read(struct selector_key *key);
static void api_write(struct selector_key *key);
static void api_close(struct selector_key *key);

static bool done = false; // Bandera global para detener el servidor limpiamente

static void sigterm_handler(const int signal) {
    printf("[INF] Signal %d received, cleaning up and exiting...\n", signal);
    done = true;
}

// Prototipo de la función que acepta conexiones (la definimos abajo o en api_service.c)
void api_passive_accept(struct selector_key *key);

static const struct fd_handler api_handlers = {
    .handle_read   = api_read,
    .handle_write  = api_write,
    .handle_close  = api_close,
    .handle_block  = NULL,
};

static const struct fd_handler api_passive_handler = {
    .handle_read   = api_passive_accept,
    .handle_write  = NULL,
    .handle_close  = NULL, 
    .handle_block  = NULL,
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


static void register_acceptor_or_exit(fd_selector selector, int server_fd) {
    selector_status st = selector_register(selector, server_fd, &api_passive_handler, OP_READ, NULL);
    if (st != SELECTOR_SUCCESS) {
        fprintf(stderr, "selector_register(serverSocket) error: %s\n", selector_error(st));
        exit(EXIT_FAILURE);
    }
}


static void api_read(struct selector_key *key) {
    struct admin_connection *conn = (struct admin_connection *)key->data;
    ssize_t n;

    // MÁQUINA DE ESTADOS DE LECTURA

    switch (conn->state) {
        
        case API_STATE_READ_HEADER:
            // Intentamos leer lo que falta para completar los 7 bytes del header
            n = recv(key->fd, 
                     conn->raw_header_buf + conn->req_header_read_bytes, 
                     ADMIN_HEADER_SIZE - conn->req_header_read_bytes, 
                     0);

            if (n == 0) goto close_conn;
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) return; // Esperar más datos
                goto close_conn; // Error real
            }

            conn->req_header_read_bytes += n;

            // Si completamos el header (7 bytes)
            if (conn->req_header_read_bytes == ADMIN_HEADER_SIZE) {
                // Deserializar
                if (admin_deserialize_req(conn->raw_header_buf, ADMIN_HEADER_SIZE, &conn->req_h) < 0) {
                     // Error de protocolo
                     goto close_conn;
                }
                
                conn->cmd = (enum admin_cmd)conn->req_h.cmd;
                conn->req_body_len = conn->req_h.len;

                // Transición de estado
                if (conn->req_body_len > 0) {
                    // Preparar lectura de body
                    conn->req_body = malloc(conn->req_body_len);
                    if (conn->req_body == NULL) goto close_conn; // OOM
                    conn->req_body_read_bytes = 0;
                    conn->state = API_STATE_READ_BODY;
                    // Intentamos leer inmediatamente por si los datos ya vinieron pegados
                    api_read(key); 
                } else {
                    // No hay body, pasamos a procesar
                    conn->req_body = NULL;
                    conn->state = API_STATE_PROCESS;
                    api_read(key); // Llamada recursiva para procesar ya mismo
                }
            }
            break;

        case API_STATE_READ_BODY:
            n = recv(key->fd, 
                     conn->req_body + conn->req_body_read_bytes, 
                     conn->req_body_len - conn->req_body_read_bytes, 
                     0);

            if (n == 0) goto close_conn;
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) return;
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

            
            {
                uint8_t *p = conn->raw_resp_header_buf;
                
                // ID
                uint32_t net_id = htonl(conn->resp_h.id);
                memcpy(p, &net_id, 4);
                p += 4;

                // Status
                *p++ = conn->resp_h.status;

                // Len
                uint16_t net_len = htons(conn->resp_h.len);
                memcpy(p, &net_len, 2);
                p += 2;
            }


            // 3. Preparar para escribir
            conn->state = API_STATE_WRITE;
            conn->write_offset = 0;
            conn->header_sent = false;

            // 4. Cambiar interés del selector a WRITE
            selector_set_interest(key->s, key->fd, OP_WRITE);
            
            // 5. Intentar escribir inmediatamente
            api_write(key);
            break;

        default:
            break;
    }
    return;

close_conn:
    selector_unregister_fd(key->s, key->fd);
    print_error("Close en read");
}

static void api_write(struct selector_key *key) {
    struct admin_connection *conn = (struct admin_connection *)key->data;
    ssize_t n;

    if (conn->state != API_STATE_WRITE) return;

    if (!conn->header_sent) {
        size_t remaining = ADMIN_HEADER_SIZE - conn->write_offset;
        n = send(key->fd, conn->raw_resp_header_buf + conn->write_offset, remaining, MSG_NOSIGNAL);

        if (n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            goto close_conn;
        }
        conn->write_offset += n;

        if (conn->write_offset == ADMIN_HEADER_SIZE) {
            conn->header_sent = true;
            conn->write_offset = 0; // Reiniciar offset para usarlo en el body
        } else {
            return; // Falta enviar parte del header
        }
    }

    if (conn->header_sent && conn->resp_h.len > 0) {
        size_t remaining = conn->resp_h.len - conn->write_offset;
        n = send(key->fd, conn->resp_body + conn->write_offset, remaining, MSG_NOSIGNAL);

        if (n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            goto close_conn;
        }
        conn->write_offset += n;

        if (conn->write_offset < conn->resp_h.len) {
            return; // Falta enviar parte del body
        }
    }

    // FASE 3: Finalización de la respuesta
    // Limpiamos memoria de la request/response actual
    if (conn->req_body) { free(conn->req_body); conn->req_body = NULL; }
    if (conn->resp_body) { free(conn->resp_body); conn->resp_body = NULL; }

    // Chequear si era comando de salida
    if (conn->cmd == ADMIN_QUIT) {
        conn->state = API_STATE_CLOSE;
        goto close_conn;
    }

    // Keep-Alive: Volver a esperar un Request
    conn->state = API_STATE_READ_HEADER;
    conn->req_header_read_bytes = 0;
    
    // Cambiar interés a READ
    selector_set_interest(key->s, key->fd, OP_READ);
    return;

close_conn:
    selector_unregister_fd(key->s, key->fd);
    print_error("Close en write");

}

static void api_close(struct selector_key *key) {
    struct admin_connection *conn = (struct admin_connection *)key->data;
    if (conn == NULL) return;

    if (conn->req_body) { 
        free(conn->req_body); 
        conn->req_body = NULL; 
    }
    if (conn->resp_body) { 
        free(conn->resp_body); 
        conn->resp_body = NULL; 
    }

    free(conn);
    key->data = NULL; 

    // Cerrar el socket real
    if (key->fd != -1) {
        close(key->fd);
    }
    printf("[INF] Connection closed (fd %d)\n", key->fd);
}


void api_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    
    // Aceptar conexión entrante
    int client_fd = accept(key->fd, (struct sockaddr *)&client_addr, &client_addr_len);
    
    if (client_fd == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("accept");
        }
        return;
    }

    // Configurar cliente como NO BLOQUEANTE
    if (selector_fd_set_nio(client_fd) == -1) {
        perror("selector_fd_set_nio client");
        close(client_fd);
        return;
    }

    // Crear estado para este cliente
    struct admin_connection *state = malloc(sizeof(struct admin_connection));
    if (state == NULL) {
        close(client_fd);
        return;
    }
    memset(state, 0, sizeof(*state));
    state->fd = client_fd;
    

    // Registrar el NUEVO cliente en el selector
    selector_status ss = selector_register(key->s, client_fd, &api_handlers, OP_READ, state);

    if (ss != SELECTOR_SUCCESS) {
        perror("selector_register client");
        free(state);
        close(client_fd);
        return;
    }
    
    print_info("New admin connection registered (fd=%d)\n", client_fd);
}


/* ----------- main ----------- */

int main(int argc, const char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

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

    // === DIAGNÓSTICO DEL ERROR ===
    if (server_fd == -1) {
        // Si entra aquí, el problema NO es el selector, es que no pudiste abrir el puerto
        print_error("No se pudo crear el socket en el puerto %d. Error: %s\n", 
                listen_port, strerror(errno));
        
        // Pista común: Puerto ocupado
        if (errno == EADDRINUSE) {
            print_error("El puerto ya está en uso. ¿Tienes otro servidor corriendo?\n");
        }
        
        goto finally; // O return EXIT_FAILURE;
    }
    
    // CRÍTICO: Configurar socket como NO BLOQUEANTE para el selector
    if (selector_fd_set_nio(server_fd) == -1) {
        perror("selector_fd_set_nio");
        goto finally;
    }

    // 5. Inicializar Selector
    struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = { .tv_sec = 10, .tv_nsec = 0 }
    };
    selector_status st = SELECTOR_SUCCESS;
    fd_selector selector = NULL;
    
    create_selector_or_exit(&st, &selector);


    register_acceptor_or_exit( selector, server_fd);

    // 7. Bucle Principal (Event Loop)
    print_info("Admin API serving on port %d (Non-blocking mode)\n", listen_port);
    
    while (!done) {
        selector_status ss = selector_select(selector);

        if (ss != SELECTOR_SUCCESS) {
            // Verificamos si salimos por la señal (done = 1) antes de reportar error
            if (done) break; 
            
            fprintf(stderr, "[ERR] selector_select failed: %s\n", selector_error(ss));
            break;
        }
    }

destroy_selector:
    if (selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();

finally:
    if (server_fd >= 0) close(server_fd);
    args_destroy(&args, &API_CFG);
    
    print_info("Server shut down cleanly.\n");
    return 0;
}
