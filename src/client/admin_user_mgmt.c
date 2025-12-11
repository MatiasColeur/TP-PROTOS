#include "../../include/errors.h"
#include "../../include/shared.h"

#define SERVER_IP   "127.0.0.1"
#define SERVER_PORT 1080
#define BUFFER_SIZE 512

/* ==================== Protocolo Admin API ==================== */

struct admin_req_header {
    uint32_t id;   // network order
    uint8_t  cmd;  // enum admin_cmd
    uint16_t len;  // network order
} __attribute__((packed));

struct admin_resp_header {
    uint32_t id;     // network order
    uint8_t  status; // 0 = OK, !=0 error
    uint16_t len;    // network order
} __attribute__((packed));

enum admin_cmd {
    ADMIN_GET_CONCURRENT_CONN   = 0x01,
    ADMIN_GET_HIST_CONN         = 0x02,
    ADMIN_GET_BYTES_TRANSFERRED = 0x03,

    ADMIN_SET_USER_ROLE         = 0x10,
    ADMIN_ADD_USER              = 0x11,
    ADMIN_DELETE_USER           = 0x12,

    ADMIN_GET_USER_CONNECTIONS  = 0x20,

    ADMIN_QUIT                  = 0xFF,
};

/* ==================== Handshake SOCKS5 (tu código) ==================== */

void perform_handshake(int sockfd) {
    char buf[BUFFER_SIZE];

    // 1. Hello
    print_info("Enviando Hello...\n");
    char hello[] = { 0x05, 0x01, 0x02 }; // VER=5, NMETHODS=1, METHOD=0x02 (User/Pass)
    if (send(sockfd, hello, sizeof(hello), 0) < 0) {
        print_error("Error sending Hello");
        exit(1);
    }

    // 2. Reply
    ssize_t n = recv(sockfd, buf, BUFFER_SIZE, 0);
    if (n < 2 || buf[1] != 0x02) {
        fprintf(stderr, "Error: servidor no aceptó Auth User/Pass. Recibido: %02x\n", (unsigned char)buf[1]);
        exit(1);
    }

    // 3. Subnegociación RFC1929
    char username[] = "admin";
    char password[] = "admin";

    char auth_req[512];
    int idx = 0;
    auth_req[idx++] = 0x01;                 // Versión subnegociación
    auth_req[idx++] = strlen(username);
    memcpy(&auth_req[idx], username, strlen(username));
    idx += strlen(username);
    auth_req[idx++] = strlen(password);
    memcpy(&auth_req[idx], password, strlen(password));
    idx += strlen(password);

    if (send(sockfd, auth_req, idx, 0) < 0) {
        print_error("Error sending auth");
        exit(1);
    }

    // 4. Respuesta
    n = recv(sockfd, buf, BUFFER_SIZE, 0);
    if (n >= 2 && buf[1] == 0x00) {
        print_success("Authentication Completed");
    } else {
        print_error("Authentication Rejected");
        exit(1);
    }
}

static void verify_socks5_reply(int sockfd) {
    char buf[BUFFER_SIZE];
    ssize_t n = recv(sockfd, buf, BUFFER_SIZE, 0);

    if (n < 4) {
        print_error("Reply too short or connection closed");
        exit(1);
    }

    uint8_t rep = buf[1];

    if (rep == 0x00) {
        print_success("SOCKS5 Request Granted (Tunnel Established)");
    } else {
        const char *err_msg = "Unknown Error";
        switch (rep) {
            case 0x01: err_msg = "General Failure"; break;
            case 0x02: err_msg = "Connection not allowed"; break;
            case 0x03: err_msg = "Network Unreachable"; break;
            case 0x04: err_msg = "Host Unreachable"; break;
            case 0x05: err_msg = "Connection Refused"; break;
            case 0x06: err_msg = "TTL Expired"; break;
            case 0x07: err_msg = "Command not supported"; break;
            case 0x08: err_msg = "Address type not supported"; break;
        }
        fprintf(stderr, "[ERR] Server replied: 0x%02x (%s)\n", rep, err_msg);
        print_error("SOCKS5 Request Failed");
        exit(1);
    }
}

/* CONNECT a la API via IPv6 loopback (::1) */
void perform_request_ipv6(int sockfd, const char *ip6_str, int port) {
    char buf[BUFFER_SIZE];
    print_info("Enviando Request IPv6 CONNECT a [%s]:%d...\n", ip6_str, port);

    int idx = 0;
    buf[idx++] = 0x05; // VER
    buf[idx++] = 0x01; // CMD: CONNECT
    buf[idx++] = 0x00; // RSV
    buf[idx++] = 0x04; // ATYP: IPv6

    // Dirección IPv6 (16 bytes)
    if (inet_pton(AF_INET6, ip6_str, &buf[idx]) <= 0) {
        print_error("Invalid IPv6 address: %s", ip6_str);
        exit(1);
    }
    idx += 16;

    // Puerto
    uint16_t p = htons(port);
    memcpy(&buf[idx], &p, 2);
    idx += 2;

    if (send(sockfd, buf, idx, 0) < 0) {
        print_error("Failed sending request");
        exit(1);
    }

    verify_socks5_reply(sockfd);
}

/* ==================== Cliente Admin API ==================== */

/* Envía un comando admin genérico y muestra la respuesta */
static void admin_send_request(int sockfd,
                               uint32_t id,
                               uint8_t cmd,
                               const char *payload) {
    struct admin_req_header req;
    struct admin_resp_header resp;

    size_t payload_len = payload ? strlen(payload) : 0;
    if (payload_len > UINT16_MAX) {
        fprintf(stderr, "[ERR] Payload too large\n");
        return;
    }

    req.id  = htonl(id);
    req.cmd = cmd;
    req.len = htons((uint16_t)payload_len);

    // Enviar header
    if (!write_exact(sockfd, &req, sizeof(req))) {
        print_error("Error escribiendo header admin");
        exit(1);
    }

    // Enviar payload, si hay
    if (payload_len > 0) {
        if (!write_exact(sockfd, payload, payload_len)) {
            print_error("Error escribiendo payload admin");
            exit(1);
        }
    }

    // Leer header de respuesta
    if (!read_exact(sockfd, &resp, sizeof(resp))) {
        print_error("Error leyendo header de respuesta admin");
        exit(1);
    }

    uint32_t resp_id  = ntohl(resp.id);
    uint16_t resp_len = ntohs(resp.len);

    printf("[ADMIN] Resp id=%u status=%u len=%u\n",
           resp_id, resp.status, resp_len);

    // Leer payload de respuesta si lo hay
    if (resp_len > 0) {
        char buf[512];
        if (resp_len >= sizeof(buf)) {
            resp_len = sizeof(buf) - 1;
        }

        if (!read_exact(sockfd, buf, resp_len)) {
            print_error("Error leyendo payload de respuesta");
            exit(1);
        }
        buf[resp_len] = '\0';
        printf("[ADMIN] Payload: %s", buf);
        if (buf[resp_len-1] != '\n') {
            printf("\n");
        }
    }
}

/* Wrapper: ADD_USER "username password role" */
static void admin_add_user(int sockfd,
                           uint32_t *id_counter,
                           const char *user,
                           const char *pass,
                           const char *role) {
    char payload[256];
    int n = snprintf(payload, sizeof(payload), "%s %s %s\n", user, pass, role);
    if (n < 0 || (size_t)n >= sizeof(payload)) {
        fprintf(stderr, "[ERR] Payload add_user too long\n");
        return;
    }

    printf("\n[ADMIN] ADD_USER %s %s %s\n", user, pass, role);
    admin_send_request(sockfd, (*id_counter)++, ADMIN_ADD_USER, payload);
}

/* Wrapper: SET_USER_ROLE "username role" */
static void admin_set_user_role(int sockfd,
                                uint32_t *id_counter,
                                const char *user,
                                const char *role) {
    char payload[256];
    int n = snprintf(payload, sizeof(payload), "%s %s\n", user, role);
    if (n < 0 || (size_t)n >= sizeof(payload)) {
        fprintf(stderr, "[ERR] Payload set_user_role too long\n");
        return;
    }

    printf("\n[ADMIN] SET_USER_ROLE %s %s\n", user, role);
    admin_send_request(sockfd, (*id_counter)++, ADMIN_SET_USER_ROLE, payload);
}

/* Wrapper: DELETE_USER "username" */
static void admin_delete_user(int sockfd,
                              uint32_t *id_counter,
                              const char *user) {
    char payload[256];
    int n = snprintf(payload, sizeof(payload), "%s\n", user);
    if (n < 0 || (size_t)n >= sizeof(payload)) {
        fprintf(stderr, "[ERR] Payload delete_user too long\n");
        return;
    }

    printf("\n[ADMIN] DELETE_USER %s\n", user);
    admin_send_request(sockfd, (*id_counter)++, ADMIN_DELETE_USER, payload);
}

/* Opcional: QUIT */
static void admin_quit(int sockfd, uint32_t *id_counter) {
    printf("\n[ADMIN] QUIT\n");
    admin_send_request(sockfd, (*id_counter)++, ADMIN_QUIT, NULL);
}

/* ==================== main ==================== */

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    int sockfd;
    struct sockaddr_in serv_addr;

    // 1. Crear socket TCP hacia el proxy
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        print_error("Failed creating socket");
        return 1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        print_error("Invalid direction");
        return 1;
    }

    // 2. Conectar al servidor SOCKS5
    print_info("Conectando al Proxy SOCKS5 en %s:%d...\n", SERVER_IP, SERVER_PORT);
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        print_error("Connection Failed (Is the server running?)");
        return 1;
    }

    // 3. Handshake + Auth
    perform_handshake(sockfd);

    // 4. CONNECT a la Admin API: loopback IPv6 + puerto de la API
    perform_request_ipv6(sockfd, LOOPBACK_IPV6, ADMIN_API_PORT);

    // 5. Usar el túnel como cliente de la Admin API
    uint32_t req_id = 1;

    // a) Agregar usuario (password sin hash, como pediste)
    admin_add_user(sockfd, &req_id, "pepito", "1234", "user");

    // b) Cambiar rol de juan → admin
    admin_set_user_role(sockfd, &req_id, "juan", "admin");

    // c) Eliminar usuario messi
    admin_delete_user(sockfd, &req_id, "messi");

    // d) Cerrar sesión limpia en la API
    admin_quit(sockfd, &req_id);

    close(sockfd);
    return 0;
}