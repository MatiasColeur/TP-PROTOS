#include "../../include/errors.h"
#include "../../include/shared.h"
#include "../../include/api.h"
#include "../../include/client_utils.h"

#define SERVER_IP   "127.0.0.1"
#define SERVER_PORT 1080
#define BUFFER_SIZE 512

/* ==================== Handshake SOCKS5 (tu código) ==================== */

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
    perform_handshake(sockfd,"admin","admin");

    // 4. CONNECT a la Admin API: loopback IPv6 + puerto de la API
    perform_request_ipv6(sockfd, LOOPBACK_IPV6, ADMIN_API_PORT);

    // 5. Usar el túnel como cliente de la Admin API
    uint32_t req_id = 1;

    // a) Agregar usuario 
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
