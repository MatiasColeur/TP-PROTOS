#include "../../include/errors.h"
#include "../../include/shared.h"
#include "../../include/api.h"
#include "../../include/client_utils.h"
#include "../../include/parser_arguments.h"

static const ArgParserConfig USER_MGMT_CFG = {
    .version_str = "Admin User Mgmt Client v1.0",
    .help_str =
        "Usage: %s [OPTIONS]\n"
        "  -l <SOCKS addr>  Dirección del proxy SOCKS (default: 127.0.0.1)\n"
        "  -p <SOCKS port>  Puerto del proxy SOCKS (default: 1080)\n"
        "  -L <API host>    Host de la API a conectar via CONNECT (default: ::1)\n"
        "  -P <API port>    Puerto de la API (default: 8080)\n"
        "  -h / -v          Ayuda o versión\n",

    .def_socks_addr = LOOPBACK_IPV4,
    .def_socks_port = 1080,

    .def_aux_addr = LOOPBACK_IPV6,
    .def_aux_port = ADMIN_API_PORT,

    .enable_aux        = true,
    .enable_users      = false,
    .enable_dissectors = false,
};

static void connect_to_api(int sockfd, const ProgramArgs *args) {
    struct in_addr  ipv4;
    struct in6_addr ipv6;

    if (inet_pton(AF_INET, args->aux_addr, &ipv4) == 1) {
        perform_request_ipv4(sockfd, args->aux_addr, args->aux_port);
        return;
    }

    if (inet_pton(AF_INET6, args->aux_addr, &ipv6) == 1) {
        perform_request_ipv6(sockfd, args->aux_addr, args->aux_port);
        return;
    }

    perform_request_domain(sockfd, args->aux_addr, args->aux_port);
}

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

int main(int argc, const char *argv[]) {
    ProgramArgs args;

    if (parse_arguments_ex(argc, argv, &args, &USER_MGMT_CFG) < 0) {
        return EXIT_FAILURE;
    }
    if (validate_arguments_ex(&args, &USER_MGMT_CFG) < 0) {
        args_destroy(&args, &USER_MGMT_CFG);
        return EXIT_FAILURE;
    }

    int sockfd = create_client_socket(args.socks_addr, args.socks_port);
    if (sockfd < 0) {
        args_destroy(&args, &USER_MGMT_CFG);
        return EXIT_FAILURE;
    }

    // 3. Handshake + Auth
    perform_handshake(sockfd, "admin", "admin");

    // 4. CONNECT a la Admin API
    connect_to_api(sockfd, &args);

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
    args_destroy(&args, &USER_MGMT_CFG);
    return EXIT_SUCCESS;
}
