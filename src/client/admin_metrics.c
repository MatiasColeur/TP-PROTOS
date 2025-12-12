#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../../include/shared.h"
#include "../../include/api.h"
#include "../../include/client_utils.h"
#include "../../include/parser_arguments.h"

static const ArgParserConfig METRICS_CFG = {
    .version_str = "Admin Metrics Client v1.0",
    .help_str =
        "Usage: %s [OPTIONS] [username_for_logs]\n"
        "  -l <SOCKS addr>  Dirección del proxy SOCKS (default: 127.0.0.1)\n"
        "  -p <SOCKS port>  Puerto del proxy SOCKS (default: 1080)\n"
        "  -L <API host>    Host de la API a conectar via CONNECT (default: ::1)\n"
        "  -P <API port>    Puerto de la API (default: 8080)\n"
        "  -h / -v          Ayuda o versión\n",

    .def_socks_addr = LOOPBACK_IPV4,
    .def_socks_port = 1080,

    .def_aux_addr = LOOPBACK_IPV6,
    .def_aux_port = ADMIN_API_PORT,

    .enable_aux        = true,   /* -L/-P para destino de la API */
    .enable_users      = false,  /* no se usan en el cliente */
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

/* -------- main -------- */

int main(int argc, const char *argv[]) {
    ProgramArgs args;

    if (parse_arguments_ex(argc, argv, &args, &METRICS_CFG) < 0) {
        return EXIT_FAILURE;
    }

    const char *user_for_logs = "admin";
    if (optind < argc) {
        user_for_logs = argv[optind];
    }

    if (validate_arguments_ex(&args, &METRICS_CFG) < 0) {
        args_destroy(&args, &METRICS_CFG);
        return EXIT_FAILURE;
    }

    int sockfd = create_client_socket(args.socks_addr, args.socks_port);
    if (sockfd < 0) {
        args_destroy(&args, &METRICS_CFG);
        return EXIT_FAILURE;
    }

    perform_handshake(sockfd, "admin", "admin");
    connect_to_api(sockfd, &args);

    uint32_t id = 1;

    /* a) Conexiones históricas */
    admin_send_request(sockfd, id++, ADMIN_GET_HIST_CONN, NULL);

    /* b) Conexiones concurrentes */
    admin_send_request(sockfd, id++, ADMIN_GET_CONCURRENT_CONN, NULL);

    /* c) Bytes transferidos */
    admin_send_request(sockfd, id++, ADMIN_GET_BYTES_TRANSFERRED, NULL);

    /* d) Conexiones de un usuario (líneas de log) */
    char body[256];
    int len = snprintf(body, sizeof(body), "%s\n", user_for_logs);
    if (len < 0 || len >= (int)sizeof(body)) {
        fprintf(stderr, "[ADMIN] Username too long\n");
    } else {
        admin_send_request(sockfd, id++, ADMIN_GET_USER_CONNECTIONS, body);
    }

    /* QUIT para cerrar prolijo del lado de la API */
    admin_send_request(sockfd, id++, ADMIN_QUIT, NULL);

    close(sockfd);
    args_destroy(&args, &METRICS_CFG);
    return 0;
}
