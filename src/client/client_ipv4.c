#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "../../include/shared.h"
#include "../../include/api.h"
#include "../../include/client_utils.h"
#include "../../include/parser_arguments.h"

static const ArgParserConfig CLIENT_IPV4_CFG = {
    .version_str = "SOCKS5 Demo Client IPv4 v1.0",
    .help_str =
        "Usage: %s [OPTIONS]\n"
        "  -l <SOCKS addr>  Dirección del proxy SOCKS (default: 127.0.0.1)\n"
        "  -p <SOCKS port>  Puerto del proxy SOCKS (default: 1080)\n"
        "  -L <dst IPv4>    Destino IPv4 para CONNECT (default: 142.250.190.14)\n"
        "  -P <dst port>    Puerto destino (default: 80)\n"
        "  -h / -v          Ayuda o versión\n",

    .def_socks_addr = "127.0.0.1",
    .def_socks_port = 1080,

    .def_aux_addr = "142.251.129.14",
    .def_aux_port = 80,

    .enable_aux        = true,
    .enable_users      = false,
    .enable_dissectors = false,
};

static int validate_ipv4_addr(const char *addr) {
    struct in_addr ipv4;
    return inet_pton(AF_INET, addr, &ipv4) == 1;
}

int main(int argc, const char *argv[]) {
    ProgramArgs args;
    if (parse_arguments_ex(argc, argv, &args, &CLIENT_IPV4_CFG) < 0) {
        return EXIT_FAILURE;
    }
    if (!validate_ipv4_addr(args.aux_addr)) {
        fprintf(stderr, "Destino IPv4 inválido: %s\n", args.aux_addr);
        args_destroy(&args, &CLIENT_IPV4_CFG);
        return EXIT_FAILURE;
    }
    if (validate_arguments_ex(&args, &CLIENT_IPV4_CFG) < 0) {
        args_destroy(&args, &CLIENT_IPV4_CFG);
        return EXIT_FAILURE;
    }

    int sockfd = create_client_socket(args.socks_addr, args.socks_port);
    if (sockfd < 0) {
        args_destroy(&args, &CLIENT_IPV4_CFG);
        return EXIT_FAILURE;
    }

    perform_handshake(sockfd, "admin", "admin");
    perform_request_ipv4(sockfd, args.aux_addr, args.aux_port);
    test_tunnel(sockfd);

    close(sockfd);
    args_destroy(&args, &CLIENT_IPV4_CFG);
    return EXIT_SUCCESS;
}
