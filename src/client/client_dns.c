#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../include/shared.h"
#include "../../include/api.h"
#include "../../include/client_utils.h"
#include "../../include/parser_arguments.h"

static const ArgParserConfig CLIENT_DNS_CFG = {
    .version_str = "SOCKS5 Demo Client DNS v1.0",
    .help_str =
        "Usage: %s [OPTIONS]\n"
        "  -l <SOCKS addr>  Dirección del proxy SOCKS (default: 127.0.0.1)\n"
        "  -p <SOCKS port>  Puerto del proxy SOCKS (default: 1080)\n"
        "  -L <dest host>   Host destino (default: google.com)\n"
        "  -P <dest port>   Puerto destino (default: 80)\n"
        "  -h / -v          Ayuda o versión\n",

    .def_socks_addr = "127.0.0.1",
    .def_socks_port = 1080,

    .def_aux_addr = "google.com",
    .def_aux_port = 80,

    .enable_aux        = true,
    .enable_users      = false,
    .enable_dissectors = false,
};

int main(int argc, const char *argv[]) {
    ProgramArgs args;
    if (parse_arguments_ex(argc, argv, &args, &CLIENT_DNS_CFG) < 0) {
        return EXIT_FAILURE;
    }
    if (validate_arguments_ex(&args, &CLIENT_DNS_CFG) < 0) {
        args_destroy(&args, &CLIENT_DNS_CFG);
        return EXIT_FAILURE;
    }

    int sockfd = create_client_socket(args.socks_addr, args.socks_port);
    if (sockfd < 0) {
        args_destroy(&args, &CLIENT_DNS_CFG);
        return EXIT_FAILURE;
    }

    perform_handshake(sockfd, "admin", "admin");
    perform_request_domain(sockfd, args.aux_addr, args.aux_port);
    test_tunnel(sockfd);

    close(sockfd);
    args_destroy(&args, &CLIENT_DNS_CFG);
    return EXIT_SUCCESS;
}
