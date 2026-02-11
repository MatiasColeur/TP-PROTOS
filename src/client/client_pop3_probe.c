#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../include/shared.h"
#include "../../include/client_utils.h"
#include "../../include/parser_arguments.h"
#include "../../include/errors.h"

/*
 * Cliente de prueba para POP3 en claro a través del proxy SOCKS5.
 * Envía USER/PASS y cierra. Sirve para disparar el dissector y verificar
 * que se registren credenciales en log/credentials.txt.
 *
 * Uso:
 *   ./bin/client_pop3_probe [OPCIONES] [<user> <pass>]
 *
 * Opciones (parser común):
 *   -l <SOCKS addr>  Dirección del proxy (default: 127.0.0.1)
 *   -p <SOCKS port>  Puerto del proxy (default: 1080)
 *   -L <dst host>    Host destino POP3 (default: 127.0.0.1)
 *   -P <dst port>    Puerto destino POP3 (default: 110)
 *   -h / -v          Ayuda o versión
 */
static const ArgParserConfig POP3_PROBE_CFG = {
    .version_str = "SOCKS5 POP3 Probe v1.0",
    .help_str =
        "Usage: %s [OPTIONS] [<user> <pass>]\n"
        "  -l <SOCKS addr>  Direccion del proxy SOCKS (default: 127.0.0.1)\n"
        "  -p <SOCKS port>  Puerto del proxy SOCKS (default: 1080)\n"
        "  -L <dest host>   Host destino POP3 (default: 127.0.0.1)\n"
        "  -P <dest port>   Puerto destino POP3 (default: 110)\n"
        "  -h / -v          Ayuda o version\n"
        "Posicionales opcionales: <user> <pass> (default: alice/secret)\n",

    .def_socks_addr = "127.0.0.1",
    .def_socks_port = 1080,

    .def_aux_addr = "127.0.0.1",
    .def_aux_port = 110,

    .enable_aux        = true,
    .enable_users      = false,
    .enable_dissectors = false,
};

static int send_line(int fd, const char *line) {
    size_t len = strlen(line);
    ssize_t n = send(fd, line, len, 0);
    return (n == (ssize_t)len) ? 0 : -1;
}

int main(int argc, const char *argv[]) {
    ProgramArgs args;
    const char *pop_user = "alice";
    const char *pop_pass = "secret";

    if (parse_arguments_ex(argc, argv, &args, &POP3_PROBE_CFG) < 0) {
        return EXIT_FAILURE;
    }

    if (optind < argc) {
        pop_user = argv[optind++];
    }
    if (optind < argc) {
        pop_pass = argv[optind++];
    }
    if (optind < argc) {
        fprintf(stderr, "Argumentos extra no reconocidos.\n");
        args_destroy(&args, &POP3_PROBE_CFG);
        return EXIT_FAILURE;
    }

    if (validate_arguments_ex(&args, &POP3_PROBE_CFG) < 0) {
        args_destroy(&args, &POP3_PROBE_CFG);
        return EXIT_FAILURE;
    }

    int sockfd = create_client_socket(args.socks_addr, args.socks_port);
    if (sockfd < 0) {
        args_destroy(&args, &POP3_PROBE_CFG);
        return EXIT_FAILURE;
    }

    perform_handshake(sockfd, "admin", "admin");
    perform_request_domain(sockfd, args.aux_addr, args.aux_port);

    char line[256];
    snprintf(line, sizeof(line), "USER %s\r\n", pop_user);
    if (send_line(sockfd, line) != 0) {
        print_error("No se pudo enviar USER");
        close(sockfd);
        args_destroy(&args, &POP3_PROBE_CFG);
        return EXIT_FAILURE;
    }

    snprintf(line, sizeof(line), "PASS %s\r\n", pop_pass);
    if (send_line(sockfd, line) != 0) {
        print_error("No se pudo enviar PASS");
        close(sockfd);
        args_destroy(&args, &POP3_PROBE_CFG);
        return EXIT_FAILURE;
    }

    print_success("Credenciales POP3 enviadas a traves del proxy");

    /* Sostener la conexion un rato para que el proxy tenga tiempo de responder y no se cierre el pipe */
    sleep(2);

    close(sockfd);
    args_destroy(&args, &POP3_PROBE_CFG);
    return EXIT_SUCCESS;
}
