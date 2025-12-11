#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "../../include/parser_arguments.h"
#include "../../include/errors.h"

static void usage(const char *progname) {
    fprintf(stderr,
        "Usage: %s [OPTIONS]...\n"
        "\n"
        "   -h <host>    SOCKS5 Proxy IP (Default: 127.0.0.1)\n"
        "   -p <port>    SOCKS5 Proxy Port (Default: 1080)\n"
        "   -t <target>  Target Host (Default: google.com)\n"
        "   -P <port>    Target Port (Default: 80)\n"
        "   -c <num>     Concurrency (Default: 1)\n"
        "\n",
        progname);
    exit(1);
}

void parse_args(int argc, char *argv[], ProgramArgs *args) {
    // Defaults para el cliente
    args->addr = "127.0.0.1"; // Proxy IP
    args->port = 1080;             // Proxy Port
    args->target_host = "google.com";
    args->target_port = 80;
    args->concurrency = 1;

    int opt;
    // Nota: 'h' ahora requiere argumento (host), 'P' mayuscula para target port
    while ((opt = getopt(argc, argv, "h:p:t:P:c:")) != -1) {
        switch (opt) {
            case 'h':
                args->addr = optarg; // Reusamos este campo para Proxy IP
                break;
            case 'p':
                args->port = atoi(optarg);
                break;
            case 't':
                args->target_host = optarg;
                break;
            case 'P':
                args->target_port = atoi(optarg);
                break;
            case 'c':
                args->concurrency = atoi(optarg);
                break;
            default:
                usage(argv[0]);
        }
    }
}

int validate_arguments(const ProgramArgs *args) {
    if (args == NULL) {
        print_error("There's not any arguments");

        return -1;
    }

    // 1. Validar Puerto de Escucha / Proxy
    if (args->port <= 0 || args->port > 65535) {
        print_error("Invalid Port (%d), must be between 1 and 65535.",args->port);
        return -1;
    }

    // 2. Validar Dirección de Binding / Proxy Host
    if (args->addr == NULL || strlen(args->addr) == 0) {
        print_error("Address null or empty");
        return -1;
    }

    // 3. Validaciones Específicas para Cliente/Stress Test
    // (Solo si estás usando la misma struct para el cliente)
    if (args->concurrency < 0) { // Asumimos 0 o 1 como mínimo
         fprintf(stderr, "[ARGS] Error: Concurrencia inválida (%d).\n", args->concurrency);
         print_error("Invalid Concurrency (%d)",args->concurrency);
         return -1;
    }

    if (args->target_port != 0) { // Si se seteó un target port
        if (args->target_port <= 0 || args->target_port > 65535) {
            print_error("Invalid remote port (%d)",args->target_port);
            return -1;
        }
    }

    return 0; // OK
}
