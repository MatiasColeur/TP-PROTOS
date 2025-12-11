#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "../../include/parser_arguments.h"
#include "../../include/errors.h"

static void version(void) {
    fprintf(stderr, "SOCKS5 Proxy Server v1.0\n");
    exit(0);
}

void print_help(const char *progname) {
    fprintf(stderr,
        "Usage: %s [OPTIONS]...\n"
        "\n"
        "   -h               Imprime la ayuda y termina.\n"
        "   -l <SOCKS addr>  Dirección donde servirá el proxy SOCKS.\n"
        "                    Por defecto escucha en todas las interfaces (0.0.0.0).\n"
        "   -N               Deshabilita los passwords disectors.\n"
        "   -L <MNG addr>    Dirección donde servirá el servicio de management.\n"
        "                    Por defecto escucha únicamente en loopback (127.0.0.1).\n"
        "   -p <SOCKS port>  Puerto TCP conexiones entrantes SOCKS.\n"
        "                    Por defecto el valor es 1080.\n"
        "   -P <MNG port>    Puerto conexiones entrantes configuración.\n"
        "                    Por defecto el valor es 8080.\n"
        "   -u <user:pass>   Declara un usuario del proxy con su contraseña.\n"
        "                    Se puede utilizar hasta 10 veces.\n"
        "   -v               Imprime información sobre la versión y termina.\n"
        "\n",
        progname);
    exit(0);
}

/**
 * Parsea el string "user:pass" y lo guarda en la estructura.
 */
static void handle_user(const char *progname, char *arg, ProgramArgs *args) {
    if (args->user_count >= MAX_USERS) {
        fprintf(stderr, "%s: Ha excedido el límite de %d usuarios.\n", progname, MAX_USERS);
        exit(1);
    }

    char *p = strchr(arg, ':');
    if (p == NULL) {
        fprintf(stderr, "%s: Formato de usuario inválido '%s'. Debe ser user:pass\n", progname, arg);
        exit(1);
    }

    *p = '\0'; // Separa el string en dos
    args->users[args->user_count].name = arg;
    args->users[args->user_count].pass = p + 1;
    args->user_count++;
}

void parse_arguments(int argc, const char* argv[], ProgramArgs *args) {
    // 1. Valores por defecto
    args->socks_addr      = "127.0.0.1";
    args->socks_port      = 1080;
    
    args->mng_addr        = "::1";
    args->mng_port        = 8080;
    
    args->disectors_enabled = true; // Por defecto habilitados
    args->user_count      = 0;

    int opt;
    // hl:NL:p:P:u:v
    // : indica que la opción requiere un argumento
    while ((opt = getopt(argc, (char *const *) argv, "hl:NL:p:P:u:v")) != -1) {
        switch (opt) {
            case 'h':
                print_help(argv[0]);
                break;
            case 'l':
                args->socks_addr = optarg;
                break;
            case 'N':
                args->disectors_enabled = false;
                break;
            case 'L':
                args->mng_addr = optarg;
                break;
            case 'p':
                args->socks_port = atoi(optarg);
                break;
            case 'P':
                args->mng_port = atoi(optarg);
                break;
            case 'u':
                handle_user(argv[0], optarg, args);
                break;
            case 'v':
                version();
                break;
            default:
                fprintf(stderr, "Opción desconocida '%c'\n", opt);
                print_help(argv[0]);
        }
    }
}

int validate_arguments(const ProgramArgs *args) {
    if (args == NULL) {
        print_error("There are no arguments to validate.");
        return -1;
    }

    // 1. Validar SOCKS (-p y -l)
    if (args->socks_port <= 0 || args->socks_port > 65535) {
        print_error("Invalid SOCKS Port (%d). Must be between 1 and 65535.", args->socks_port);
        return -1;
    }

    if (args->socks_addr == NULL || strlen(args->socks_addr) == 0) {
        print_error("SOCKS Address is null or empty.");
        return -1;
    }

    // 2. Validar Management (-P y -L)
    if (args->mng_port <= 0 || args->mng_port > 65535) {
        print_error("Invalid Management Port (%d). Must be between 1 and 65535.", args->mng_port);
        return -1;
    }

    // Validación extra: No permitir el mismo puerto para ambos servicios
    if (args->socks_port == args->mng_port) {
        print_error("SOCKS port and Management port cannot be the same (%d).", args->socks_port);
        return -1;
    }

    if (args->mng_addr == NULL || strlen(args->mng_addr) == 0) {
        print_error("Management Address is null or empty.");
        return -1;
    }

    // 3. Validar Usuarios (-u)
    // El límite se chequea en parse_args, pero validamos integridad aquí
    if (args->user_count < 0 || args->user_count > MAX_USERS) {
        print_error("Invalid user count (%d). Max allowed is %d.", args->user_count, MAX_USERS);
        return -1;
    }

    // Opcional: Validar que los usuarios cargados no tengan campos vacíos
    for (int i = 0; i < args->user_count; i++) {
        if (args->users[i].name == NULL || strlen(args->users[i].name) == 0 ||
            args->users[i].pass == NULL || strlen(args->users[i].pass) == 0) {
            print_error("User #%d has empty username or password.", i + 1);
            return -1;
        }
    }

    return 0; // OK
}
