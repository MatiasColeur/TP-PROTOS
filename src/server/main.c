// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>

#include "../../include/util.h"
#include "../../include/selector.h"
#include "../../include/logger.h"
#include "../../include/parser_arguments.h"
#include "../../include/bootstrap.h"
#include "../../include/socks5.h"

#define MAX_PENDING_CONNECTION_REQUESTS 128
#define MAX_SOCKETS 1024

/* ==================== Server Config ==================== */

static const ArgParserConfig SERVER_CFG = {
    .version_str = "SOCKS5 Proxy Server v1.0",
    .help_str =
        "Usage: %s [OPTIONS]...\n"
        "\n"
        "   -h               Imprime la ayuda y termina.\n"
        "   -l <SOCKS addr>  Dirección donde servirá el proxy SOCKS.\n"
        "                    Por defecto escucha en todas las interfaces (0.0.0.0).\n"
        "   -N               Deshabilita los password dissectors.\n"
        "   -L <MNG addr>    Dirección donde servirá el servicio de management.\n"
        "                    Por defecto escucha únicamente en loopback (::1).\n"
        "   -p <SOCKS port>  Puerto TCP conexiones entrantes SOCKS.\n"
        "                    Por defecto el valor es 1080.\n"
        "   -P <MNG port>    Puerto conexiones entrantes configuración.\n"
        "                    Por defecto el valor es 8080.\n"
        "   -u <user:pass>   Declara un usuario del proxy con su contraseña.\n"
        "                    Se puede utilizar hasta 10 veces.\n"
        "   -v               Imprime información sobre la versión y termina.\n"
        "\n",

    .def_socks_addr = "0.0.0.0",
    .def_socks_port = 1080,

    .def_aux_addr   = "::1",
    .def_aux_port   = 8080,

    .enable_aux        = true,  // -L/-P
    .enable_users      = true,  // -u
    .enable_dissectors = true,  // -N
};


/* ==================== Accept handler ==================== */

static void accept_handle_read(struct selector_key *key);
static void accept_handle_close(struct selector_key *key);

static const fd_handler accept_handler = {
    .handle_read  = accept_handle_read,
    .handle_write = NULL,
    .handle_block = NULL,
    .handle_close = accept_handle_close,
};

static void accept_handle_read(struct selector_key *key) {
    struct sockaddr_storage clientAddress;
    socklen_t clientAddressLen = sizeof(clientAddress);

    for (;;) {
        int client_fd = accept(key->fd, (struct sockaddr *)&clientAddress, &clientAddressLen);

        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            perror("[ERR] accept()");
            break;
        }

        if (selector_fd_set_nio(client_fd) == -1) {
            perror("[ERR] selector_fd_set_nio(client_fd)");
            close(client_fd);
            continue;
        }

        char addrBuffer[128];
        printSocketAddress((struct sockaddr*)&clientAddress, addrBuffer);
        printf("[INF] New connection from %s. Registered for fd %d\n", addrBuffer, client_fd);

        handle_new_client(key->s, client_fd);
    }
}

static void accept_handle_close(struct selector_key *key) {
    close(key->fd);
}

/* ==================== Helpers ==================== */

static void setup_stdio_unbuffered(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

static void print_listening_endpoints(const ProgramArgs *args) {
    print_info("SOCKS Listening on %s:%d", args->socks_addr, args->socks_port);
    print_info("Management API will be reached at %s:%d when required", args->aux_addr, args->aux_port);
}

static int create_listen_socket_ipv6_any(const uint16_t port) {
    int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        print_error("socket()");
        return -1;
    }

    if (selector_fd_set_nio(fd) == -1) {
        print_error("selector_fd_set_nio(serverSocket)");
        close(fd);
        return -1;
    }

    struct sockaddr_in6 srcSocket;
    memset(&srcSocket, 0, sizeof(srcSocket));
    srcSocket.sin6_family = AF_INET6;
    srcSocket.sin6_port   = htons(port);
    memcpy(&srcSocket.sin6_addr, &in6addr_any, sizeof(in6addr_any));

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (bind(fd, (struct sockaddr*)&srcSocket, sizeof(srcSocket)) != 0) {
        print_error("bind()");
        close(fd);
        return -1;
    }

    if (listen(fd, MAX_PENDING_CONNECTION_REQUESTS) != 0) {
        print_error("listen()");
        close(fd);
        return -1;
    }

    struct sockaddr_storage boundAddress;
    socklen_t boundAddressLen = sizeof(boundAddress);
    if (getsockname(fd, (struct sockaddr*)&boundAddress, &boundAddressLen) >= 0) {
        char addrBuffer[128];
        printSocketAddress((struct sockaddr*)&boundAddress, addrBuffer);
        print_info("Binding to %s\n", addrBuffer);
    } else {
        print_error("Failed to getsockname()");
    }

    return fd;
}

/**
 * Inicializa la librería selector + crea el selector.
 */
static void create_selector_or_exit(selector_status *st_out, fd_selector *selector_out) {
    struct selector_init init = {
        .signal = SIGUSR1,
        .select_timeout = {
            .tv_sec  = 5,
            .tv_nsec = 0,
        },
    };

    selector_status st = selector_init(&init);
    if (st != SELECTOR_SUCCESS) {
        fprintf(stderr, "selector_init error: %s\n", selector_error(st));
        exit(EXIT_FAILURE);
    }

    fd_selector sel = selector_new(MAX_SOCKETS);
    if (sel == NULL) {
        fprintf(stderr, "selector_new error\n");
        selector_close();
        exit(EXIT_FAILURE);
    }

    *st_out = st;
    *selector_out = sel;
}

static void register_acceptor_or_exit(fd_selector selector, int server_fd) {
    selector_status st = selector_register(selector, server_fd, &accept_handler, OP_READ, NULL);
    if (st != SELECTOR_SUCCESS) {
        fprintf(stderr, "selector_register(serverSocket) error: %s\n", selector_error(st));
        exit(EXIT_FAILURE);
    }
}

static void maybe_bootstrap_users_async(const ProgramArgs *args) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("[ERR] fork(), initial users creation skipped");
        return;
    }
    if (pid == 0) {
        sleep(1);
        bootstrap_cli_users_via_api(args);
        _exit(0);
    }
}

static void selector_loop(fd_selector selector) {
    for (;;) {
        selector_status st = selector_select(selector);
        if (st != SELECTOR_SUCCESS) {
            fprintf(stderr, "selector_select error: %s\n", selector_error(st));
            break;
        }
    }
}

/* ==================== main ==================== */


int main(int argc, const char* argv[]) {
    ProgramArgs args;

    if (parse_arguments_ex(argc, argv, &args, &SERVER_CFG) < 0) {
        return EXIT_FAILURE;
    }
    if (validate_arguments_ex(&args, &SERVER_CFG) < 0) {
        args_destroy(&args, &SERVER_CFG);
        return EXIT_FAILURE;
    }

    socks5_set_management_endpoint(args.aux_addr, (uint16_t) args.aux_port);

    setup_stdio_unbuffered();
    print_listening_endpoints(&args);

    int server_fd = create_listen_socket_ipv6_any((uint16_t) args.socks_port);
    
    int val = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
        close(server_fd);
        return EXIT_FAILURE;
    }

    if (server_fd < 0) {
        args_destroy(&args, &SERVER_CFG);
        return EXIT_FAILURE;
    }

    init_log();

    selector_status st = SELECTOR_SUCCESS;
    fd_selector selector = NULL;

    create_selector_or_exit(&st, &selector);
    register_acceptor_or_exit(selector, server_fd);

    maybe_bootstrap_users_async(&args);

    signal(SIGPIPE, SIG_IGN); // Ignore SIGPIPE

    selector_loop(selector);

    selector_destroy(selector);
    selector_close();
    close(server_fd);

    args_destroy(&args, &SERVER_CFG);
    return EXIT_SUCCESS;
}