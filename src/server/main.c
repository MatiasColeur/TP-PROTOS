// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>

#include "../../include/echo.h"
#include "../../include/util.h"
#include "../../include/selector.h"
#include "../../include/logger.h"
#include "../../include/parser_arguments.h"
#include "../../include/bootstrap.h"

#define MAX_PENDING_CONNECTION_REQUESTS 128
#define MAX_SOCKETS 1024
#define SOURCE_PORT 1080

static void accept_handle_read(struct selector_key *key);
static void accept_handle_close(struct selector_key *key);

static const fd_handler accept_handler = {
    .handle_read  = accept_handle_read,
    .handle_write = NULL,
    .handle_block = NULL,
    .handle_close = accept_handle_close,
};

int main(int argc, const char* argv[]) {
    ProgramArgs args;
    parse_arguments(argc, argv, &args);

    // Configuración del Servidor SOCKS
    print_info("SOCKS Listening on %s:%d", args.socks_addr, args.socks_port);
    
    // Configuración del Servidor Management
    print_info("Management Listening on %s:%d", args.mng_addr, args.mng_port);

    if (args.disectors_enabled) {
        print_info("[Password Disectors: ENABLED");
    } else {
        print_info("Password Disectors: DISABLED");
    }

    // Registro de usuarios pasados por parámetro (si aplica a tu lógica)
    for(int i=0; i < args.user_count; i++) {
        // auth_register_user(args.users[i].name, args.users[i].pass);
        print_info("User registered: %s:%s", args.users[i].name,args.users[i].pass);
    }

    // Disable buffering on stdout and stderr
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    // Create the socket. We'll use IPv6 only, IPv6 has backwards compatibility with IPv4
    // so by using IPv6, we can also handle incoming IPv4 connections ;)
    int serverSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket < 0) {
        print_error("socket()");
        exit(EXIT_FAILURE);
    }

    if (selector_fd_set_nio(serverSocket) == -1) {
        print_error("selector_fd_set_nio(serverSocket)");
        exit(EXIT_FAILURE);
    }

    // We want to bind our socket on IPv6 listening on all available IP addresses on port SOURCE_PORT.
    struct sockaddr_in6 srcSocket;
    memset((char*)&srcSocket, 0, sizeof(srcSocket));
    srcSocket.sin6_family = AF_INET6;
    srcSocket.sin6_port = htons(args.socks_port);
    memcpy(&srcSocket.sin6_addr, &in6addr_any, sizeof(in6addr_any));

    if (bind(serverSocket, (struct sockaddr*)&srcSocket, sizeof(srcSocket)) != 0) {
        print_error("bind()");
        exit(1);
    }

    if (listen(serverSocket, MAX_PENDING_CONNECTION_REQUESTS) != 0) {
        print_error("listen()");
        exit(1);
    }

    // Get the local address at which our socket was found, for nothing more than printing it out.
    struct sockaddr_storage boundAddress;
    socklen_t boundAddressLen = sizeof(boundAddress);
    if (getsockname(serverSocket, (struct sockaddr*)&boundAddress, &boundAddressLen) >= 0) {
        char addrBuffer[128];
        printSocketAddress((struct sockaddr*)&boundAddress, addrBuffer);
        print_info("Binding to %s\n", addrBuffer);
    } else
        print_error("Failed to getsockname()");


    // logger initialization
    init_log();


    // Selector initialization
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
        return EXIT_FAILURE;
    }

    fd_selector selector = selector_new(MAX_SOCKETS);
    if (selector == NULL) {
        fprintf(stderr, "selector_new error\n");
        selector_close();
        return EXIT_FAILURE;
    }

    st = selector_register(selector, serverSocket, &accept_handler, OP_READ, NULL);

    if (st != SELECTOR_SUCCESS) {
        fprintf(stderr, "selector_register(serverSocket) error: %s\n", selector_error(st));
        close(serverSocket);
        selector_destroy(selector);
        selector_close();
        return EXIT_FAILURE;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("[ERR] fork(), initial users creation skipped");
        // si falla, seguís sin bootstrap pero el server vive
    } else if (pid == 0) {
        sleep(1);
        bootstrap_cli_users_via_api(&args);
        _exit(0);
    }


    // Handle incomming connections
    for (;;) {
        st = selector_select(selector);
        if (st != SELECTOR_SUCCESS) {
            fprintf(stderr, "selector_select error: %s\n", selector_error(st));
            break;
        }
    }
    
    // Cleanup
    selector_destroy(selector);
    selector_close();
    close(serverSocket);
    return EXIT_SUCCESS;
}

static void accept_handle_read(struct selector_key *key) {
    struct sockaddr_storage clientAddress;
    socklen_t clientAddressLen = sizeof(clientAddress);

    for (;;) {
        int client_fd = accept(key->fd,
                               (struct sockaddr *)&clientAddress,
                               &clientAddressLen);

        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
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
