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

#define MAX_PENDING_CONNECTION_REQUESTS 5
#define SIMULTANEOUS_CONNECTIONS 10
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
    // Disable buffering on stdout and stderr
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    // Create the socket. We'll use IPv6 only, IPv6 has backwards compatibility with IPv4
    // so by using IPv6, we can also handle incoming IPv4 connections ;)
    int serverSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket < 0) {
        perror("[ERR] socket()");
        exit(EXIT_FAILURE);
    }

    if (selector_fd_set_nio(serverSocket) == -1) {
        perror("[ERR] selector_fd_set_nio(serverSocket)");
        exit(EXIT_FAILURE);
    }

    // We want to bind our socket on IPv6 listening on all available IP addresses on port SOURCE_PORT.
    struct sockaddr_in6 srcSocket;
    memset((char*)&srcSocket, 0, sizeof(srcSocket));
    srcSocket.sin6_family = AF_INET6;
    srcSocket.sin6_port = htons(SOURCE_PORT);
    memcpy(&srcSocket.sin6_addr, &in6addr_any, sizeof(in6addr_any));

    if (bind(serverSocket, (struct sockaddr*)&srcSocket, sizeof(srcSocket)) != 0) {
        perror("[ERR] bind()");
        exit(1);
    }

    if (listen(serverSocket, MAX_PENDING_CONNECTION_REQUESTS) != 0) {
        perror("[ERR] listen()");
        exit(1);
    }

    // Get the local address at which our socket was found, for nothing more than printing it out.
    struct sockaddr_storage boundAddress;
    socklen_t boundAddressLen = sizeof(boundAddress);
    if (getsockname(serverSocket, (struct sockaddr*)&boundAddress, &boundAddressLen) >= 0) {
        char addrBuffer[128];
        printSocketAddress((struct sockaddr*)&boundAddress, addrBuffer);
        printf("[INF] Binding to %s\n", addrBuffer);
    } else
        perror("[WRN] Failed to getsockname()");


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

    fd_selector selector = selector_new(SIMULTANEOUS_CONNECTIONS);
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
