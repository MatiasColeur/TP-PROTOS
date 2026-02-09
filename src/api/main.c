#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../../include/api_service.h"          
#include "../../include/user_mgmt.h"
#include "../../include/shared.h"
#include "../../include/metrics.h"
#include "../../include/api.h"
#include "../../include/socks5.h"
#include "../../include/auth.h"
#include "../../include/parser_arguments.h"
#include "../../include/util.h"
#include "../../include/selector.h"

#define BACKLOG 5

static volatile sig_atomic_t done = 0;

static void sigterm_handler(const int signal) {
    printf("[INF] Signal %d received, cleaning up and exiting...\n", signal);
    done = 1;
}

static const ArgParserConfig API_CFG = {
    .version_str = "Admin API v1.0",
    .help_str =
        "Usage: %s [OPTIONS]\n"
        "\n"
        "Options:\n"
        "  -h             Imprime esta ayuda / termina.\n"
        "  -v             Imprime la versión y termina.\n"
        "  -l <addr>      Escucha con la dirección indicada (IPv6 preferido).\n"
        "                 Por defecto ::1 (loopback IPv6).\n"
        "  -p <port>      Puerto TCP donde se expone la API (default: 8080).\n",
    .def_socks_addr = LOOPBACK_IPV6,
    .def_socks_port = ADMIN_API_PORT,
    .def_aux_addr = NULL, .def_aux_port = 0,
    .enable_aux = false, .enable_users = false, .enable_dissectors = false,
};

static int create_server_socket(const char *listen_addr, uint16_t port) {
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port   = htons(port);

    if (inet_pton(AF_INET6, listen_addr, &addr.sin6_addr) != 1) {
        // Fallback a mapeo IPv4 si falla IPv6 puro
        struct in_addr v4;
        if (inet_pton(AF_INET, listen_addr, &v4) == 1) {
             addr.sin6_addr = in6addr_any;
             addr.sin6_addr.s6_addr[10] = 0xff;
             addr.sin6_addr.s6_addr[11] = 0xff;
             memcpy(&addr.sin6_addr.s6_addr[12], &v4, 4);
        } else {
            close(fd); return -1;
        }
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    if (listen(fd, BACKLOG) < 0) { close(fd); return -1; }
    
    return fd;
}

int main(int argc, const char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    ProgramArgs args;
    if (parse_arguments_ex(argc, argv, &args, &API_CFG) < 0) return EXIT_FAILURE;
    if (validate_arguments_ex(&args, &API_CFG) < 0) { args_destroy(&args, &API_CFG); return EXIT_FAILURE; }

    if (!user_store_load(USER_DB_PATH)) {
        print_error("Failed to load user database");
        args_destroy(&args, &API_CFG);
        return EXIT_FAILURE;
    }

    int server_fd = create_server_socket(args.socks_addr, args.socks_port);
    if (server_fd == -1) {
        print_error("Cannot bind to %s:%d (Check if port is used)", args.socks_addr, args.socks_port);
        goto finally;
    }

    if (selector_fd_set_nio(server_fd) == -1) goto finally;

    struct selector_init conf = { .signal = SIGALRM, .select_timeout = { .tv_sec = 10, .tv_nsec = 0 } };
    selector_status ss = selector_init(&conf);
    if (ss != SELECTOR_SUCCESS) goto finally;

    fd_selector selector = selector_new(1024);
    if (!selector) goto finally;

    // Aquí usamos el handler que importamos de api_service.h
    ss = selector_register(selector, server_fd, &api_passive_handler, OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) goto destroy_selector;

    print_info("Admin API serving on port %d (Non-blocking)", args.socks_port);

    while (!done) {
        ss = selector_select(selector);
        if (ss != SELECTOR_SUCCESS) {
            if (done) break;
            print_error("selector_select failed: %s", selector_error(ss));
            break;
        }
    }

destroy_selector:
    if (selector) selector_destroy(selector);
    selector_close();

finally:
    if (server_fd >= 0) close(server_fd);
    args_destroy(&args, &API_CFG);
    print_info("Server shut down cleanly.");
    return 0;
}
