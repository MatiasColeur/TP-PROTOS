#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "../../include/shared.h"
#include "../../include/api.h"
#include "../../include/client_utils.h"

/*
 * Fijos (sin CLI):
 *  - SOCKS: 127.0.0.1:1080
 *  - API:   [::1]:8080
 *  - Credenciales: admin/admin
 */
#define SOCKS_ADDR LOOPBACK_IPV4
#define SOCKS_PORT 1080

#define API_ADDR   LOOPBACK_IPV6   // "::1"
#define API_PORT   ADMIN_API_PORT  // 8080

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "Options (choose one or more):\n"
        "  -H            Get historical connections\n"
        "  -C            Get concurrent connections\n"
        "  -B            Get bytes transferred\n"
        "  -U <user>     Get connections/log lines for <user>\n"
        "  -h            Help\n"
        "\n"
        "Examples:\n"
        "  %s -H\n"
        "  %s -C -B\n"
        "  %s -U admin\n",
        prog, prog, prog, prog
    );
}

int main(int argc, char *argv[]) {
    bool want_hist  = false;
    bool want_conc  = false;
    bool want_bytes = false;
    const char *user = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "HCBU:h")) != -1) {
        switch (opt) {
            case 'H': want_hist = true; break;
            case 'C': want_conc = true; break;
            case 'B': want_bytes = true; break;
            case 'U': user = optarg; break;
            case 'h':
            default:
                usage(argv[0]);
                return (opt == 'h') ? 0 : 1;
        }
    }

    if (!want_hist && !want_conc && !want_bytes && user == NULL) {
        usage(argv[0]);
        return 1;
    }

    int sockfd = create_client_socket(SOCKS_ADDR, SOCKS_PORT);
    if (sockfd < 0) {
        return 1;
    }

    perform_handshake(sockfd, "admin", "admin");

    // CONNECT a la API fija via IPv6 literal
    perform_request_ipv6(sockfd, API_ADDR, API_PORT);

    uint32_t id = 1;

    if (want_hist) {
        admin_send_request(sockfd, id++, ADMIN_GET_HIST_CONN, NULL);
    }
    if (want_conc) {
        admin_send_request(sockfd, id++, ADMIN_GET_CONCURRENT_CONN, NULL);
    }
    if (want_bytes) {
        admin_send_request(sockfd, id++, ADMIN_GET_BYTES_TRANSFERRED, NULL);
    }
    if (user != NULL) {
        char body[256];
        int len = snprintf(body, sizeof(body), "%s\n", user);
        if (len < 0 || len >= (int)sizeof(body)) {
            fprintf(stderr, "[ADMIN] Username too long\n");
        } else {
            admin_send_request(sockfd, id++, ADMIN_GET_USER_CONNECTIONS, body);
        }
    }

    admin_send_request(sockfd, id++, ADMIN_QUIT, NULL);

    close(sockfd);
    return 0;
}
