#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

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
        "Options (choose one or more stats):\n"
        "  -H            Get historical connections\n"
        "  -C            Get concurrent connections\n"
        "  -B            Get bytes transferred\n"
        "  -U <user>     Get connections/log lines for <user>\n"
        "  -l <addr>     Address where the SOCKS proxy is listening (default: %s)\n"
        "  -p <port>     Port where the SOCKS proxy is listening (default: %u)\n"
        "  -A <addr>     Address where the Admin API is listening (default: %s)\n"
        "  -P <port>     Port where the Admin API is listening (default: %u)\n"
        "  -h            Help\n"
        "\n"
        "Examples:\n"
        "  %s -H\n"
        "  %s -C -B\n"
        "  %s -U admin -A ::1 -P 8080\n",
        prog, SOCKS_ADDR, (unsigned)SOCKS_PORT, API_ADDR, (unsigned)ADMIN_API_PORT, prog, prog, prog
    );
}

static int connect_api_via_socks(int sockfd, const char *api_addr, uint16_t api_port) {
    struct in6_addr v6;
    struct in_addr v4;

    if (inet_pton(AF_INET6, api_addr, &v6) == 1) {
        perform_request_ipv6(sockfd, api_addr, api_port);
        return 0;
    }
    if (inet_pton(AF_INET, api_addr, &v4) == 1) {
        perform_request_ipv4(sockfd, api_addr, api_port);
        return 0;
    }

    fprintf(stderr, "[ADMIN] Invalid API address: %s\n", api_addr);
    return -1;
}

int main(int argc, char *argv[]) {
    bool want_hist  = false;
    bool want_conc  = false;
    bool want_bytes = false;
    const char *user = NULL;
    const char *socks_addr = SOCKS_ADDR;
    uint16_t socks_port = SOCKS_PORT;
    const char *api_addr = API_ADDR;
    uint16_t api_port = API_PORT;

    int opt;
    while ((opt = getopt(argc, argv, "HCBU:hA:P:l:p:")) != -1) {
        switch (opt) {
            case 'H': want_hist = true; break;
            case 'C': want_conc = true; break;
            case 'B': want_bytes = true; break;
            case 'U': user = optarg; break;
            case 'l':
                socks_addr = optarg;
                break;
            case 'p': {
                int parsed = atoi(optarg);
                if (parsed <= 0 || parsed > 65535) {
                    fprintf(stderr, "[ADMIN] Invalid SOCKS port: %s\n", optarg);
                    return 1;
                }
                socks_port = (uint16_t) parsed;
                break;
            }
            case 'A': api_addr = optarg; break;
            case 'P': {
                int parsed = atoi(optarg);
                if (parsed <= 0 || parsed > 65535) {
                    fprintf(stderr, "[ADMIN] Invalid API port: %s\n", optarg);
                    return 1;
                }
                api_port = (uint16_t) parsed;
                break;
            }
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

    int sockfd = create_client_socket(socks_addr, (int)socks_port);
    if (sockfd < 0) {
        return 1;
    }

    perform_handshake(sockfd, "admin", "admin");

    // CONNECT a la API configurable
    if (connect_api_via_socks(sockfd, api_addr, api_port) < 0) {
        close(sockfd);
        return 1;
    }

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
