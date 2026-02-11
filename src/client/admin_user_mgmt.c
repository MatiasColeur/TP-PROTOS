#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "../../include/shared.h"
#include "../../include/api.h"
#include "../../include/client_utils.h"
#include "../../include/logger.h"

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
        "Usage: %s [OPTIONS] ACTION\n"
        "\n"
        "Options:\n"
        "  -l <addr>       Address where the SOCKS proxy is listening (default: %s)\n"
        "  -p <port>       Port where the SOCKS proxy is listening (default: %u)\n"
        "  -a <addr>       Address where the Admin API is listening (default: %s)\n"
        "  -P <port>       Port where the Admin API is listening (default: %u)\n"
        "\n"
        "Actions (choose exactly one):\n"
        "  -A <user> <role>          Add user (role: user|admin, password prompted)\n"
        "  -R <user> <role>          Set user role (role: user|admin)\n"
        "  -D <user>                 Delete user\n"
        "  -h                        Help\n"
        "\n"
        "Examples:\n"
        "  %s -A pepito user\n"
        "  %s -R juan admin\n"
        "  %s -D messi\n"
        "  %s -l 192.168.0.10 -p 1080 -a 192.168.0.20 -P 8080 -A pepito user\n",
        prog, SOCKS_ADDR, (unsigned)SOCKS_PORT, API_ADDR, (unsigned)API_PORT,
        prog, prog, prog, prog
    );
}

static bool prompt_password(char *out, size_t len) {
    if (out == NULL || len == 0) return false;

    struct termios original, raw;
    if (tcgetattr(STDIN_FILENO, &original) != 0) return false;
    raw = original;
    raw.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0) return false;

    char buffer[256] = {0};
    bool success = false;

    fprintf(stderr, "Password: ");
    fflush(stderr);

    if (fgets(buffer, sizeof buffer, stdin) != NULL) {
        size_t newline_pos = strcspn(buffer, "\n");
        if (buffer[newline_pos] == '\n') {
            buffer[newline_pos] = '\0';
        } else {
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF);
        }

        size_t copy_len = strlen(buffer);
        if (copy_len >= len) copy_len = len - 1;
        memcpy(out, buffer, copy_len);
        out[copy_len] = '\0';
        success = true;
    }

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
    fprintf(stderr, "\n");
    return success;
}

static bool role_is_valid(const char *role) {
    return role != NULL && (strcmp(role, "user") == 0 || strcmp(role, "admin") == 0);
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

    print_error("Invalid API address: %s", api_addr);
    return -1;
}

/* Wrapper: ADD_USER "username password role" */
static void admin_add_user(int sockfd, uint32_t *id_counter,
                           const char *user, const char *pass, const char *role) {
    char payload[256];
    int n = snprintf(payload, sizeof(payload), "%s %s %s\n", user, pass, role);
    if (n < 0 || (size_t)n >= sizeof(payload)) {
        print_error("Payload add_user too long\n");
        return;
    }
    admin_send_request(sockfd, (*id_counter)++, ADMIN_ADD_USER, payload);
}

/* Wrapper: SET_USER_ROLE "username role" */
static void admin_set_user_role(int sockfd, uint32_t *id_counter,
                                const char *user, const char *role) {
    char payload[256];
    int n = snprintf(payload, sizeof(payload), "%s %s\n", user, role);
    if (n < 0 || (size_t)n >= sizeof(payload)) {
        print_error("Payload set_user_role too long\n");
        return;
    }
    admin_send_request(sockfd, (*id_counter)++, ADMIN_SET_USER_ROLE, payload);
}

/* Wrapper: DELETE_USER "username" */
static void admin_delete_user(int sockfd, uint32_t *id_counter, const char *user) {
    char payload[256];
    int n = snprintf(payload, sizeof(payload), "%s\n", user);
    if (n < 0 || (size_t)n >= sizeof(payload)) {
        print_error("Payload delete_user too long\n");
        return;
    }
    print_info("LLEGO: admin delete user: ", ADMIN_DELETE_USER);
    admin_send_request(sockfd, (*id_counter)++, ADMIN_DELETE_USER, payload);
}

static void admin_quit(int sockfd, uint32_t *id_counter) {
    admin_send_request(sockfd, (*id_counter)++, ADMIN_QUIT, NULL);
}

int main(int argc, char *argv[]) {
    enum { ACT_NONE, ACT_ADD, ACT_ROLE, ACT_DEL } act = ACT_NONE;

    const char *socks_addr = SOCKS_ADDR;
    uint16_t socks_port = SOCKS_PORT;
    const char *api_addr = API_ADDR;
    uint16_t api_port = API_PORT;

    const char *add_user = NULL, *add_pass = NULL, *add_role = NULL;
    char add_pass_buf[128] = {0};
    const char *role_user = NULL, *role_role = NULL;
    const char *del_user = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "A:R:D:hl:p:a:P:")) != -1) {
        switch (opt) {
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
            case 'a':
                api_addr = optarg;
                break;
            case 'P': {
                int parsed = atoi(optarg);
                if (parsed <= 0 || parsed > 65535) {
                    fprintf(stderr, "[ADMIN] Invalid API port: %s\n", optarg);
                    return 1;
                }
                api_port = (uint16_t) parsed;
                break;
            }
            case 'A': {
                // -A consumes 2 args: user role; password read interactively
                act = ACT_ADD;
                add_user = optarg;
                if (optind >= argc) { usage(argv[0]); return 1; }
                add_role = argv[optind++];
                break;
            }
            case 'R': {
                // -R consumes 2 args: user role
                act = ACT_ROLE;
                role_user = optarg;
                if (optind >= argc) { usage(argv[0]); return 1; }
                role_role = argv[optind++];
                break;
            }
            case 'D': {
                // -D consumes 1 arg: user
                act = ACT_DEL;
                del_user = optarg;
                break;
            }
            case 'h':
            default:
                usage(argv[0]);
                return (opt == 'h') ? 0 : 1;
        }
    }

    // exactamente una acción
    if (act == ACT_NONE) {
        usage(argv[0]);
        return 1;
    }

    if (act == ACT_ADD) {
        if (add_user == NULL || add_role == NULL || !role_is_valid(add_role)) {
            print_error("Invalid -A args. role must be user|admin\n");
            return 1;
        }
        if (!prompt_password(add_pass_buf, sizeof add_pass_buf)) {
            print_error("No password provided\n");
            return 1;
        }
        add_pass = add_pass_buf;
    } else if (act == ACT_ROLE) {
        if (role_user == NULL || role_role == NULL || !role_is_valid(role_role)) {
            print_error("Invalid -R args. role must be user|admin\n");
            return 1;
        }
    } else if (act == ACT_DEL) {
        if (del_user == NULL) {
            print_error("Invalid -D args\n");
            return 1;
        }
    }

    int sockfd = create_client_socket(socks_addr, (int)socks_port);
    if (sockfd < 0) return 1;

    perform_handshake(sockfd, "admin", "admin");
    if (connect_api_via_socks(sockfd, api_addr, api_port) < 0) {
        close(sockfd);
        return 1;
    }

    uint32_t req_id = 1;

    if (act == ACT_ADD) {
        admin_add_user(sockfd, &req_id, add_user, add_pass, add_role);
        memset(add_pass_buf, 0, sizeof add_pass_buf);
    } else if (act == ACT_ROLE) {
        admin_set_user_role(sockfd, &req_id, role_user, role_role);
    } else if (act == ACT_DEL) {
        admin_delete_user(sockfd, &req_id, del_user);
    }

    admin_quit(sockfd, &req_id);

    close(sockfd);
    return 0;
}
