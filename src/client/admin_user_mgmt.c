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
        "Usage: %s ACTION\n"
        "\n"
        "Actions (choose exactly one):\n"
        "  -A <user> <pass> <role>   Add user (role: user|admin)\n"
        "  -R <user> <role>          Set user role (role: user|admin)\n"
        "  -D <user>                 Delete user\n"
        "  -h                        Help\n"
        "\n"
        "Examples:\n"
        "  %s -A pepito 1234 user\n"
        "  %s -R juan admin\n"
        "  %s -D messi\n",
        prog, prog, prog, prog
    );
}

static bool role_is_valid(const char *role) {
    return role != NULL && (strcmp(role, "user") == 0 || strcmp(role, "admin") == 0);
}

/* Wrapper: ADD_USER "username password role" */
static void admin_add_user(int sockfd, uint32_t *id_counter,
                           const char *user, const char *pass, const char *role) {
    char payload[256];
    int n = snprintf(payload, sizeof(payload), "%s %s %s\n", user, pass, role);
    if (n < 0 || (size_t)n >= sizeof(payload)) {
        fprintf(stderr, "[ERR] Payload add_user too long\n");
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
        fprintf(stderr, "[ERR] Payload set_user_role too long\n");
        return;
    }
    admin_send_request(sockfd, (*id_counter)++, ADMIN_SET_USER_ROLE, payload);
}

/* Wrapper: DELETE_USER "username" */
static void admin_delete_user(int sockfd, uint32_t *id_counter, const char *user) {
    char payload[256];
    int n = snprintf(payload, sizeof(payload), "%s\n", user);
    if (n < 0 || (size_t)n >= sizeof(payload)) {
        fprintf(stderr, "[ERR] Payload delete_user too long\n");
        return;
    }
    admin_send_request(sockfd, (*id_counter)++, ADMIN_DELETE_USER, payload);
}

static void admin_quit(int sockfd, uint32_t *id_counter) {
    admin_send_request(sockfd, (*id_counter)++, ADMIN_QUIT, NULL);
}

int main(int argc, char *argv[]) {
    enum { ACT_NONE, ACT_ADD, ACT_ROLE, ACT_DEL } act = ACT_NONE;

    const char *add_user = NULL, *add_pass = NULL, *add_role = NULL;
    const char *role_user = NULL, *role_role = NULL;
    const char *del_user = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "A:R:D:h")) != -1) {
        switch (opt) {
            case 'A': {
                // -A consumes 3 args: user pass role
                act = ACT_ADD;
                add_user = optarg;
                if (optind + 1 >= argc) { usage(argv[0]); return 1; }
                add_pass = argv[optind++];
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
        if (add_user == NULL || add_pass == NULL || add_role == NULL || !role_is_valid(add_role)) {
            fprintf(stderr, "[ERR] Invalid -A args. role must be user|admin\n");
            return 1;
        }
    } else if (act == ACT_ROLE) {
        if (role_user == NULL || role_role == NULL || !role_is_valid(role_role)) {
            fprintf(stderr, "[ERR] Invalid -R args. role must be user|admin\n");
            return 1;
        }
    } else if (act == ACT_DEL) {
        if (del_user == NULL) {
            fprintf(stderr, "[ERR] Invalid -D args\n");
            return 1;
        }
    }

    int sockfd = create_client_socket(SOCKS_ADDR, SOCKS_PORT);
    if (sockfd < 0) return 1;

    perform_handshake(sockfd, "admin", "admin");
    perform_request_ipv6(sockfd, API_ADDR, API_PORT);

    uint32_t req_id = 1;

    if (act == ACT_ADD) {
        admin_add_user(sockfd, &req_id, add_user, add_pass, add_role);
    } else if (act == ACT_ROLE) {
        admin_set_user_role(sockfd, &req_id, role_user, role_role);
    } else if (act == ACT_DEL) {
        admin_delete_user(sockfd, &req_id, del_user);
    }

    admin_quit(sockfd, &req_id);

    close(sockfd);
    return 0;
}
