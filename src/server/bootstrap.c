#include "../../include/bootstrap.h"

#define BOOTSTRAP_BUFFER_SIZE 512

static void bootstrap_perform_handshake(int sockfd) {
    char buf[BOOTSTRAP_BUFFER_SIZE];

    // 1. Hello: request USER/PASS method (0x02)
    char hello[] = { 0x05, 0x01, 0x02 };
    if (send(sockfd, hello, sizeof(hello), 0) < 0) {
        print_error("bootstrap: failed sending Hello");
        exit(1);
    }
 
    ssize_t n = recv(sockfd, buf, sizeof(buf), 0);
    if (n < 2 || buf[1] != 0x02) {
        fprintf(stderr, "[BOOTSTRAP] Error: server did not accept Auth User/Pass. Received: %02x\n",
                (unsigned char)buf[1]);
        exit(1);
    }

    // 2. RFC1929 subnegotiation: admin/admin
    const char *username = "admin";
    const char *password = "admin";

    char auth_req[256];
    int idx = 0;
    auth_req[idx++] = 0x01;                 // Subnegotiation version
    auth_req[idx++] = (uint8_t)strlen(username);
    memcpy(&auth_req[idx], username, strlen(username));
    idx += (int)strlen(username);
    auth_req[idx++] = (uint8_t)strlen(password);
    memcpy(&auth_req[idx], password, strlen(password));
    idx += (int)strlen(password);

    if (send(sockfd, auth_req, idx, 0) < 0) {
        print_error("bootstrap: failed sending auth");
        exit(1);
    }

    n = recv(sockfd, buf, sizeof(buf), 0);
    if (n >= 2 && buf[1] == 0x00) {
        print_success("[BOOTSTRAP] Authentication Completed (admin/admin)");
    } else {
        print_error("[BOOTSTRAP] Authentication Rejected");
        exit(1);
    }
}

static void bootstrap_perform_request(int sockfd,
                                      const char *addr_str,
                                      int port) {
    char buf[BOOTSTRAP_BUFFER_SIZE];
    int idx = 0;

    buf[idx++] = 0x05; // VER
    buf[idx++] = 0x01; // CMD: CONNECT
    buf[idx++] = 0x00; // RSV
    uint8_t atyp;

    uint8_t addr_bin[16];
    size_t addr_len = 0;
    if (inet_pton(AF_INET6, addr_str, addr_bin) == 1) {
        atyp = 0x04;
        addr_len = 16;
    } else if (inet_pton(AF_INET, addr_str, addr_bin) == 1) {
        atyp = 0x01;
        addr_len = 4;
    } else {
        print_error("bootstrap: invalid address: %s", addr_str);
        exit(1);
    }

    buf[idx++] = atyp;
    memcpy(&buf[idx], addr_bin, addr_len);
    idx += (int)addr_len;

    uint16_t p = htons((uint16_t)port);
    memcpy(&buf[idx], &p, 2);
    idx += 2;

    if (send(sockfd, buf, idx, 0) < 0) {
        print_error("bootstrap: failed sending CONNECT request");
        exit(1);
    }

    // Reply SOCKS
    ssize_t n = recv(sockfd, buf, sizeof(buf), 0);
    if (n < 4) {
        print_error("bootstrap: reply too short");
        exit(1);
    }

    uint8_t rep = buf[1];
    if (rep != 0x00) {
        fprintf(stderr, "[BOOTSTRAP] SOCKS5 CONNECT failed. REP=0x%02x\n", rep);
        exit(1);
    }

    print_success("[BOOTSTRAP] SOCKS5 CONNECT to Admin API established");
}

/* ---- reuse admin_* wrappers ---- */

static void bootstrap_admin_add_user(int sockfd,
                                     uint32_t *id_counter,
                                     const char *user,
                                     const char *pass,
                                     const char *role) {
    char payload[256];
    int n = snprintf(payload, sizeof(payload), "%s %s %s\n", user, pass, role);
    if (n < 0 || (size_t)n >= sizeof(payload)) {
        fprintf(stderr, "[BOOTSTRAP] add_user payload too long\n");
        return;
    }

    print_info("[BOOTSTRAP] ADD_USER %s %s %s\n", user, pass, role);
    admin_send_request(sockfd, (*id_counter)++, ADMIN_ADD_USER, payload);
}

static void bootstrap_admin_quit(int sockfd, uint32_t *id_counter) {
    print_info("[BOOTSTRAP] QUIT\n");
    admin_send_request(sockfd, (*id_counter)++, ADMIN_QUIT, NULL);
}

/**
 * Creates, via Admin API, all CLI-provided users (-u user:pass).
 * IMPORTANT: assumes admin/admin already exists on the server.
 */
void bootstrap_cli_users_via_api(const ProgramArgs *args) {
    if (args->user_count == 0) return;

    const char *host = args->socks_addr;

    // Si viene un bind-any, como cliente conectamos a loopback
    if (host == NULL || strcmp(host, "0.0.0.0") == 0 || strcmp(host, "::") == 0) {
        host = "::1";
    }

    int sockfd;
    struct sockaddr_storage serv_addr;
    socklen_t serv_len = 0;

    memset(&serv_addr, 0, sizeof(serv_addr));
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&serv_addr;
    struct sockaddr_in  *addr4 = (struct sockaddr_in  *)&serv_addr;

    if (inet_pton(AF_INET6, host, &addr6->sin6_addr) == 1) {
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port   = htons(args->socks_port);
        serv_len = sizeof(*addr6);
        sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    } else if (inet_pton(AF_INET, host, &addr4->sin_addr) == 1) {
        addr4->sin_family = AF_INET;
        addr4->sin_port   = htons(args->socks_port);
        serv_len = sizeof(*addr4);
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
    } else {
        print_error("[BOOTSTRAP] invalid address %s", host);
        return;
    }

    if (sockfd < 0) {
        print_error("[BOOTSTRAP] socket()");
        return;
    }

    print_info("[BOOTSTRAP] Connecting to SOCKS5 in %s:%d...\n", host, args->socks_port);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, serv_len) < 0) {
        print_error("[BOOTSTRAP] connect() failed");
        close(sockfd);
        return;
    }

    // Handshake + auth as admin
    bootstrap_perform_handshake(sockfd);

    // CONNECT via SOCKS to Admin API (management addr/port)
    bootstrap_perform_request(sockfd, args->aux_addr, args->aux_port);

    uint32_t req_id = 1;

    // For simplicity, all with role "user". Adjust policy if needed.
    for (int i = 0; i < args->user_count; i++) {
        bootstrap_admin_add_user(sockfd, &req_id,
                                 args->users[i].name,
                                 args->users[i].pass,
                                 "0");
    }

    bootstrap_admin_quit(sockfd, &req_id);
    close(sockfd);

    print_success("[BOOTSTRAP] CLI users registered via Admin API");
}
