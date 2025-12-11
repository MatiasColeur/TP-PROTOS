#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../../include/shared.h"    // LOOPBACK_IPV6, ADMIN_API_PORT, read_exact, write_exact
#include "../../include/api.h"

#define SERVER_IP   "127.0.0.1"
#define SERVER_PORT 1080
#define BUFFER_SIZE 512

/* -------- SOCKS5: handshake + CONNECT -------- */

static void perform_handshake(int sockfd) {
    uint8_t buf[BUFFER_SIZE];

    printf("[SOCKS] Enviando Hello...\n");
    uint8_t hello[] = { 0x05, 0x01, 0x02 }; // VER=5, NMETHODS=1, METHOD=0x02 (user/pass)
    if (!write_exact(sockfd, hello, sizeof(hello))) {
        perror("[SOCKS] Error enviando Hello");
        exit(1);
    }

    if (!read_exact(sockfd, buf, 2)) {
        perror("[SOCKS] Error recibiendo respuesta de Hello");
        exit(1);
    }

    if (buf[0] != 0x05 || buf[1] != 0x02) {
        fprintf(stderr, "[SOCKS] Server no aceptó auth user/pass. VER=0x%02x METHOD=0x%02x\n",
                buf[0], buf[1]);
        exit(1);
    }

    // Subnegociación RFC 1929
    const char *username = "admin";
    const char *password = "admin";

    uint8_t auth_req[256];
    size_t idx = 0;
    size_t ulen = strlen(username);
    size_t plen = strlen(password);

    auth_req[idx++] = 0x01;          // VER subnegociación
    auth_req[idx++] = (uint8_t)ulen;
    memcpy(&auth_req[idx], username, ulen);
    idx += ulen;
    auth_req[idx++] = (uint8_t)plen;
    memcpy(&auth_req[idx], password, plen);
    idx += plen;

    if (!write_exact(sockfd, auth_req, idx)) {
        perror("[SOCKS] Error enviando credenciales");
        exit(1);
    }

    if (!read_exact(sockfd, buf, 2)) {
        perror("[SOCKS] Error recibiendo respuesta de auth");
        exit(1);
    }

    if (buf[1] == 0x00) {
        printf("[SOCKS] Authentication Completed\n");
    } else {
        fprintf(stderr, "[SOCKS] Authentication Rejected\n");
        exit(1);
    }
}

static void verify_socks5_reply(int sockfd) {
    uint8_t buf[BUFFER_SIZE];

    // leemos al menos 4 bytes: VER, REP, RSV, ATYP
    if (!read_exact(sockfd, buf, 4)) {
        perror("[SOCKS] Reply too short o conexión cerrada");
        exit(1);
    }

    uint8_t rep = buf[1];
    if (rep == 0x00) {
        printf("[SOCKS] Request Granted (Tunnel Established)\n");
    } else {
        const char *err_msg = "Unknown Error";
        switch (rep) {
            case 0x01: err_msg = "General Failure"; break;
            case 0x02: err_msg = "Connection not allowed"; break;
            case 0x03: err_msg = "Network Unreachable"; break;
            case 0x04: err_msg = "Host Unreachable"; break;
            case 0x05: err_msg = "Connection Refused"; break;
            case 0x06: err_msg = "TTL Expired"; break;
            case 0x07: err_msg = "Command not supported"; break;
            case 0x08: err_msg = "Address type not supported"; break;
        }
        fprintf(stderr, "[SOCKS] Server REP=0x%02x (%s)\n", rep, err_msg);
        exit(1);
    }

    // Nos faltan los bytes de BND.ADDR + BND.PORT, depende de ATYP
    uint8_t atyp = buf[3];
    size_t addr_len = 0;

    switch (atyp) {
        case 0x01: addr_len = 4;  break; // IPv4
        case 0x03: {
            // dominio: primero un byte de longitud
            uint8_t dlen;
            if (!read_exact(sockfd, &dlen, 1)) {
                fprintf(stderr, "[SOCKS] Error leyendo len de dominio\n");
                exit(1);
            }
            addr_len = dlen;
            if (!read_exact(sockfd, buf, addr_len)) {
                fprintf(stderr, "[SOCKS] Error leyendo dominio\n");
                exit(1);
            }
            break;
        }
        case 0x04: addr_len = 16; break; // IPv6
        default:
            fprintf(stderr, "[SOCKS] ATYP desconocido en reply\n");
            exit(1);
    }

    if (atyp == 0x01 || atyp == 0x04) {
        if (!read_exact(sockfd, buf, addr_len)) {
            fprintf(stderr, "[SOCKS] Error leyendo BND.ADDR\n");
            exit(1);
        }
    }

    // leer BND.PORT (2 bytes)
    if (!read_exact(sockfd, buf, 2)) {
        fprintf(stderr, "[SOCKS] Error leyendo BND.PORT\n");
        exit(1);
    }
}

static void perform_request_ipv6(int sockfd, const char *ip6_str, int port) {
    uint8_t buf[BUFFER_SIZE];
    printf("[SOCKS] Enviando Request IPv6 CONNECT a [%s]:%d...\n", ip6_str, port);

    size_t idx = 0;
    buf[idx++] = 0x05; // VER
    buf[idx++] = 0x01; // CMD: CONNECT
    buf[idx++] = 0x00; // RSV
    buf[idx++] = 0x04; // ATYP: IPv6

    if (inet_pton(AF_INET6, ip6_str, &buf[idx]) <= 0) {
        perror("[SOCKS] Invalid IPv6 address");
        exit(1);
    }
    idx += 16;

    uint16_t p = htons((uint16_t)port);
    memcpy(&buf[idx], &p, 2);
    idx += 2;

    if (!write_exact(sockfd, buf, idx)) {
        fprintf(stderr, "[SOCKS] Failed sending request\n");
        exit(1);
    }

    verify_socks5_reply(sockfd);
}



/* -------- main -------- */

int main(int argc, const char *argv[]) {
    int sockfd;
    struct sockaddr_in serv_addr;

    /* usuario para ADMIN_GET_USER_CONNECTIONS */
    const char *user_for_logs = (argc > 1) ? argv[1] : "admin";

    /* 1. Crear socket TCP hacia el proxy SOCKS5 */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Failed creating socket\n");
        return 1;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid direction\n");
        close(sockfd);
        return 1;
    }

    printf("Conectando al Proxy SOCKS5 en %s:%d...\n", SERVER_IP, SERVER_PORT);
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "Connection Failed (Is the server running?)\n");
        close(sockfd);
        return 1;
    }

    /* 2. Handshake socks + auth */
    perform_handshake(sockfd);

    /* 3. CONNECT a la API admin (loopback v6 + puerto admin) */
    perform_request_ipv6(sockfd, LOOPBACK_IPV6, ADMIN_API_PORT);

    /* 4. Usar el túnel como conexión TCP a la API */

    uint32_t id = 1;

    /* a) Conexiones históricas */
    admin_send_request(sockfd, id++, ADMIN_GET_HIST_CONN, NULL);

    /* b) Conexiones concurrentes */
    admin_send_request(sockfd, id++, ADMIN_GET_CONCURRENT_CONN, NULL);

    /* c) Bytes transferidos */
    admin_send_request(sockfd, id++, ADMIN_GET_BYTES_TRANSFERRED, NULL);

    /* d) Conexiones de un usuario (líneas de log) */
    char body[256];
    int len = snprintf(body, sizeof(body), "%s\n", user_for_logs);
    if (len < 0 || len >= (int)sizeof(body)) {
        fprintf(stderr, "[ADMIN] Username too long\n");
    } else {
        admin_send_request(sockfd, id++, ADMIN_GET_USER_CONNECTIONS, body);
    }

    /* QUIT para cerrar prolijo del lado de la API */
    admin_send_request(sockfd, id++, ADMIN_QUIT, NULL);

    close(sockfd);
    return 0;
}
