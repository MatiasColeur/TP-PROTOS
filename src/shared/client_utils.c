#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include "../../include/errors.h" 
#include "../../include/client_utils.h"

/**
 * Función auxiliar interna para validar la respuesta del servidor (REP).
 */
static void verify_socks5_reply(int sockfd) {
    char buf[BUFFER_SIZE];
    ssize_t n = recv(sockfd, buf, BUFFER_SIZE, 0);
    
    if (n < 4) {
        print_error("Reply too short or connection closed");
        exit(1);
    }

    uint8_t rep = buf[1];

    if (rep == 0x00) {
        print_success("SOCKS5 Request Granted (Tunnel Established)");
    } else {
        const char *err_msg = "Unknown Error";
        switch(rep) {
            case 0x01: err_msg = "General Failure"; break;
            case 0x02: err_msg = "Connection not allowed"; break;
            case 0x03: err_msg = "Network Unreachable"; break;
            case 0x04: err_msg = "Host Unreachable"; break;
            case 0x05: err_msg = "Connection Refused"; break;
            case 0x06: err_msg = "TTL Expired"; break;
            case 0x07: err_msg = "Command not supported"; break;
            case 0x08: err_msg = "Address type not supported"; break;
        }
        fprintf(stderr, "[ERR] Server replied: 0x%02x (%s)\n", rep, err_msg);
        print_error("SOCKS5 Request Failed");
        exit(1);
    }
}

int create_client_socket(const char *server_address, int server_port) {
    int sockfd;
    struct sockaddr_in serv_addr;

    // 1. Crear socket TCP
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        print_error("Failed creating socket");
        return -1;
    }

    // Limpieza de estructura (buena práctica)
    memset(&serv_addr, 0, sizeof(serv_addr));
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(server_port);

    // 2. Convertir IP de texto a binario
    if (inet_pton(AF_INET, server_address, &serv_addr.sin_addr) <= 0) {
        print_error("Invalid address / Address not supported: %s", server_address);
        close(sockfd); // Liberar recurso antes de salir
        return -1;
    }

    // 3. Conectar al servidor
    print_info("Connecting to Proxy SOCKS5 at %s:%d...", server_address, server_port);
    
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        print_error("Connection Failed (Is the server running?)");
        close(sockfd); // Liberar recurso antes de salir
        return -1;
    }

    return sockfd; // Retornar el socket conectado
}

void perform_handshake(int sockfd, const char *username, const char *password) {
    char buf[BUFFER_SIZE];
    
    // 1. Enviar saludo inicial
    print_info("Enviando Hello...\n");
    char hello[] = { 0x05, 0x01, 0x02 }; // Ver 5, 1 Metodo, Auth User/Pass (0x02)
    if (send(sockfd, hello, sizeof(hello), 0) < 0) {
        print_error("Error sending Hello");
        exit(1);
    }

    // 2. Recibir respuesta de método seleccionado
    ssize_t n = recv(sockfd, buf, BUFFER_SIZE, 0);
    if (n < 2 || buf[1] != 0x02) {
        print_error("El servidor no aceptó autenticación User/Pass. Recibido: %02x\n", (unsigned char)buf[1]);
        exit(1);
    }

    // 3. Enviar credenciales (RFC 1929)
    char auth_req[512];
    int idx = 0;
    auth_req[idx++] = 0x01;                 // Version subnegociación
    
    // Usuario
    size_t ulen = strlen(username);
    auth_req[idx++] = (uint8_t)ulen;
    memcpy(&auth_req[idx], username, ulen);
    idx += ulen;
    
    // Password
    size_t plen = strlen(password);
    auth_req[idx++] = (uint8_t)plen;
    memcpy(&auth_req[idx], password, plen);
    idx += plen;

    send(sockfd, auth_req, idx, 0);

    // 4. Recibir respuesta de autenticación
    n = recv(sockfd, buf, BUFFER_SIZE, 0);
    if (n >= 2 && buf[1] == 0x00) {
        print_success("Authentication Completed");
    } else {
        print_error("Authentication Rejected");
        exit(1);
    }
}

void perform_request_domain(int sockfd, const char *domain, int port) {
    char buf[BUFFER_SIZE];
    print_info("Enviando Request CONNECT a %s:%d...\n", domain, port);

    int idx = 0;
    buf[idx++] = 0x05; // VER
    buf[idx++] = 0x01; // CMD: CONNECT
    buf[idx++] = 0x00; // RSV
    buf[idx++] = 0x03; // ATYP: Domain
    
    size_t len = strlen(domain);
    buf[idx++] = (uint8_t)len;
    memcpy(&buf[idx], domain, len);
    idx += len;

    uint16_t port_net = htons(port);
    memcpy(&buf[idx], &port_net, 2);
    idx += 2;

    if (send(sockfd, buf, idx, 0) < 0) {
        print_error("Failed sending request");
        exit(1);
    }

    verify_socks5_reply(sockfd);
}

void perform_request_ipv4(int sockfd, const char *ip_str, int port) {
    char buf[BUFFER_SIZE];
    print_info("Enviando Request IPv4 CONNECT a %s:%d...", ip_str, port);

    int idx = 0;
    buf[idx++] = 0x05;
    buf[idx++] = 0x01;
    buf[idx++] = 0x00;
    buf[idx++] = 0x01; // ATYP: IPv4

    if (inet_pton(AF_INET, ip_str, &buf[idx]) <= 0) {
        print_error("Invalid IPv4 address: %s", ip_str);
        exit(1);
    }
    idx += 4;

    uint16_t p = htons(port);
    memcpy(&buf[idx], &p, 2);
    idx += 2;

    if (send(sockfd, buf, idx, 0) < 0) {
        print_error("Failed sending request");
        exit(1);
    }

    verify_socks5_reply(sockfd);
}

void perform_request_ipv6(int sockfd, const char *ip6_str, int port) {
    char buf[BUFFER_SIZE];
    print_info("Enviando Request IPv6 CONNECT a [%s]:%d...", ip6_str, port);

    int idx = 0;
    buf[idx++] = 0x05;
    buf[idx++] = 0x01;
    buf[idx++] = 0x00;
    buf[idx++] = 0x04; // ATYP: IPv6

    if (inet_pton(AF_INET6, ip6_str, &buf[idx]) <= 0) {
        print_error("Invalid IPv6 address: %s", ip6_str);
        exit(1);
    }
    idx += 16;

    uint16_t p = htons(port);
    memcpy(&buf[idx], &p, 2);
    idx += 2;

    if (send(sockfd, buf, idx, 0) < 0) {
        print_error("Failed sending request");
        exit(1);
    }

    verify_socks5_reply(sockfd);
}

void test_tunnel(int sockfd) {
    char http_msg[] = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";
    
    if (send(sockfd, http_msg, strlen(http_msg), 0) < 0) {
        print_error("Failed writing to tunnel");
        return;
    }

    char buf[BUFFER_SIZE + 1];
    ssize_t n;
    print_info("Respuesta recibida del destino:");
    while ((n = recv(sockfd, buf, BUFFER_SIZE, 0)) > 0) {
        buf[n] = '\0';
        printf("%s", buf);
    }
    print_info("Conexión cerrada por el extremo remoto.");
}

/**
 * Realiza el Handshake SOCKS5 (Metodo 0x02) y la Autenticación RFC 1929.
 */
int perform_handshake_thread(int sockfd, const char *username, const char *password) {
    char buf[512];

    // 1. Enviar Hello: VER=5, NMETHODS=1, METHOD=0x02 (Username/Password)
    char hello[] = { 0x05, 0x01, 0x02 }; 
    if (send(sockfd, hello, sizeof(hello), 0) != sizeof(hello)) return -1;

    if (recv(sockfd, buf, 2, 0) != 2) return -1;

    // Verificar que el servidor eligió 0x02 (Auth)
    if (buf[1] != 0x02) {
        // Si devuelve 0xFF es que no soporta nuestros métodos.
        // Si devuelve 0x00 es que no requiere auth (pero nosotros forzamos 0x02 arriba).
        return -1; 
    }

    // 3. Enviar Credenciales (RFC 1929)
    // Formato: VER(1) | ULEN | USER | PLEN | PASS
    int idx = 0;
    buf[idx++] = 0x01; // Versión de sub-negociación (siempre 1)
    
    size_t ulen = strlen(username);
    if (ulen > 255) return -1;
    buf[idx++] = (uint8_t)ulen;
    memcpy(&buf[idx], username, ulen);
    idx += ulen;
    
    size_t plen = strlen(password);
    if (plen > 255) return -1;
    buf[idx++] = (uint8_t)plen;
    memcpy(&buf[idx], password, plen);
    idx += plen;

    if (send(sockfd, buf, idx, 0) != idx) return -1;

    // 4. Recibir Resultado de Autenticación
    // Formato: VER(1) | STATUS
    if (recv(sockfd, buf, 2, 0) != 2) return -1;

    // Status 0x00 significa Éxito
    if (buf[1] != 0x00) return -1; 

    return 0; // Auth OK
}

int verify_socks5_reply_thread(int sockfd) {
    char buf[BUFFER_SIZE];
    ssize_t n = recv(sockfd, buf, 4, 0); // Leemos header mínimo
    
    if (n < 4) return -1; 

    uint8_t rep = buf[1];
    if (rep != 0x00) {
        // Error del servidor SOCKS (Connection Refused, etc.)
        return -1;
    }
    
    // Consumir el resto (BND.ADDR + BND.PORT) para limpiar el socket
    int to_read = 0;
    switch (buf[3]) {
        case 0x01: to_read = 4 + 2; break; // IPv4
        case 0x03: // Domain
            if (recv(sockfd, buf, 1, 0) != 1) return -1; // Leer longitud dominio
            to_read = buf[0] + 2;
            break;
        case 0x04: to_read = 16 + 2; break; // IPv6
        default: return -1;
    }

    // Leer remanente
    while (to_read > 0) {
        n = recv(sockfd, buf, (to_read > sizeof(buf)) ? sizeof(buf) : to_read, 0);
        if (n <= 0) return -1;
        to_read -= n;
    }

    return 0; 
}

// Reutilizamos tus funciones de request tal cual (asegurando que retornen int)
int perform_request_ipv4_thread(int sockfd, const char *ip_str, int port) {
    char buf[BUFFER_SIZE];
    int idx = 0;
    buf[idx++] = 0x05; buf[idx++] = 0x01; buf[idx++] = 0x00; buf[idx++] = 0x01; // IPv4
    
    if (inet_pton(AF_INET, ip_str, &buf[idx]) <= 0) return -1;
    idx += 4;
    
    uint16_t p = htons(port);
    memcpy(&buf[idx], &p, 2);
    idx += 2;

    if (send(sockfd, buf, idx, 0) != idx) return -1;
    return verify_socks5_reply_thread(sockfd);
}

int perform_request_domain_thread(int sockfd, const char *domain, int port) {
    char buf[BUFFER_SIZE];
    int idx = 0;
    buf[idx++] = 0x05; buf[idx++] = 0x01; buf[idx++] = 0x00; buf[idx++] = 0x03; // Domain
    
    size_t len = strlen(domain);
    if (len > 255) return -1;
    buf[idx++] = (uint8_t)len;
    memcpy(&buf[idx], domain, len);
    idx += len;
    
    uint16_t p = htons(port);
    memcpy(&buf[idx], &p, 2);
    idx += 2;

    if (send(sockfd, buf, idx, 0) != idx) return -1;
    return verify_socks5_reply_thread(sockfd);
}
