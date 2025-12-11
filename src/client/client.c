#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include "../../include/errors.h"
#include "../../include/shared.h"
#include "../../include/api.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 1080
#define BUFFER_SIZE 512

void perform_handshake(int sockfd) {
    char buf[BUFFER_SIZE];
    
    // 1. Enviar saludo inicial
    printf("[Info] Enviando Hello...\n");
    char hello[] = { 0x05, 0x01, 0x02 }; // Ver 5, 1 Metodo, Metodo Auth User/Pass
    if (send(sockfd, hello, sizeof(hello), 0) < 0) {
        print_error("Error sending Hello");
        exit(1);
    }

    // 2. Recibir respuesta del servidor
    ssize_t n = recv(sockfd, buf, BUFFER_SIZE, 0);
    if (n < 2 || buf[1] != 0x02) {
        fprintf(stderr, "Error: El servidor no aceptó autenticación User/Pass. Recibido: %02x\n", (unsigned char)buf[1]);
        exit(1);
    }

    // 3. Enviar credenciales (Subnegociación RFC 1929)
    // Formato: Ver(0x01) | Ulen | User | Plen | Pass
    char username[] = "admin";
    char password[] = "admin";
    
    char auth_req[512];
    int idx = 0;
    auth_req[idx++] = 0x01;                 // Version de subnegociación
    auth_req[idx++] = strlen(username);     // Longitud usuario
    memcpy(&auth_req[idx], username, strlen(username));
    idx += strlen(username);
    auth_req[idx++] = strlen(password);     // Longitud password
    memcpy(&auth_req[idx], password, strlen(password));
    idx += strlen(password);

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

/**
 * Función auxiliar común para recibir y validar la respuesta del servidor.
 * Se llama automáticamente al final de cada perform_request.
 */
static void verify_socks5_reply(int sockfd) {
    char buf[BUFFER_SIZE];
    ssize_t n = recv(sockfd, buf, BUFFER_SIZE, 0);
    
    if (n < 4) {
        print_error("Reply too short or connection closed");
        exit(1);
    }

    // buf[0] = VER, buf[1] = REP, buf[2] = RSV, buf[3] = ATYP
    uint8_t rep = buf[1];

    if (rep == 0x00) {
        print_success("SOCKS5 Request Granted (Tunnel Established)");
    } else {
        // Mapeo básico de errores para mostrar info útil
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


/**
 * Realiza el REQUEST para conectar a un destino (RFC 1928)
 * Intentaremos conectar a "google.com" puerto 80
 */
void perform_request_domain(int sockfd, const char *ip_str, int port) {
    char buf[BUFFER_SIZE];
    

    print_info("Enviando Request CONNECT a %s:%d...\n", ip_str, port);

    // Construcción del paquete REQUEST
    // VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
    int idx = 0;
    buf[idx++] = 0x05; // VER
    buf[idx++] = 0x01; // CMD: CONNECT
    buf[idx++] = 0x00; // RSV
    buf[idx++] = 0x03; // ATYP: Domain Name (0x03)
    
    // Para ATYP 0x03: [Len] [DomainString]
    buf[idx++] = strlen(ip_str); 
    memcpy(&buf[idx], ip_str, strlen(ip_str));
    idx += strlen(ip_str);

    // Puerto (Network Byte Order)
    uint16_t port_net = htons(port);
    memcpy(&buf[idx], &port_net, 2);
    idx += 2;

    if (send(sockfd, buf, idx, 0) < 0) {
        print_error("Failed sending request");
        exit(1);
    }

    verify_socks5_reply(sockfd);
}

/**
 * Realiza un request usando IPv6 (ATYP 0x04)
 * Ejemplo: perform_request_ipv6(sock, "::1", 80);
 */
void perform_request_ipv6(int sockfd, const char *ip6_str, int port) {
    char buf[BUFFER_SIZE];
    print_info("Enviando Request IPv6 CONNECT a [%s]:%d...", ip6_str, port);

    int idx = 0;
    buf[idx++] = 0x05; // VER
    buf[idx++] = 0x01; // CMD: CONNECT
    buf[idx++] = 0x00; // RSV
    buf[idx++] = 0x04; // ATYP: IPv6

    // Convertir IPv6 string a binario (16 bytes)
    if (inet_pton(AF_INET6, ip6_str, &buf[idx]) <= 0) {
        print_error("Invalid IPv6 address: %s", ip6_str);
        exit(1);
    }
    idx += 16;

    // Puerto
    uint16_t p = htons(port);
    memcpy(&buf[idx], &p, 2);
    idx += 2;

    if (send(sockfd, buf, idx, 0) < 0) {
        print_error("Failed sending request");
        exit(1);
    }

    verify_socks5_reply(sockfd);
}

/**
 * Realiza un request usando IPv4 (ATYP 0x01)
 * Ejemplo: perform_request_ipv4(sock, "127.0.0.1", 80);
 */
void perform_request_ipv4(int sockfd, const char *ip_str, int port) {
    char buf[BUFFER_SIZE];
    print_info("Enviando Request IPv4 CONNECT a %s:%d...", ip_str, port);

    int idx = 0;
    buf[idx++] = 0x05; // VER
    buf[idx++] = 0x01; // CMD: CONNECT
    buf[idx++] = 0x00; // RSV
    buf[idx++] = 0x01; // ATYP: IPv4

    // Convertir IP string a binario (4 bytes)
    if (inet_pton(AF_INET, ip_str, &buf[idx]) <= 0) {
        print_error("Invalid IPv4 address: %s", ip_str);
        exit(1);
    }
    idx += 4;

    // Puerto
    uint16_t p = htons(port);
    memcpy(&buf[idx], &p, 2);
    idx += 2;

    if (send(sockfd, buf, idx, 0) < 0) {
        print_error("Failed sending request");
        exit(1);
    }

    verify_socks5_reply(sockfd);
}

/**
 * Envía datos a través del túnel establecido para probar la conexión
 */
void test_tunnel(int sockfd) {
    // print_info("Enviando HTTP GET a google.com a través del túnel...");
    
    char http_msg[] = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";
    
    if (send(sockfd, http_msg, strlen(http_msg), 0) < 0) {
        print_error("Failed writing to tunnel");
        return;
    }

    // Leemos la respuesta en bucle
    char buf[BUFFER_SIZE + 1];
    ssize_t n;
    print_info("Respuesta recibida del destino:");
    while ((n = recv(sockfd, buf, BUFFER_SIZE, 0)) > 0) {
        buf[n] = '\0';
        printf("%s", buf);
    }
    print_info("Conexión cerrada por el extremo remoto.");
}

int main(int argc, char *argv[]) {
    int sockfd;
    struct sockaddr_in serv_addr;

    // 1. Crear socket TCP
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        print_error("Failed creating socket");
        return 1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        print_error("Invalid direction");
        return 1;
    }

    // 2. Conectar al servidor SOCKS5
    print_info("Conectando al Proxy SOCKS5 en %s:%d...\n", SERVER_IP, SERVER_PORT);
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        print_error("Connection Failed (Is the server running?)");
        return 1;
    }

    // 3. Ejecutar pasos del protocolo
    perform_handshake(sockfd);  // Auth
    // Caso A: Dominio (Requiere que tu servidor resuelva DNS)
    // perform_request_domain(sockfd, "google.com", 80);

    // Caso B: IPv4 (Prueba tu servidor web local o una IP pública)
    // perform_request_ipv4(sockfd, "8.8.8.8", 80); // IP de Google

    // Caso C: IPv6 (Si tienes red IPv6 o para probar loopback)
    // perform_request_ipv6(sockfd, "::1", 8080);
    perform_request_ipv6(sockfd, LOOPBACK_IPV6, ADMIN_API_PORT);
    test_tunnel(sockfd);        // Data Relay

    close(sockfd);
    return 0;
}
