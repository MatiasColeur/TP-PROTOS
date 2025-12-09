#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include "../../include/errors.h"

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
 * Realiza el REQUEST para conectar a un destino (RFC 1928)
 * Intentaremos conectar a "google.com" puerto 80
 */
void perform_request(int sockfd) {
    char buf[BUFFER_SIZE];
    
    // Datos del destino
    char target_host[] = "google.com";
    int target_port = 80;

    printf("[Info] Enviando Request CONNECT a %s:%d...\n", target_host, target_port);

    // Construcción del paquete REQUEST
    // VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
    int idx = 0;
    buf[idx++] = 0x05; // VER
    buf[idx++] = 0x01; // CMD: CONNECT
    buf[idx++] = 0x00; // RSV
    buf[idx++] = 0x03; // ATYP: Domain Name (0x03)
    
    // Para ATYP 0x03: [Len] [DomainString]
    buf[idx++] = strlen(target_host); 
    memcpy(&buf[idx], target_host, strlen(target_host));
    idx += strlen(target_host);

    // Puerto (Network Byte Order)
    uint16_t port_net = htons(target_port);
    memcpy(&buf[idx], &port_net, 2);
    idx += 2;

    if (send(sockfd, buf, idx, 0) < 0) {
        print_error("Failed sending request");
        exit(1);
    }

    // Recibir REPLY del servidor
    // VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
    ssize_t n = recv(sockfd, buf, BUFFER_SIZE, 0);
    if (n < 4) {
        print_error("Reply too short or connection closed");
        exit(1);
    }

    // Verificar el campo REP (Reply field)
    if (buf[1] == 0x00) {
        print_success("SOCKS5 Request Granted (Tunnel Established)");
    } else {
        fprintf(stderr, "[ERR] Server replied with error code: 0x%02x\n", (unsigned char)buf[1]);
        print_error("SOCKS5 Request Failed");
        exit(1);
    }
}

/**
 * Envía datos a través del túnel establecido para probar la conexión
 */
void test_tunnel(int sockfd) {
    printf("[Info] Enviando HTTP GET a google.com a través del túnel...\n");
    
    char http_msg[] = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";
    
    if (send(sockfd, http_msg, strlen(http_msg), 0) < 0) {
        print_error("Failed writing to tunnel");
        return;
    }

    // Leemos la respuesta en bucle
    char buf[BUFFER_SIZE + 1];
    ssize_t n;
    printf("[Info] Respuesta recibida del destino:\n");
    printf("------------------------------------------------\n");
    while ((n = recv(sockfd, buf, BUFFER_SIZE, 0)) > 0) {
        buf[n] = '\0';
        printf("%s", buf);
    }
    printf("\n------------------------------------------------\n");
    printf("[Info] Conexión cerrada por el extremo remoto.\n");
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
    printf("[Info] Conectando al Proxy SOCKS5 en %s:%d...\n", SERVER_IP, SERVER_PORT);
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        print_error("Connection Failed (Is the server running?)");
        return 1;
    }

    // 3. Ejecutar pasos del protocolo
    perform_handshake(sockfd);  // Auth
    perform_request(sockfd);    // Connect
    test_tunnel(sockfd);        // Data Relay

    close(sockfd);
    return 0;
}