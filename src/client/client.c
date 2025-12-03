#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 1080
#define BUFFER_SIZE 512

// Envía y recibe datos básicos para el handshake
void perform_handshake(int sockfd) {
    char buf[BUFFER_SIZE];
    
    // 1. Enviar saludo inicial: Version 5, 1 Método, Método 0x02 (User/Pass)
    // Según tu socks5.c, el servidor rechaza si no ve el método 0x02.
    char hello[] = { 0x05, 0x01, 0x02 };
    if (send(sockfd, hello, sizeof(hello), 0) < 0) {
        perror("Error enviando hello");
        exit(1);
    }

    // 2. Recibir respuesta del servidor (debe ser 0x05 0x02)
    ssize_t n = recv(sockfd, buf, BUFFER_SIZE, 0);
    if (n < 2 || buf[1] != 0x02) {
        fprintf(stderr, "Error: El servidor no aceptó autenticación User/Pass (0x02)\n");
        exit(1);
    }
    printf("[Info] Handshake inicial exitoso. Autenticando...\n");

    // 3. Enviar credenciales (Subnegociación RFC 1929)
    // Formato: Ver(0x01) | Ulen | User | Plen | Pass
    char username[] = "usuario";
    char password[] = "secreto";
    
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
        printf("[Exito] Autenticación completada.\n");
    } else {
        printf("[Fallo] Credenciales rechazadas.\n");
    }
}

int main(int argc, char *argv[]) {
    int sockfd;
    struct sockaddr_in serv_addr;

    // Crear socket TCP
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Error creando socket");
        return 1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        perror("Dirección inválida");
        return 1;
    }

    // Conectar al servidor
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Error de conexión");
        return 1;
    }

    printf("Conectado a %s:%d\n", SERVER_IP, SERVER_PORT);
    
    perform_handshake(sockfd);

    while (1)
    {
        /* code */
    }
    
    close(sockfd);
    return 0;
}