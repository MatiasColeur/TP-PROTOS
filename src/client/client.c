#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "../../include/errors.h"
#include "../../include/shared.h"
#include "../../include/api.h"
#include "../../include/client_utils.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 1080

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
    print_info("Connecting to Proxy SOCKS5 en %s:%d...", SERVER_IP, SERVER_PORT);
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        print_error("Connection Failed (Is the server running?)");
        return 1;
    }

    perform_handshake(sockfd, "admin", "admin");  

    // Caso A: Dominio (Requiere que tu servidor resuelva DNS)
    // perform_request_domain(sockfd, "google.com", 80);

    // Caso B: IPv4 (Prueba tu servidor web local o una IP pública)
    // perform_request_ipv4(sockfd, "8.8.8.8", 80); // IP de Google

    // Caso C: IPv6 (Si tienes red IPv6 o para probar loopback)
    // perform_request_ipv6(sockfd, "::1", 8080);
    
    // 4. Testear datos
    test_tunnel(sockfd);

    close(sockfd);
    return 0;
}