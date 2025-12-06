#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

#define SERVER_PORT 1080
#define SERVER_ADDR "127.0.0.1"

int main(void) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[ERR] socket");
        return 1;
    }

    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_ADDR, &server.sin_addr) <= 0) {
        perror("[ERR] inet_pton");
        close(sockfd);
        return 1;
    }

    printf("[INF] Connecting to %s:%d...\n", SERVER_ADDR, SERVER_PORT);

    if (connect(sockfd, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("[ERR] connect");
        close(sockfd);
        return 1;
    }

    printf("[INF] Connected!\n");

    

    char buffer[1024];
    ssize_t n = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (n < 0) {
        perror("[ERR] recv");
        close(sockfd);
        return 1;
    }

    buffer[n] = '\0';

    printf("[INF] Received: '%s'\n", buffer);


    char msg[1024];
    ssize_t sent;

    while (fgets(msg, sizeof(msg), stdin) != NULL) {

        sent = send(sockfd, msg, strlen(msg)-1, 0);
        if (sent < 0) {
            perror("[ERR] send");
            close(sockfd);
            return 1;
        }

        n = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (n < 0) {
            perror("[ERR] recv");
            close(sockfd);
            return 1;
        }

        buffer[n] = '\0';   

        printf("[INF] Received: '%s'\n", buffer);
    }

    msg[0] = EOF;
    sent = send(sockfd, msg, 1, 0);


    close(sockfd);
    return 0;
}
