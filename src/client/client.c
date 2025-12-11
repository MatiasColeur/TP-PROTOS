#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "../../include/errors.h"
#include "../../include/shared.h"
#include "../../include/api.h"
#include "../../include/client_utils.h"
#include "../../include/parser_arguments.h"



int main(int argc, const char *argv[]) {

    ProgramArgs args;
    parse_arguments(argc, argv, &args);

    int sockfd = create_client_socket(args.socks_addr, args.socks_port);
    
    if (sockfd < 0) {
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