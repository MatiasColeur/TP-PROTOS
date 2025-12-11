#ifndef _CLIENT_UTILS_H
#define _CLIENT_UTILS_H

#include <netinet/in.h> // Para uint16_t, etc.

#define BUFFER_SIZE 512

/**
 * @brief Realiza el saludo inicial y la autenticación User/Pass (RFC 1929).
 * @param sockfd Socket conectado al servidor.
 * @param username Usuario (ej: "admin").
 * @param password Contraseña (ej: "admin").
 */
void perform_handshake(int sockfd, const char *username, const char *password);

/**
 * @brief Solicita conexión a un dominio (FQDN) (ATYP 0x03).
 */
void perform_request_domain(int sockfd, const char *domain, int port);

/**
 * @brief Solicita conexión a una IP IPv4 (ATYP 0x01).
 */
void perform_request_ipv4(int sockfd, const char *ip_str, int port);

/**
 * @brief Solicita conexión a una IP IPv6 (ATYP 0x04).
 */
void perform_request_ipv6(int sockfd, const char *ip6_str, int port);

/**
 * @brief Envía un request HTTP simple y muestra la respuesta.
 */
void test_tunnel(int sockfd);

#endif