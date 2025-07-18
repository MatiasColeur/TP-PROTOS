#ifndef _UTIL_H_
#define _UTIL_H_

#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int printSocketAddress(const struct sockaddr* address, char* addrBuffer);

const char* printFamily(struct addrinfo* aip);
const char* printType(struct addrinfo* aip);
const char* printProtocol(struct addrinfo* aip);
void printFlags(struct addrinfo* aip);
char* printAddressPort(const struct addrinfo* aip, char addr[], size_t addrlen);

// Determina si dos sockets son iguales (misma direccion y puerto)
int sockAddrsEqual(const struct sockaddr* addr1, const struct sockaddr* addr2);

#endif
