#ifndef _SOCKS5_H_
#define _SOCKS5_H_

#include <netdb.h>
#include <stdbool.h>

#define VER 5

int handleClient(int clientSocket);

int handleAuthNegotiation(int clientSocket, char * clientUsername, char * clientPassword);
int handleRequest(int clientSocket, struct addrinfo** addressConnectTo, int * clientPort, char * clientHostname);
int handleConnectAndReply(int clientSocket, struct addrinfo** addressConnectTo, int* remoteSocket);
int handleConnectionData(int clientSocket, int remoteSocket);
int handleUsernamePasswordAuth(int clientSocket, char * username, char * password, size_t maxLen);
bool authenticateUser(int clientSocket);

#endif
