#ifndef _SOCKS5_H_
#define _SOCKS5_H_

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#include "util.h"
#include "logger.h"
#include "selector.h"
#include "stm.h"
#include "buffer.h"
#include "auth.h"

#define SUCCESS 0
#define IPV4_N 1
#define FQDN_N 3
#define IPV6_N 4

//Connect Status
#define CONNECTION_REFUSED 5
#define HOST_UNREACHABLE 4


#define VER 5
#define CMD 1
#define SUBNEGOTIATION_VER 1

int handleClient(int clientSocket);

int handleAuthNegotiation(int clientSocket, char * clientUsername, char * clientPassword);
int handleRequest(int clientSocket, struct addrinfo** addressConnectTo, int * clientPort, char * clientHostname);
int handleConnectAndReply(int clientSocket, struct addrinfo** addressConnectTo, int* remoteSocket);
int handleConnectionData(int clientSocket, int remoteSocket);
int handleUsernamePasswordAuth(int clientSocket, char * username, char * password, size_t maxLen);
bool authenticateUser(int clientSocket);

#endif
