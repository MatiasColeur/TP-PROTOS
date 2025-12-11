#ifndef SHARED_H
#define SHARED_H

#define ADMIN_API_PORT 5555
#define LOOPBACK_IPV4 "127.0.0.1"
#define LOOPBACK_IPV6 "::1"
#define USER_DB_PATH "users.csv"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>



int read_exact(int fd, void *buf, size_t len);
int write_exact(int fd, const void *buf, size_t len);


#endif
