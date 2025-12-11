#ifndef SHARED_H
#define SHARED_H

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
