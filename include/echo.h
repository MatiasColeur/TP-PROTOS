#ifndef ECHO_H_XYZ1234567890ABCDEFGHIJ
#define ECHO_H_XYZ1234567890ABCDEFGHIJ

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

#include "util.h"
#include "selector.h"
#include "stm.h"
#include "buffer.h"

void 
handle_new_client(fd_selector selector, int client_fd);



#endif
