#include "../../include/shared.h"

int read_exact(int fd, void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, (char *)buf + off, len - off, 0);
        if (n <= 0) {
            return 0; // error o EOF
        }
        off += (size_t)n;
    }
    return 1;
}

int write_exact(int fd, const void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, (const char *)buf + off, len - off, 0);
        if (n <= 0) {
            return 0; // error
        }
        off += (size_t)n;
    }
    return 1;
}