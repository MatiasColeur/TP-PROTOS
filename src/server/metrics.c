#include "../../include/metrics.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static const char *log_path = NULL;

static uint64_t concurrent_connections = 0;
static uint64_t total_bytes_received = 0;
static uint64_t total_bytes_sent = 0;

void metrics_init(const char *access_log_path) {
    log_path = access_log_path;
}

uint64_t metrics_get_total_connections(void) {
    if (log_path == NULL)
        return 0;

    FILE *f = fopen(log_path, "r");
    if (!f)
        return 0;

    uint64_t count = 0;
    char buffer[1024];

    while (fgets(buffer, sizeof(buffer), f)) {
        count++;
    }

    fclose(f);
    return count;
}

void metrics_inc_concurrent_connections(void) {
    concurrent_connections++;
}

void metrics_dec_concurrent_connections(void) {
    if (concurrent_connections > 0)
        concurrent_connections--;
}

void metrics_add_bytes_received(uint64_t n) {
    total_bytes_received += n;
}

void metrics_add_bytes_sent(uint64_t n) {
    total_bytes_sent += n;
}

uint64_t metrics_get_concurrent_connections(void) {
    return concurrent_connections;
}

uint64_t metrics_get_total_bytes_received(void) {
    return total_bytes_received;
}

uint64_t metrics_get_total_bytes_sent(void) {
    return total_bytes_sent;
}

void metrics_print(void) {
    printf("=== Server metrics ===\n");
    printf("Total connections (from log): %lu\n", metrics_get_total_connections());
    printf("Concurrent connections: %lu\n", concurrent_connections);
    printf("Total bytes received: %lu\n", total_bytes_received);
    printf("Total bytes sent: %lu\n", total_bytes_sent);
}
