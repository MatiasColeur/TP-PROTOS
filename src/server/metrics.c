#include "../../include/metrics.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static uint64_t concurrent_connections = 0;
static uint64_t total_bytes_received = 0;
static uint64_t total_bytes_sent = 0;


static FILE * get_file(const char * file){
    FILE * logFile = fopen(file, "r"); //opens the file in read mode
    if (!logFile) {
        print_error("[ERR] Couldn't open the log file");
        return 0;
    }
    return logFile;
}

uint64_t metrics_get_total_connections(void) {
    FILE * f = get_file(ACCESS_FILE);

    uint64_t count = 0;
    char buffer[1024];

    while (fgets(buffer, sizeof(buffer), f)) {
        count++;
    }

    fclose(f);
    return count;
}

void metrics_add_bytes_received(uint64_t n) {
    total_bytes_received += n;
}

void metrics_add_bytes_sent(uint64_t n) {
    total_bytes_sent += n;
}

uint64_t metrics_get_concurrent_connections(void) {
    FILE * f = get_file(CONCURRENCIES_FILE);
    
    int value;

    if (fscanf(f, "%d", &value) != 1) {
        print_error("[ERR] Couldn't read file");
        fclose(f);
        return -1;
    }

    fclose(f);

    return value;

}

uint64_t metrics_get_total_bytes_received(void) {
    return total_bytes_received;
}

uint64_t metrics_get_total_bytes_sent(void) {
    return total_bytes_sent;
}

void metrics_print(void) {
    printf("=== Server metrics ===\n");
    printf("Total connections (from log): %llu\n", metrics_get_total_connections());
    printf("Concurrent connections: %llu\n", concurrent_connections);
    printf("Total bytes received: %llu\n", total_bytes_received);
    printf("Total bytes sent: %llu\n", total_bytes_sent);
}
