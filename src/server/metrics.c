#include "../../include/metrics.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

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

static uint64_t read_int_from_log_file(char * logFilePath) {
    FILE * f = get_file(logFilePath);
    
    uint64_t value;

    if (fscanf(f, "%llu", &value) != 1) {
        print_error("[ERR] Couldn't read file");
        fclose(f);
        return -1;
    }

    fclose(f);

    return value;

}

uint64_t metrics_get_concurrent_connections(void) {
    return read_int_from_log_file(CONCURRENCIES_FILE);

}

uint64_t metrics_get_bytes(void) {
    return read_int_from_log_file(BYTES_FILE);
}


void metrics_print(void) {
    printf("=== Server metrics ===\n");
    printf("Total connections (from log): %llu\n", metrics_get_total_connections());
    // printf("Concurrent connections: %llu\n", concurrent_connections);
    // printf("Total bytes received: %llu\n", bytes_transfered);
}
