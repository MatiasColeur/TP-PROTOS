#include "../../include/metrics.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>

static FILE * read_file(const char * file){
    FILE * logFile = fopen(file, "r"); //opens the file in read mode
    if (!logFile) {
        print_error("[ERR] Couldn't open the log file");
        return 0;
    }
    return logFile;
}


uint64_t metrics_get_total_connections(void) {
    FILE * f = read_file(ACCESS_FILE);

    uint64_t count = 0;
    char buffer[1024];

    while (fgets(buffer, sizeof(buffer), f)) {
        count++;
    }

    fclose(f);
    return count;
}

static uint64_t read_int_from_log_file(char * logFilePath) {
    FILE * f = read_file(logFilePath);
    if (f == NULL) {
        return -1;
    }
    
    uint64_t value;

    if (fscanf(f, "%" SCNu64, &value) != 1) {
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

void metrics_find_user(const char *username) {

    FILE *f = read_file(ACCESS_FILE);

    char line[MAX_LINE];

    while (fgets(line, sizeof(line), f) != NULL) {

        const char *p = strstr(line, "] - ");
        if (p == NULL) continue;

        p += strlen("] - ");

        char user_in_line[128];
        int i = 0;

        while (p[i] != ':' &&
               p[i] != '\0' &&
               i < (int)sizeof(user_in_line)-1) {

            user_in_line[i] = p[i];
            i++;
        }
        user_in_line[i] = '\0';

        if (strcmp(user_in_line, username) == 0) {
            printf("%s", line);
        }
    }

    fclose(f);
}




void metrics_print(void) {
    printf("=== Server metrics ===\n");
    printf("Total connections (from log): %" PRIu64 "\n", metrics_get_total_connections());
    // printf("Concurrent connections: %llu\n", concurrent_connections);
    // printf("Total bytes received: %llu\n", bytes_transfered);
}
