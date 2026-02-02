#include "../../include/metrics.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>

static FILE * read_file(const char * file){
    FILE * logFile = fopen(file, "r"); //opens the file in read mode
    if (!logFile) {
        print_error("Couldn't open the log file");
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
    if (f == NULL) {
        perror("Error abriendo access file");
        return;
    }

    char line[MAX_LINE];

    while (fgets(line, sizeof(line), f) != NULL) {

        char copy[MAX_LINE];
        strncpy(copy, line, sizeof(copy));
        copy[sizeof(copy)-1] = '\0';   // <-- FIX importante

        // parseo por TAB
        strtok(copy, "\t");  // timestamp
        char *field2 = strtok(NULL, "\t");  // username  <---- IMPORTANTE

        if (field2 == NULL)
            continue;

        // remover salto de línea
        field2[strcspn(field2, "\r\n")] = '\0';

        if (strcmp(field2, username) == 0) {
            printf("%s", line);
        }
    }

    fclose(f);
}


