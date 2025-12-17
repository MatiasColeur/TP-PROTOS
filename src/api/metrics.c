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

int metrics_find_user(const char *username, uint8_t **out_buf, size_t *out_len, uint64_t *out_matches) {
    FILE *f = read_file(ACCESS_FILE);
    if (f == NULL) {
        return -1;
    }

    char line[MAX_LINE];
    uint8_t *buffer = NULL;
    size_t buf_len = 0;
    size_t buf_cap = 0;
    uint64_t matches = 0;

    while (fgets(line, sizeof(line), f) != NULL) {

        char copy[MAX_LINE];
        strncpy(copy, line, sizeof(copy) - 1);
        copy[sizeof(copy) - 1] = '\0';

        char *saveptr = NULL;
        strtok_r(copy, "\t", &saveptr);        // timestamp
        char *user = strtok_r(NULL, "\t", &saveptr); // username

        if (user == NULL)
            continue;

        if (strcmp(user, username) != 0)
            continue;

        size_t line_len = strlen(line);

        if (buf_len + line_len > buf_cap) {
            size_t new_cap = buf_cap == 0 ? 1024 : buf_cap * 2;
            while (new_cap < buf_len + line_len)
                new_cap *= 2;

            uint8_t *tmp = realloc(buffer, new_cap);
            if (tmp == NULL) {
                free(buffer);
                fclose(f);
                return -1;
            }
            buffer = tmp;
            buf_cap = new_cap;
        }

        memcpy(buffer + buf_len, line, line_len);
        buf_len += line_len;
        matches++;
    }

    fclose(f);

    *out_buf = buffer;
    *out_len = buf_len;
    *out_matches = matches;

    return 0;
}
