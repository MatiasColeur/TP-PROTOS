#include "../../include/logger.h"
#include "../../include/errors.h"
#include <pthread.h>

uint64_t concurrent_connections = 0;

/*---------- STATIC FUNCTIONS ----------*/

static FILE * get_file(const char * file, const char * mode) {
    FILE * f = fopen(file, mode);
    if (!f) {
        print_error("Couldn't open the log file");
        return 0;
    }
    return f; 
}

inline static FILE * get_file_append(const char * file){
    return get_file(file, "a");
}

inline static FILE * get_file_write(const char * file) {
    return get_file(file, "w");
}

inline static FILE * get_file_read(const char * file) {
    return get_file(file, "r");
}

/*---------- LOGGER FUNCTIONS ----------*/

void log_access(char * username, char * password, char * hostname, int port) {
    FILE * accessFile = get_file_append(ACCESS_FILE);
    FILE * concurrenciesFile = get_file_write(CONCURRENCIES_FILE);

    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(accessFile, "[%s] - %s:%s - Connected to %s port %d\n", timestamp, username, password, hostname, port);

    int value = ++concurrent_connections;
    fprintf(concurrenciesFile,"%d\n", value);

    fclose(accessFile);
    fclose(concurrenciesFile);
}

void log_exit(void) {
    FILE * concurrenciesFile = get_file_write(CONCURRENCIES_FILE);

    if (concurrent_connections > 0) 
        concurrent_connections--;

    fprintf(concurrenciesFile, "%lld\n", concurrent_connections);
    fclose(concurrenciesFile);

    return;
}

void log_bytes(uint64_t bytes) {

    uint64_t value = 0;

    FILE *fr = get_file_read(BYTES_FILE);
    if (fr != NULL) {
        if (fscanf(fr, "%llu", &value) != 1) {
            value = 0;
        }
        fclose(fr);
    }

    FILE *fw = get_file_write(BYTES_FILE);
    fprintf(fw, "%llu\n", value + bytes);
    fclose(fw);
}


void log_info(const char *fmt, ...) {
    va_list args;
    
    va_start(args, fmt);
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    FILE *logFile = get_file_append(LOGS_FILE);
    if (logFile) {
        fprint_info(logFile, "%s", buffer);
        fclose(logFile);
    }
}

void log_success(const char *fmt, ...) {
    va_list args;
    char buffer[1024];
    
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    FILE *logFile = get_file_append(LOGS_FILE);
    if (logFile) {
        plain_fprint_success(logFile, "%s", buffer); 
        fclose(logFile);
    }
}

void log_error(const char *fmt, ...) {
    va_list args;
    char buffer[1024];

    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    FILE *logGeneral = get_file_append(LOGS_FILE);
    if (logGeneral) {
        plain_fprint_error(logGeneral, "%s", buffer);
        fclose(logGeneral);
    }

    FILE *logErrors = get_file_append(ERRORS_FILE);
    if (logErrors) {
        plain_fprint_error(logErrors, "%s", buffer);
        fclose(logErrors);
    }
}


void log_print_info(const char *fmt, ...) {
    va_list args;
    char buffer[2048];

    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    log_info("%s", buffer);
    print_info("%s", buffer);
}

void log_print_success(const char *fmt, ...) {
    va_list args;
    char buffer[2048];

    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    log_success("%s", buffer);
    print_success("%s", buffer);
}

void log_print_error(const char *fmt, ...) {
    va_list args;
    char buffer[2048];

    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    log_error("%s", buffer);
    print_error("%s", buffer);
}
