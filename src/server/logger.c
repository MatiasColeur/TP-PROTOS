#include "../../include/logger.h"
#include "../../include/errors.h"


static FILE * get_file(const char * file){
    FILE * logFile = fopen(file, "a");
    if (!logFile) {
        print_error("Couldn't open the log file");
        return 0;
    }
    return logFile;
}

void logAccess(char * username, char * password, char * hostname, int port) {
    FILE * logFile = get_file(ACCESS_FILE);

    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(logFile, "[%s] - %s:%s - Connected to %s port %d\n", timestamp, username, password, hostname, port);
    fclose(logFile);
}

void log_info(const char *fmt, ...) {
    va_list args;
    
    va_start(args, fmt);
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    FILE *logFile = get_file(LOGS_FILE);
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

    FILE *logFile = get_file(LOGS_FILE);
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

    FILE *logGeneral = get_file(LOGS_FILE);
    if (logGeneral) {
        plain_fprint_error(logGeneral, "%s", buffer);
        fclose(logGeneral);
    }

    FILE *logErrors = get_file(ERRORS_FILE);
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