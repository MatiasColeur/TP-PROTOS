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

void log_info(const char *fmt){
    FILE * logFile = get_file(LOGS_FILE);

    fprint_info(logFile,fmt);

    fclose(logFile);
}

void log_success(const char *fmt){
    FILE * logFile = get_file(LOGS_FILE);

    plain_fprint_success(logFile,fmt);

    fclose(logFile);
}

void log_error(const char *fmt){
    FILE * logFile = get_file(LOGS_FILE);

    fprint_error(logFile,fmt);
    fclose(logFile);
}