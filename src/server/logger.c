#include "../../include/logger.h"
#include "../../include/errors.h"

void logAccess(char * username, char * password, char * hostname, int port) {
    FILE * logFile = fopen("log/access.txt", "a");
    if (!logFile) {
        log_error("Couldn't open the log file");
        return;
    }

    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(logFile, "[%s] - %s:%s - Connected to %s port %d\n", timestamp, username, password, hostname, port);
    fclose(logFile);
}