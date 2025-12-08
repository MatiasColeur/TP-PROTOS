#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <errno.h>


// Códigos ANSI para colores
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_RESET   "\x1b[0m"


void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    // Imprime [INF] y luego el mensaje
    fprintf(stdout, "[INF] ");
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "\n");

    va_end(args);
}

void log_success(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    // Imprime [INF] en verde
    fprintf(stdout, "%s[SUC] ", COLOR_GREEN);
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "%s\n", COLOR_RESET);

    va_end(args);
}

void log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    // Imprime [ERR] en rojo, el mensaje, y resetea el color
    fprintf(stderr, "%s[ERR] ", COLOR_RED);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "%s\n", COLOR_RESET);

    va_end(args);
}

void log_perror(const char *s) {
    // Obtiene el error del sistema antes de que otra llamada lo limpie
    int errnum = errno;
    
    fprintf(stderr, "%s[ERR] %s: %s%s\n", 
            COLOR_RED, 
            s, 
            strerror(errnum), 
            COLOR_RESET);
}