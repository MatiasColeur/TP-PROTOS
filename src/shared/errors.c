#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "../../include/errors.h" 

// Códigos ANSI para colores
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_RESET   "\x1b[0m"


// Función auxiliar para centralizar la lógica de impresión
static void v_print_format(FILE *fd, const char *color, const char *prefix, const char *fmt, va_list args) {
    if (color != NULL) {
        fprintf(fd, "%s", color);
    }
    
    fprintf(fd, "%s ", prefix);
    vfprintf(fd, fmt, args);
    
    if (color != NULL) {
        fprintf(fd, "%s", COLOR_RESET);
    }
    
    fprintf(fd, "\n");
}

void fprint_info(FILE *fd, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    v_print_format(fd, NULL, "[INF]", fmt, args);
    va_end(args);
}

void fprint_success(FILE *fd, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    v_print_format(fd, COLOR_GREEN, "[SUC]", fmt, args);
    va_end(args);
}

void fprint_error(FILE *fd, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    v_print_format(fd, COLOR_RED, "[ERR]", fmt, args);
    va_end(args);
}

void print_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    v_print_format(stdout, NULL, "[INF]", fmt, args);
    va_end(args);
}

void print_success(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    v_print_format(stdout, COLOR_GREEN, "[SUC]", fmt, args);
    va_end(args);
}

void print_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    v_print_format(stderr, COLOR_RED, "[ERR]", fmt, args);
    va_end(args);
}

void print_perror(const char *s) {
    int errnum = errno;
    
    fprintf(stderr, "%s[ERR] %s: %s%s\n", 
            COLOR_RED, 
            s, 
            strerror(errnum), 
            COLOR_RESET);
}

void plain_fprint_success(FILE *fd,const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    v_print_format(fd, NULL, "[SUC]", fmt, args);
    va_end(args);
}

void plain_fprint_error(FILE *fd,const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    v_print_format(fd, NULL, "[ERR]", fmt, args);
    va_end(args);
}
