#ifndef __ERRORS_H_
#define __ERRORS_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>


/**
 * Imprime un mensaje informativo en stdout con el prefijo [INF].
 * Ejemplo: log_info("Nueva conexión desde %s", ip_str);
 */
void print_info(const char *fmt, ...);

/**
 * Imprime un mensaje de éxito/debug en verde.
 */
void print_success(const char *fmt, ...);

/**
 * Imprime un mensaje de error en stderr con color ROJO y el prefijo [ERR].
 * Ejemplo: print_error("Fallo al conectar con %s", host);
 */
void print_error(const char *fmt, ...);

/**
 * Similar a perror(): Imprime el mensaje en ROJO seguido de la descripción 
 * del error actual en errno.
 * Ejemplo: log_perror("bind()"); -> "[ERR] bind(): Address already in use"
 */
void print_perror(const char *s);

void fprint_success(FILE * fd, const char *fmt,...);

void fprint_error(FILE *fd,const char *fmt, ...);

void fprint_info(FILE *fd, const char *fmt, ...);

void plain_fprint_success(FILE *fd,const char *fmt, ...);

void plain_fprint_error(FILE *fd,const char *fmt, ...);

#endif
