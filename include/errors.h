#ifndef __ERRORS_H_
#define __ERRORS_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>


/**
 * Imprime un mensaje informativo en stdout con el prefijo [INF].
 * Ejemplo: log_info("Nueva conexión desde %s", ip_str);
 */
void log_info(const char *fmt, ...);

/**
 * Imprime un mensaje de éxito/debug en verde.
 */
void log_success(const char *fmt, ...);

/**
 * Imprime un mensaje de error en stderr con color ROJO y el prefijo [ERR].
 * Ejemplo: log_error("Fallo al conectar con %s", host);
 */
void log_error(const char *fmt, ...);

/**
 * Similar a perror(): Imprime el mensaje en ROJO seguido de la descripción 
 * del error actual en errno.
 * Ejemplo: log_perror("bind()"); -> "[ERR] bind(): Address already in use"
 */
void log_perror(const char *s);

#endif