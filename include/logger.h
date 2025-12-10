#ifndef __loger_h_
#define __loger_h_

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

#define ACCESS_FILE "log/access.txt"
#define CONCURRENCIES_FILE "log/concurrencies.txt"
#define LOGS_FILE "log/logs.txt"
#define ERRORS_FILE "log/errors.txt"

void log_access(char * username, char * password, char * hostname, int port);

void log_exit();

/**
 * @brief Registra un mensaje informativo en el archivo de log.
 * * Abre el archivo de log, escribe el mensaje precedido por [INF] y fecha/hora (si
 * fprint_info lo implementa), y cierra el archivo.
 * * @param fmt Cadena de mensaje (texto plano).
 */
void log_info(const char *fmt, ...);
/**
 * @brief Registra un mensaje de éxito en el archivo de log.
 * * Abre el archivo de log, escribe el mensaje precedido por [INF] (generalmente
 * asociado a operaciones exitosas) y cierra el archivo.
 * * @param fmt Cadena de mensaje (texto plano).
 */
void log_success(const char *fmt, ...);

/**
 * @brief Registra un mensaje de error en el archivo de log.
 * * Abre el archivo de log, escribe el mensaje precedido por [ERR] para indicar
 * fallos críticos o advertencias y cierra el archivo.
 * * @param fmt Cadena de mensaje (texto plano).
 */
void log_error(const char *fmt, ...);

/**
 * @brief Combina log_info y print_info.
 * * 1. Escribe el mensaje formateado en LOGS_FILE.
 * 2. Imprime el mensaje formateado en stdout.
 * * @param fmt Cadena de mensaje con formato.
 */
void log_print_info(const char *fmt, ...);

/**
 * @brief Combina log_success y print_success.
 * * 1. Escribe el mensaje formateado en LOGS_FILE.
 * 2. Imprime el mensaje formateado en stdout con color VERDE.
 * * @param fmt Cadena de mensaje con formato.
 */
void log_print_success(const char *fmt, ...);

/**
 * @brief Combina log_error y print_error.
 * * 1. Escribe el mensaje formateado en LOGS_FILE y ERROR_FILE.
 * 2. Imprime el mensaje formateado en stderr con color ROJO.
 * * @param fmt Cadena de mensaje con formato.
 */
void log_print_error(const char *fmt, ...);
#endif //__loger_h_
