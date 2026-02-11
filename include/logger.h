#ifndef __loger_h_
#define __loger_h_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include "errors.h"

#define ACCESS_FILE "log/access.txt"
#define CONCURRENCIES_FILE "log/concurrencies.txt"
#define BYTES_FILE "log/bytes.txt"
#define LOGS_FILE "log/logs.txt"
#define ERRORS_FILE "log/errors.txt"
#define CREDENTIALS_FILE "log/credentials.txt"

void init_log(void);

void log_access(char * username, 
                char * hostname, 
                int port, 
                int client_port, 
                char * client_ip, 
                int status);

void log_exit(void);

void log_bytes(uint64_t bytes);

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

/**
 * @brief Registra credenciales capturadas por un dissector (ej. POP3).
 */
void log_credentials(const char *requester_user,
                     const char *protocol,
                     const char *dst_host,
                     int dst_port,
                     const char *captured_user,
                     const char *captured_password);
#endif //__loger_h_
