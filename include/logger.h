#ifndef __loger_h_
#define __loger_h_

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define ACCESS_FILE "log/access.txt"
#define LOGS_FILE "log/logs.txt"

void logAccess(char * username, char * password, char * hostname, int port);

/**
 * @brief Registra un mensaje informativo en el archivo de log.
 * * Abre el archivo de log, escribe el mensaje precedido por [INF] y fecha/hora (si
 * fprint_info lo implementa), y cierra el archivo.
 * * @param fmt Cadena de mensaje (texto plano).
 */
void log_info(const char *fmt);

/**
 * @brief Registra un mensaje de éxito en el archivo de log.
 * * Abre el archivo de log, escribe el mensaje precedido por [INF] (generalmente
 * asociado a operaciones exitosas) y cierra el archivo.
 * * @param fmt Cadena de mensaje (texto plano).
 */
void log_success(const char *fmt);

/**
 * @brief Registra un mensaje de error en el archivo de log.
 * * Abre el archivo de log, escribe el mensaje precedido por [ERR] para indicar
 * fallos críticos o advertencias y cierra el archivo.
 * * @param fmt Cadena de mensaje (texto plano).
 */
void log_error(const char *fmt);

#endif //__loger_h_
