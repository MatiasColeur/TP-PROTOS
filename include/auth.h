#ifndef AUTH_H
#define AUTH_H

#include <stdbool.h>

/**
 * Valida si el par usuario/contraseña existe en el archivo de base de datos (CSV).
 * Formato esperado del CSV: usuario,contraseña
 */
bool auth_validate_user(const char *username, const char *password,int * role);

#endif