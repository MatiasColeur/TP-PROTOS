#ifndef AUTH_H
#define AUTH_H

#include <stdbool.h>

/**
 * Valida si el par usuario/contraseña existe en el archivo de base de datos (CSV).
 * Formato esperado del CSV: usuario,contraseña
 */
bool auth_validate_user(const char *username, const char *password,int * role);

/**
 * @brief Obtiene el hash SHA3-256 en formato string hexadecimal.
 * * @param password La contraseña a hashear.
 * @param out Buffer de salida. DEBE tener al menos 65 bytes de tamaño.
 */
void get_sha3(const char *password, char *out);

#endif
