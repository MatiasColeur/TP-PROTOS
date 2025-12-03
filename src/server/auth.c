
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "../../include/auth.h"

// Ruta a tu archivo CSV.
#define USERS_DB_FILE "users.csv"
#define MAX_LINE_LEN 512

bool auth_validate_user(const char *username, const char *password) {
    if (username == NULL || password == NULL) return false;

    FILE *file = fopen(USERS_DB_FILE, "r");
    if (file == NULL) {
        perror("[AUTH] Error abriendo base de datos de usuarios");
        return false; 
    }

    char line[MAX_LINE_LEN];
    bool found = false;

    while (fgets(line, sizeof(line), file)) {
        // Remover el salto de línea al final (\n o \r\n)
        line[strcspn(line, "\r\n")] = 0;

        // Buscar el separador (coma)
        char *coma = strchr(line, ',');
        if (coma == NULL) continue; // Línea inválida

        // Separar usuario y contraseña modificando el string en memoria
        *coma = '\0';
        char *file_user = line;
        char *file_pass = coma + 1;

        // Comparar
        if (strcmp(username, file_user) == 0 && strcmp(password, file_pass) == 0) {
            found = true;
            break;
        }
    }

    fclose(file);
    return found;
}