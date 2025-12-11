
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/evp.h>

#include "../../include/auth.h"

// Ruta a tu archivo CSV.
#define USERS_DB_FILE "users.csv"
#define MAX_LINE_LEN 512


// Función auxiliar: Calcula el SHA3-256 de un string usando OpenSSL
// Escribe el resultado (32 bytes) en el buffer 'out'
void compute_sha3(const char *password, unsigned char *out, unsigned int *out_len) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;

    md = EVP_sha3_256(); // Seleccionamos SHA3-256
    mdctx = EVP_MD_CTX_new();
    
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, out, out_len);
    
    EVP_MD_CTX_free(mdctx);
}

// Función auxiliar: Convierte binario a string Hexadecimal
static void bin2hex(const unsigned char *bin, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + (i * 2), "%02x", bin[i]);
    }
    out[len * 2] = '\0';
}


void get_sha3(const char *password, char *out) {
    unsigned char hash_bin[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    compute_sha3(password, hash_bin, &hash_len);

    bin2hex(hash_bin, hash_len, out);
}

bool auth_validate_user(const char *username, const char *password, int * role) {
    if (username == NULL || password == NULL) return false;

    FILE *file = fopen(USERS_DB_FILE, "r");
    if (file == NULL) {
        perror("[AUTH] Error abriendo base de datos de usuarios");
        return false; 
    }

    unsigned char hash_bin[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    char hash_hex[EVP_MAX_MD_SIZE * 2 + 1];

    compute_sha3(password, hash_bin, &hash_len);
    bin2hex(hash_bin, hash_len, hash_hex);

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
        char *file_hash = coma + 1;

        // El puntero file_hash ahora apunta a "hashed_password,role" (o solo hash si no hay rol)
        char *coma2 = strchr(file_hash, ',');
        if (coma2 != NULL) {
            // Si hay una segunda coma, cortamos ahí para ignorar el role
            *coma2 = '\0';
        }
        char *file_role = coma2+1;

        // Comparar
        if (strcmp(username, file_user) == 0 && strcmp(hash_hex, file_hash) == 0) {
            found = true;
            *role = atoi(file_role);
            break;
        }
    }

    fclose(file);
    return !found; // SUCCESS = 0
}
