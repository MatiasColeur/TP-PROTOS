#ifndef PARSER_ARGUMENTS_H
#define PARSER_ARGUMENTS_H

#include <stdbool.h>

#define MAX_USERS 10

typedef struct {
    char *name;
    char *pass;
} User;

typedef struct {
    char *socks_addr;       // -l
    int   socks_port;       // -p
    
    char *mng_addr;         // -L
    int   mng_port;         // -P
    
    bool  disectors_enabled;// -N (true por defecto, false si se pasa -N)
    
    User  users[MAX_USERS]; // -u
    int   user_count;
} ProgramArgs;

// Function prototypes
void print_help(const char *program_name);

/**
 * @brief Parsea los argumentos de línea de comandos.
 * Llena la estructura args con los valores encontrados o defaults.
 */
void parse_arguments(int argc, const char* argv[], ProgramArgs *args);
/**
 * @brief Valida la lógica de los argumentos.
 * Verifica rangos de puertos, punteros nulos, etc.
 * @return 0 si es válido, -1 si hay error.
 */
int validate_arguments(const ProgramArgs *args);


#endif // PARSER_H
