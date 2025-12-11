#ifndef PARSER_H
#define PARSER_H

// Structure to hold all program parameters
typedef struct {
    char *addr; // Dirección IP (ej: "0.0.0.0" o "127.0.0.1")
    int port;        // Puerto (ej: 1080)

    // Solo para el cliente de stress/prueba:
    char *target_host;
    int target_port;
    int concurrency;
} ProgramArgs;


// Function prototypes
void print_help(const char *program_name);

/**
 * @brief Parsea los argumentos de línea de comandos.
 * Llena la estructura args con los valores encontrados o defaults.
 */
int parse_arguments(int argc, char *argv[], ProgramArgs *args);
/**
 * @brief Valida la lógica de los argumentos.
 * Verifica rangos de puertos, punteros nulos, etc.
 * @return 0 si es válido, -1 si hay error.
 */
int validate_arguments(const ProgramArgs *args);


#endif // PARSER_H