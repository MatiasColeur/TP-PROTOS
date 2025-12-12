#ifndef PARSER_ARGUMENTS_H
#define PARSER_ARGUMENTS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdnoreturn.h>


#define MAX_USERS 10

typedef struct {
    char *name;
    char *pass;
} User;

typedef struct {
    /* Primary endpoint: -l / -p
     * server: bind/listen
     * client: connect (server socks)
     */
    const char *socks_addr;
    uint16_t    socks_port;

    /* Auxiliary endpoint: -L / -P
     * server: management bind/listen
     * client: destination host/port (CONNECT target)
     */
    const char *aux_addr;
    uint16_t    aux_port;

    /* Optional features (enabled/disabled by config) */
    bool  dissectors_enabled;  // -N => false
    User  users[MAX_USERS];    // -u
    int   user_count;
} ProgramArgs;

typedef struct {
    /* What to print */
    const char *version_str;   // printed as-is (plus '\n')
    const char *help_str;      // may contain %s for progname

    /* Defaults */
    const char *def_socks_addr;
    uint16_t    def_socks_port;

    const char *def_aux_addr;  // -L
    uint16_t    def_aux_port;  // -P

    /* Feature toggles */
    bool enable_aux;         // enables -L/-P
    bool enable_users;       // enables -u
    bool enable_dissectors;  // enables -N
} ArgParserConfig;


void args_init_defaults(ProgramArgs *args, const ArgParserConfig *cfg);

noreturn void print_help_ex(const char *progname, const ArgParserConfig *cfg);

noreturn void print_version_ex(const ArgParserConfig *cfg);

int  parse_arguments_ex(int argc, const char *argv[], ProgramArgs *args, const ArgParserConfig *cfg);
int  validate_arguments_ex(const ProgramArgs *args, const ArgParserConfig *cfg);

/* Frees memory allocated during parsing (e.g., -u user:pass copies) */
void args_destroy(ProgramArgs *args, const ArgParserConfig *cfg);

#endif /* PARSER_ARGUMENTS_H */
