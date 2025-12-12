#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdarg.h>

#include "../../include/parser_arguments.h"
#include "../../include/errors.h"

/* ---------- Helpers ---------- */

static void die_usage(const char *progname, const ArgParserConfig *cfg, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s: ", progname);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);

    print_help_ex(progname, cfg);
}

static void build_optstring(char out[64], const ArgParserConfig *cfg) {
    /* Base: -h -v -l: -p: */
    strcpy(out, "hvl:p:");

    if (cfg->enable_dissectors) strcat(out, "N");
    if (cfg->enable_aux)        strcat(out, "L:P:");
    if (cfg->enable_users)      strcat(out, "u:");
}

/* Copies "user:pass" into heap-owned strings stored in args */
static void handle_user(const char *progname, const char *arg, ProgramArgs *args) {
    if (args->user_count >= MAX_USERS) {
        fprintf(stderr, "%s: Ha excedido el límite de %d usuarios.\n", progname, MAX_USERS);
        exit(1);
    }

    const char *p = strchr(arg, ':');
    if (p == NULL) {
        fprintf(stderr, "%s: Formato de usuario inválido '%s'. Debe ser user:pass\n", progname, arg);
        exit(1);
    }

    size_t ulen = (size_t)(p - arg);
    size_t plen = strlen(p + 1);

    char *uname = malloc(ulen + 1);
    char *pass  = malloc(plen + 1);

    if (uname == NULL || pass == NULL) {
        free(uname);
        free(pass);
        fprintf(stderr, "%s: No hay memoria para usuario.\n", progname);
        exit(1);
    }

    memcpy(uname, arg, ulen);
    uname[ulen] = '\0';
    memcpy(pass, p + 1, plen + 1);

    args->users[args->user_count].name = uname;
    args->users[args->user_count].pass = pass;
    args->user_count++;
}

/* ---------- Public ---------- */

void args_init_defaults(ProgramArgs *args, const ArgParserConfig *cfg) {
    if (args == NULL || cfg == NULL) return;

    memset(args, 0, sizeof(*args));

    args->socks_addr = cfg->def_socks_addr;
    args->socks_port = cfg->def_socks_port;

    args->aux_addr   = cfg->def_aux_addr;
    args->aux_port   = cfg->def_aux_port;

    args->dissectors_enabled = true; /* default */
    args->user_count = 0;
}

void print_help_ex(const char *progname, const ArgParserConfig *cfg) {
    if (cfg != NULL && cfg->help_str != NULL) {
        fprintf(stderr, cfg->help_str, progname);
    } else {
        fprintf(stderr, "Usage: %s [OPTIONS]...\n", progname);
    }
    exit(0);
}

void print_version_ex(const ArgParserConfig *cfg) {
    if (cfg != NULL && cfg->version_str != NULL) {
        fprintf(stderr, "%s\n", cfg->version_str);
    }
    exit(0);
}

int parse_arguments_ex(int argc, const char *argv[], ProgramArgs *args, const ArgParserConfig *cfg) {
    if (argv == NULL || args == NULL || cfg == NULL) return -1;

    args_init_defaults(args, cfg);

    char optstring[64];
    build_optstring(optstring, cfg);

    opterr = 0; /* we print our own errors */
    int opt;

    while ((opt = getopt(argc, (char *const *)argv, optstring)) != -1) {
        switch (opt) {
            case 'h':
                print_help_ex(argv[0], cfg);
                break;

            case 'v':
                print_version_ex(cfg);
                break;

            case 'l':
                args->socks_addr = optarg;
                break;

            case 'p':
                args->socks_port = (uint16_t) atoi(optarg);
                break;

            case 'N':
                if (!cfg->enable_dissectors) die_usage(argv[0], cfg, "Opción -N no soportada");
                args->dissectors_enabled = false;
                break;

            case 'L':
                if (!cfg->enable_aux) die_usage(argv[0], cfg, "Opción -L no soportada");
                args->aux_addr = optarg;
                break;

            case 'P':
                if (!cfg->enable_aux) die_usage(argv[0], cfg, "Opción -P no soportada");
                args->aux_port = (uint16_t) atoi(optarg);
                break;

            case 'u':
                if (!cfg->enable_users) die_usage(argv[0], cfg, "Opción -u no soportada");
                handle_user(argv[0], optarg, args);
                break;

            case '?':
            default:
                if (optopt != 0) die_usage(argv[0], cfg, "Opción desconocida '-%c'", optopt);
                die_usage(argv[0], cfg, "Opción desconocida");
        }
    }

    return 0;
}

int validate_arguments_ex(const ProgramArgs *args, const ArgParserConfig *cfg) {
    if (args == NULL || cfg == NULL) {
        print_error("There are no arguments to validate.");
        return -1;
    }

    /* Primary endpoint always required */
    if (args->socks_port == 0 || args->socks_port > 65535) {
        print_error("Invalid SOCKS port (%u). Must be between 1 and 65535.", (unsigned)args->socks_port);
        return -1;
    }
    if (args->socks_addr == NULL || *args->socks_addr == '\0') {
        print_error("SOCKS address is null or empty.");
        return -1;
    }

    /* Auxiliary endpoint only if enabled */
    if (cfg->enable_aux) {
        if (args->aux_port == 0 || args->aux_port > 65535) {
            print_error("Invalid auxiliary port (%u). Must be between 1 and 65535.", (unsigned)args->aux_port);
            return -1;
        }
        if (args->aux_addr == NULL || *args->aux_addr == '\0') {
            print_error("Auxiliary address is null or empty.");
            return -1;
        }

        /* Optional: forbid same port */
        if (args->socks_port == args->aux_port) {
            print_error("Primary and auxiliary ports cannot be the same (%u).", (unsigned)args->socks_port);
            return -1;
        }
    }

    /* Users only if enabled */
    if (cfg->enable_users) {
        if (args->user_count < 0 || args->user_count > MAX_USERS) {
            print_error("Invalid user count (%d). Max allowed is %d.", args->user_count, MAX_USERS);
            return -1;
        }

        for (int i = 0; i < args->user_count; i++) {
            if (args->users[i].name == NULL || *args->users[i].name == '\0' ||
                args->users[i].pass == NULL || *args->users[i].pass == '\0') {
                print_error("User #%d has empty username or password.", i + 1);
                return -1;
            }
        }
    }

    return 0;
}

void args_destroy(ProgramArgs *args, const ArgParserConfig *cfg) {
    if (args == NULL || cfg == NULL) return;

    if (cfg->enable_users) {
        for (int i = 0; i < args->user_count; i++) {
            free(args->users[i].name);
            free(args->users[i].pass);
            args->users[i].name = NULL;
            args->users[i].pass = NULL;
        }
        args->user_count = 0;
    }
}
