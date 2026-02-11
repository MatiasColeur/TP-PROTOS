#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../include/shared.h"
#include "../../include/client_utils.h"
#include "../../include/parser_arguments.h"
#include "../../include/errors.h"

/*
 * Cliente de prueba HTTP en claro a traves del proxy SOCKS5.
 * Permite disparar el dissector HTTP (Basic Auth o form urlencoded).
 *
 * Uso:
 *   ./bin/client_http_probe [OPCIONES] [<user> <pass>]
 *
 * Opciones (parser comun):
 *   -l <SOCKS addr>  Direccion del proxy (default: 127.0.0.1)
 *   -p <SOCKS port>  Puerto del proxy (default: 1080)
 *   -L <dst host>    Host destino HTTP (default: 127.0.0.1)
 *   -P <dst port>    Puerto destino HTTP (default: 8080)
 *   -h / -v          Ayuda o version
 *   Modo: opcional tercer posicional "form" (default: Basic Auth)
 */
static const ArgParserConfig HTTP_PROBE_CFG = {
    .version_str = "SOCKS5 HTTP Probe v1.0",
    .help_str =
        "Usage: %s [OPTIONS] [<user> <pass>]\n"
        "  -l <SOCKS addr>  Direccion del proxy SOCKS (default: 127.0.0.1)\n"
        "  -p <SOCKS port>  Puerto del proxy SOCKS (default: 1080)\n"
        "  -L <dest host>   Host destino HTTP (default: 127.0.0.1)\n"
        "  -P <dest port>   Puerto destino HTTP (default: 8080)\n"
        "  -h / -v          Ayuda o version\n"
        "Posicionales opcionales: <user> <pass> [form] (default: alice/secret)\n",

    .def_socks_addr = "127.0.0.1",
    .def_socks_port = 1080,

    .def_aux_addr = "127.0.0.1",
    .def_aux_port = 8080,

    .enable_aux        = true,
    .enable_users      = false,
    .enable_dissectors = false,
};

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t b64_encode(const unsigned char *in, size_t in_len, char *out, size_t out_cap) {
    size_t i = 0, o = 0;
    while (i < in_len) {
        unsigned int v = 0;
        int rem = (int)(in_len - i);

        v |= (unsigned int)in[i++] << 16;
        if (rem > 1) v |= (unsigned int)in[i++] << 8;
        if (rem > 2) v |= (unsigned int)in[i++];

        if (o + 4 >= out_cap) break;
        out[o++] = b64_table[(v >> 18) & 0x3F];
        out[o++] = b64_table[(v >> 12) & 0x3F];
        out[o++] = (rem > 1) ? b64_table[(v >> 6) & 0x3F] : '=';
        out[o++] = (rem > 2) ? b64_table[v & 0x3F] : '=';
    }
    out[o] = '\0';
    return o;
}

static int send_all(int fd, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

int main(int argc, const char *argv[]) {
    ProgramArgs args;
    const char *user = "alice";
    const char *pass = "secret";
    bool use_form = false;

    if (parse_arguments_ex(argc, argv, &args, &HTTP_PROBE_CFG) < 0) {
        return EXIT_FAILURE;
    }

    if (optind < argc) {
        user = argv[optind++];
    }
    if (optind < argc) {
        pass = argv[optind++];
    }
    if (optind < argc && strcmp(argv[optind], "form") == 0) {
        use_form = true;
        optind++;
    }
    if (optind < argc) {
        fprintf(stderr, "Argumentos extra no reconocidos.\n");
        args_destroy(&args, &HTTP_PROBE_CFG);
        return EXIT_FAILURE;
    }

    if (validate_arguments_ex(&args, &HTTP_PROBE_CFG) < 0) {
        args_destroy(&args, &HTTP_PROBE_CFG);
        return EXIT_FAILURE;
    }

    int sockfd = create_client_socket(args.socks_addr, args.socks_port);
    if (sockfd < 0) {
        args_destroy(&args, &HTTP_PROBE_CFG);
        return EXIT_FAILURE;
    }

    perform_handshake(sockfd, "admin", "admin");
    perform_request_domain(sockfd, args.aux_addr, args.aux_port);

    char request[2048];
    if (!use_form) {
        char cred[256];
        char b64[512];
        snprintf(cred, sizeof(cred), "%s:%s", user, pass);
        b64_encode((const unsigned char *)cred, strlen(cred), b64, sizeof(b64));

        int n = snprintf(request, sizeof(request),
                         "GET / HTTP/1.1\r\n"
                         "Host: %s\r\n"
                         "Authorization: Basic %s\r\n"
                         "Connection: close\r\n"
                         "\r\n",
                         args.aux_addr, b64);
        if (n < 0 || (size_t)n >= sizeof(request)) {
            print_error("Request too long");
            close(sockfd);
            args_destroy(&args, &HTTP_PROBE_CFG);
            return EXIT_FAILURE;
        }
    } else {
        char body[512];
        int body_len = snprintf(body, sizeof(body), "username=%s&password=%s", user, pass);
        if (body_len < 0 || (size_t)body_len >= sizeof(body)) {
            print_error("Body too long");
            close(sockfd);
            args_destroy(&args, &HTTP_PROBE_CFG);
            return EXIT_FAILURE;
        }
        int n = snprintf(request, sizeof(request),
                         "POST /login HTTP/1.1\r\n"
                         "Host: %s\r\n"
                         "Content-Type: application/x-www-form-urlencoded\r\n"
                         "Content-Length: %d\r\n"
                         "Connection: close\r\n"
                         "\r\n"
                         "%s",
                         args.aux_addr, body_len, body);
        if (n < 0 || (size_t)n >= sizeof(request)) {
            print_error("Request too long");
            close(sockfd);
            args_destroy(&args, &HTTP_PROBE_CFG);
            return EXIT_FAILURE;
        }
    }

    if (send_all(sockfd, request, strlen(request)) != 0) {
        print_error("No se pudo enviar request HTTP");
        close(sockfd);
        args_destroy(&args, &HTTP_PROBE_CFG);
        return EXIT_FAILURE;
    }

    print_success("Request HTTP enviado a traves del proxy");

    sleep(1);
    close(sockfd);
    args_destroy(&args, &HTTP_PROBE_CFG);
    return EXIT_SUCCESS;
}
