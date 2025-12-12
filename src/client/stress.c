#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "../../include/parser_arguments.h"

#define TIMEOUT_SEC 5

static const ArgParserConfig STRESS_CFG = {
    .version_str = "SOCKS5 Stress Client v1.0",
    .help_str =
        "Usage: %s [OPTIONS] <concurrency> [<target_host> <target_port>]\n"
        "  -l <SOCKS addr>  Dirección del proxy (default: 127.0.0.1)\n"
        "  -p <SOCKS port>  Puerto del proxy (default: 1080)\n"
        "  -L <dst host>    Host destino del CONNECT (default: 127.0.0.1)\n"
        "  -P <dst port>    Puerto destino del CONNECT (default: 80)\n"
        "  -h / -v          Ayuda o versión\n",

    .def_socks_addr = "127.0.0.1",
    .def_socks_port = 1080,

    .def_aux_addr = "127.0.0.1",
    .def_aux_port = 80,

    .enable_aux        = true,  /* -L/-P selects CONNECT target */
    .enable_users      = false,
    .enable_dissectors = false,
};

// Estadísticas Atómicas (Thread-Safe)
atomic_int success_count = 0;
atomic_int failure_count = 0;

typedef struct {
    int id;
    const char *socks_addr;
    uint16_t socks_port;
    const char *target_host;
    int target_port;
} thread_arg_t;

// Función auxiliar para conectar TCP
int connect_tcp(const char *socks_addr, uint16_t socks_port) {
    int sockfd;
    struct sockaddr_in serv_addr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) return -1;

    // Timeout para no colgar el test eternamente si el servidor explota
    struct timeval tv;
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(socks_port);
    if (inet_pton(AF_INET, socks_addr, &serv_addr.sin_addr) <= 0) {
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sockfd);
        return -1;
    }
    return sockfd;
}

// Lógica de un cliente individual (retorna 0 éxito, -1 fallo)
int run_client_logic(const thread_arg_t *data) {
    (void)data->id; /* id disponible para debug si se requiere */

    int sockfd = connect_tcp(data->socks_addr, data->socks_port);
    if (sockfd < 0) return -1;

    char buf[512];
    ssize_t n;

    // --- 1. Handshake ---
    char hello[] = { 0x05, 0x01, 0x02 };
    if (send(sockfd, hello, sizeof(hello), 0) < 0) goto error;
    
    n = recv(sockfd, buf, sizeof(buf), 0);
    if (n < 2 || buf[1] != 0x02) goto error;

    // --- 2. Auth ---
    char auth_req[] = { 0x01, 0x05, 'a','d','m','i','n', 0x05, 'a','d','m','i','n' };
    if (send(sockfd, auth_req, sizeof(auth_req), 0) < 0) goto error;

    n = recv(sockfd, buf, sizeof(buf), 0);
    if (n < 2 || buf[1] != 0x00) goto error;

    // --- 3. Request (CONNECT) ---
    // Construimos request para Dominio (ATYP 0x03)
    int idx = 0;
    buf[idx++] = 0x05;
    buf[idx++] = 0x01; // CONNECT
    buf[idx++] = 0x00;
    buf[idx++] = 0x03; // DOMAIN
    
    int domain_len = strlen(data->target_host);
    buf[idx++] = (uint8_t)domain_len;
    memcpy(&buf[idx], data->target_host, domain_len);
    idx += domain_len;
    
    uint16_t p = htons(data->target_port);
    memcpy(&buf[idx], &p, 2);
    idx += 2;

    if (send(sockfd, buf, idx, 0) < 0) goto error;

    // Esperar Reply
    n = recv(sockfd, buf, sizeof(buf), 0);
    if (n < 4 || buf[1] != 0x00) {
        // Si el servidor responde error (ej. 0x05 Connection Refused), 
        // cuenta como fallo de conexión al destino, pero el protocolo funcionó.
        // Para el stress test, consideraremos fallo si no pudimos establecer túnel.
        goto error; 
    }

    // --- 4. Tunnel Test (Opcional: Enviar 1 byte y esperar eco) ---
    // Si llegamos aquí, el túnel está abierto.
    close(sockfd);
    return 0;

error:
    close(sockfd);
    return -1;
}

// Wrapper para pthread
void *worker_thread(void *arg) {
    thread_arg_t *data = (thread_arg_t *)arg;
    
    if (run_client_logic(data) == 0) {
        atomic_fetch_add(&success_count, 1);
        // printf("."); // Feedback visual mínimo (opcional)
    } else {
        atomic_fetch_add(&failure_count, 1);
        printf("F"); // Feedback visual de error
    }
    
    fflush(stdout);
    free(data);
    return NULL;
}

int main(int argc, const char *argv[]) {
    ProgramArgs args;

    if (parse_arguments_ex(argc, argv, &args, &STRESS_CFG) < 0) {
        return EXIT_FAILURE;
    }

    if (optind >= argc) {
        fprintf(stderr, "Uso: %s [opciones] <concurrency> [<target_host> <target_port>]\n", argv[0]);
        args_destroy(&args, &STRESS_CFG);
        return EXIT_FAILURE;
    }

    int concurrency = atoi(argv[optind++]);
    if (concurrency <= 0) {
        fprintf(stderr, "Concurrency debe ser un entero positivo.\n");
        args_destroy(&args, &STRESS_CFG);
        return EXIT_FAILURE;
    }

    if (optind < argc) {
        args.aux_addr = argv[optind++];
    }
    if (optind < argc) {
        args.aux_port = (uint16_t) atoi(argv[optind++]);
    }
    if (optind < argc) {
        fprintf(stderr, "Argumentos extra no reconocidos.\n");
        args_destroy(&args, &STRESS_CFG);
        return EXIT_FAILURE;
    }

    if (validate_arguments_ex(&args, &STRESS_CFG) < 0) {
        args_destroy(&args, &STRESS_CFG);
        return EXIT_FAILURE;
    }

    printf("=== Iniciando Stress Test SOCKS5 ===\n");
    printf("Usuarios Concurrentes: %d\n", concurrency);
    printf("Objetivo a través del Proxy: %s:%d\n", args.aux_addr, args.aux_port);
    printf("------------------------------------\n");

    pthread_t *threads = malloc(sizeof(pthread_t) * concurrency);
    
    // 1. Lanzar Hilos
    for (int i = 0; i < concurrency; i++) {
        thread_arg_t *arg = malloc(sizeof(thread_arg_t));
        arg->id = i;
        arg->socks_addr = args.socks_addr;
        arg->socks_port = args.socks_port;
        arg->target_host = args.aux_addr;
        arg->target_port = args.aux_port;

        if (pthread_create(&threads[i], NULL, worker_thread, arg) != 0) {
            perror("Error creando hilo");
            atomic_fetch_add(&failure_count, 1);
        }
    }

    // 2. Esperar Hilos
    for (int i = 0; i < concurrency; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);

    printf("\n------------------------------------\n");
    printf("RESULTADOS:\n");
    printf("Exitosos: %d\n", atomic_load(&success_count));
    printf("Fallidos: %d\n", atomic_load(&failure_count));
    
    double success_rate = (double)success_count / concurrency * 100.0;
    printf("Tasa de Éxito: %.2f%%\n", success_rate);

    args_destroy(&args, &STRESS_CFG);
    return (failure_count == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
