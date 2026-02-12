#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <stdatomic.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>

#include "../../include/parser_arguments.h" 
#include "../../include/client_utils.h"

static const ArgParserConfig STRESS_TP_CFG = {
    .version_str = "SOCKS5 Throughput Stress Client v1.0",
    .help_str =
        "Usage: %s [OPTIONS] <concurrency> <duration_sec> <payload_bytes KB>\n"
        "  -l <SOCKS addr>  Dirección del proxy (default: 127.0.0.1)\n"
        "  -p <SOCKS port>  Puerto del proxy (default: 1080)\n"
        "  -L <dst host>    Host destino del CONNECT (default: 127.0.0.1)\n"
        "  -P <dst port>    Puerto destino del CONNECT (default: 9090)\n"
        "  -h / -v          Ayuda o versión\n",

    .def_socks_addr = "127.0.0.1",
    .def_socks_port = 1080,

    .def_aux_addr = "127.0.0.1",
    .def_aux_port = 9090,

    .enable_aux        = true,
    .enable_users      = false,
    .enable_dissectors = false,
};

// --- Configuración Global (Puente entre Args y Hilos) ---
struct {
    char socks_addr[256];
    int  socks_port;
    char target_host[256];
    int  target_port;
    size_t payload_size;
} global_conf;

// --- Variables Globales Atómicas para Estadísticas ---
atomic_long bytes_sent = 0;
atomic_long bytes_recv = 0;
atomic_int  tunnels_ok = 0;
atomic_int  tunnels_fail = 0;
volatile sig_atomic_t stop_benchmark = 0;

static int connect_socks5_tunnel(void) {
    // 1. Crear Socket
    int sockfd = create_client_socket(global_conf.socks_addr, global_conf.socks_port);
    if (sockfd < 0) return -1;

    // 2. Handshake + Autenticación (admin/admin)
    // Aquí llamamos a la nueva función
    perform_handshake_thread(sockfd, "admin", "admin");
    

    // 3. Request (Lógica dinámica IP vs Dominio)
    struct sockaddr_in sa;
    
    if (inet_pton(AF_INET, global_conf.target_host, &(sa.sin_addr)) != 0) {
        perform_request_ipv4_thread(sockfd, global_conf.target_host, global_conf.target_port);
    } else {
        perform_request_domain_thread(sockfd, global_conf.target_host, global_conf.target_port);
    }

    return sockfd; // Túnel listo
}

// --- Worker Thread ---
void *worker_thread(void *arg) {
    char *tx_buf = malloc(global_conf.payload_size);
    char *rx_buf = malloc(global_conf.payload_size);
    
    if (!tx_buf || !rx_buf) {
        atomic_fetch_add(&tunnels_fail, 1);
        if (tx_buf) free(tx_buf);
        if (rx_buf) free(rx_buf);
        return NULL;
    }
    
    // Rellenamos con datos basura
    memset(tx_buf, 'A', global_conf.payload_size);

    int sock = connect_socks5_tunnel();
    if (sock < 0) {
        atomic_fetch_add(&tunnels_fail, 1);
        free(tx_buf);
        free(rx_buf);
        return NULL;
    }

    atomic_fetch_add(&tunnels_ok, 1);

    while (!stop_benchmark) {
        ssize_t sent = send(sock, tx_buf, global_conf.payload_size, 0);
        if (sent <= 0) break;
        atomic_fetch_add(&bytes_sent, sent);

        ssize_t received = 0;
        while (received < sent) {
            ssize_t n = recv(sock, rx_buf + received, sent - received, 0);
            if (n <= 0) goto cleanup;
            received += n;
        }
        atomic_fetch_add(&bytes_recv, received);
    }

cleanup:
    close(sock);
    free(tx_buf);
    free(rx_buf);
    return NULL;
}

// --- Main ---
int main(const int argc, const char *argv[]) {
    ProgramArgs args;

    // 1. Parsing de argumentos usando tu librería
    if (parse_arguments_ex(argc, argv, &args, &STRESS_TP_CFG) < 0) return EXIT_FAILURE;

    // 2. Validación de argumentos posicionales (tu snippet)
    if (optind + 1 >= argc) {
        fprintf(stderr, "Uso: %s [opciones] <concurrency> <duration_sec> [payload_bytes]\n", argv[0]);
        args_destroy(&args, &STRESS_TP_CFG);
        return EXIT_FAILURE;
    }

    int concurrency = atoi(argv[optind++]);
    int duration_sec = atoi(argv[optind++]);
    size_t payload_bytes = 16 * 1024; // default 16KB

    if (optind < argc) {
        long v = atol(argv[optind++]);
        if (v > 0) payload_bytes = (size_t)v * 1024;
    }
    if (optind < argc) {
        fprintf(stderr, "Argumentos extra no reconocidos.\n");
        args_destroy(&args, &STRESS_TP_CFG);
        return EXIT_FAILURE;
    }

    if (concurrency <= 0 || duration_sec <= 0) {
        fprintf(stderr, "Concurrency y duration_sec deben ser > 0.\n");
        args_destroy(&args, &STRESS_TP_CFG);
        return EXIT_FAILURE;
    }

    if (validate_arguments_ex(&args, &STRESS_TP_CFG) < 0) {
        args_destroy(&args, &STRESS_TP_CFG);
        return EXIT_FAILURE;
    }

    // 3. Transferir configuración a estructura global para los hilos
    // Nota: Asumo que ProgramArgs tiene estos campos. Si se llaman diferente en tu args.h, cámbialos aquí.
    strncpy(global_conf.socks_addr, args.socks_addr, sizeof(global_conf.socks_addr)-1);
    global_conf.socks_port = args.socks_port;
    
    // Si tu args.h tiene campos especificos para destino (-L, -P) úsalos.
    // Si args reutiliza dst_addr para esto:
    strncpy(global_conf.target_host, args.aux_addr, sizeof(global_conf.target_host)-1);
    global_conf.target_port = args.aux_port;
    
    global_conf.payload_size = payload_bytes;

    printf("Iniciando Stress Test de Throughput:\n");
    printf("  SOCKS5:       %s:%d\n", global_conf.socks_addr, global_conf.socks_port);
    printf("  Target:       %s:%d\n", global_conf.target_host, global_conf.target_port);
    printf("  Hilos:        %d\n", concurrency);
    printf("  Duración:     %d s\n", duration_sec);
    printf("  Payload:      %zu bytes\n\n", payload_bytes);

    // 4. Ejecución de Threads
    pthread_t *threads = malloc(sizeof(pthread_t) * concurrency);
    if (!threads) {
        perror("malloc");
        args_destroy(&args, &STRESS_TP_CFG);
        return 1;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < concurrency; i++) {
        if (pthread_create(&threads[i], NULL, worker_thread, NULL) != 0) {
            perror("pthread_create");
            atomic_fetch_add(&tunnels_fail, 1);
        }
    }

    sleep(duration_sec);
    clock_gettime(CLOCK_MONOTONIC, &end);

    // --- CÁLCULO DE ESTADÍSTICAS ---

    // 1. Tiempo transcurrido
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    
    // Evitar división por cero si el test dura 0s (improbable pero posible)
    if (elapsed <= 0.0) elapsed = 0.001;

    // 2. Mapeo de variables atómicas a locales
    int ok = atomic_load(&tunnels_ok);
    int fail = atomic_load(&tunnels_fail);
    long total_sent = atomic_load(&bytes_sent);
    long total_recv = atomic_load(&bytes_recv);

    // 3. Conversión a MiB
    double mib_sent = (double)total_sent / (1024.0 * 1024.0);
    double mib_recv = (double)total_recv / (1024.0 * 1024.0);

    // 4. Cálculo de Throughput (Velocidad)
    double thr_sent = mib_sent / elapsed;
    double thr_recv = mib_recv / elapsed;
    double thr_total = thr_sent + thr_recv;

    // --- IMPRESIÓN SOLICITADA ---

    printf("\n------------------------------------\n");
    printf("RESULTADOS:\n");
    printf("Tunnels OK: %d\n", ok);
    printf("Fails:      %d\n", fail);
    printf("Elapsed:    %.3f s\n", elapsed);
    printf("Sent:       %.2f MiB\n", mib_sent);
    printf("Recv:       %.2f MiB\n", mib_recv);
    printf("Throughput: sent=%.2f MiB/s  recv=%.2f MiB/s  total=%.2f MiB/s\n",
           thr_sent, thr_recv, thr_total);

    // --- LIMPIEZA ---
    free(threads);
    args_destroy(&args, &STRESS_TP_CFG); // Asegúrate de que STRESS_TP_CFG sea la correcta
    return EXIT_SUCCESS;
}
