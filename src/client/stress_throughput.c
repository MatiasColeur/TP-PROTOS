// SOCKS5 Throughput Stress Test (echo target)
// Usage:
//   ./bin/stress_tp [OPTIONS] <concurrency> <duration_sec> [payload_bytes]
//
// OPTIONS (reusa tu parser):
//   -l <SOCKS addr>  (default: 127.0.0.1)
//   -p <SOCKS port>  (default: 1080)
//   -L <dst host>    (default: 127.0.0.1)
//   -P <dst port>    (default: 9090)
//
// Example:
//   socat TCP-LISTEN:9090,reuseaddr,fork SYSTEM:'cat'
//   ./bin/stress_throughput -l 127.0.0.1 -p 1080 -L 127.0.0.1 -P 9090 200 10 16384

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/time.h>
#include <time.h>
#include <netdb.h>
#include <sys/socket.h>

#include "../../include/parser_arguments.h"

#define TIMEOUT_SEC 5

static const ArgParserConfig STRESS_TP_CFG = {
    .version_str = "SOCKS5 Throughput Stress Client v1.0",
    .help_str =
        "Usage: %s [OPTIONS] <concurrency> <duration_sec> [payload_bytes]\n"
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

typedef struct {
    int id;
    const char *socks_addr;
    uint16_t socks_port;
    const char *target_host;
    uint16_t target_port;
    int duration_sec;
    size_t payload_bytes;
} thread_arg_t;

static atomic_int ok_tunnels = 0;
static atomic_int fail_tunnels = 0;

static atomic_ullong total_sent = 0;
static atomic_ullong total_recv = 0;

// barrier simple
static atomic_int ready_cnt = 0;
static atomic_int start_flag = 0;

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static int set_timeouts(int fd) {
    struct timeval tv;
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) < 0) return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv) < 0) return -1;
    return 0;
}

static int connect_tcp_any(const char *host, uint16_t port) {
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, portstr, &hints, &res);
    if (rc != 0 || res == NULL) return -1;

    int fd = -1;
    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        if (set_timeouts(fd) < 0) {
            close(fd);
            fd = -1;
            continue;
        }

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break; // ok
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

static int socks5_handshake_auth(int fd, const char *user, const char *pass) {
    uint8_t buf[512];
    ssize_t n;

    // HELLO: VER=5, NMETHODS=1, METHOD=0x02
    uint8_t hello[] = { 0x05, 0x01, 0x02 };
    if (send(fd, hello, sizeof(hello), MSG_NOSIGNAL) < 0) return -1;

    n = recv(fd, buf, sizeof(buf), 0);
    if (n < 2 || buf[0] != 0x05 || buf[1] != 0x02) return -1;

    // RFC1929 auth
    size_t ulen = strlen(user);
    size_t plen = strlen(pass);
    if (ulen > 255 || plen > 255) return -1;

    size_t idx = 0;
    buf[idx++] = 0x01;
    buf[idx++] = (uint8_t)ulen;
    memcpy(buf + idx, user, ulen); idx += ulen;
    buf[idx++] = (uint8_t)plen;
    memcpy(buf + idx, pass, plen); idx += plen;

    if (send(fd, buf, idx, MSG_NOSIGNAL) < 0) return -1;

    n = recv(fd, buf, sizeof(buf), 0);
    if (n < 2 || buf[0] != 0x01 || buf[1] != 0x00) return -1;

    return 0;
}

static int socks5_connect_domain(int fd, const char *host, uint16_t port) {
    uint8_t buf[512];
    ssize_t n;

    size_t hlen = strlen(host);
    if (hlen == 0 || hlen > 255) return -1;

    size_t idx = 0;
    buf[idx++] = 0x05; // VER
    buf[idx++] = 0x01; // CONNECT
    buf[idx++] = 0x00; // RSV
    buf[idx++] = 0x03; // ATYP DOMAIN
    buf[idx++] = (uint8_t)hlen;
    memcpy(buf + idx, host, hlen); idx += hlen;
    uint16_t pn = htons(port);
    memcpy(buf + idx, &pn, 2); idx += 2;

    if (send(fd, buf, idx, MSG_NOSIGNAL) < 0) return -1;

    n = recv(fd, buf, sizeof(buf), 0);
    if (n < 4) return -1;
    if (buf[0] != 0x05) return -1;
    if (buf[1] != 0x00) return -1; // REP != success

    // No hace falta parsear el resto para el test.
    return 0;
}

// Echo throughput loop: send payload, recv same bytes back
static int run_echo_loop(int fd, int duration_sec, size_t payload_bytes,
                         uint64_t *sent_out, uint64_t *recv_out) {
    uint8_t *payload = malloc(payload_bytes);
    uint8_t *rxbuf   = malloc(payload_bytes);
    if (!payload || !rxbuf) {
        free(payload);
        free(rxbuf);
        return -1;
    }

    // payload determinístico
    for (size_t i = 0; i < payload_bytes; i++) payload[i] = (uint8_t)(i & 0xFF);

    uint64_t deadline = now_ms() + (uint64_t)duration_sec * 1000ULL;
    uint64_t sent = 0, recvd = 0;

    while (now_ms() < deadline) {
        // send full payload (best effort)
        size_t off = 0;
        while (off < payload_bytes) {
            ssize_t w = send(fd, payload + off, payload_bytes - off, MSG_NOSIGNAL);
            if (w <= 0) goto done; // timeout / closed / error
            off += (size_t)w;
            sent += (uint64_t)w;
        }

        // recv same amount
        size_t need = payload_bytes;
        while (need > 0) {
            ssize_t r = recv(fd, rxbuf, need, 0);
            if (r <= 0) goto done;
            need -= (size_t)r;
            recvd += (uint64_t)r;
        }
    }

done:
    free(payload);
    free(rxbuf);
    *sent_out = sent;
    *recv_out = recvd;
    // consider "ok" si al menos movió algo
    return (sent > 0 && recvd > 0) ? 0 : -1;
}

static void *worker(void *p) {
    thread_arg_t *a = (thread_arg_t*)p;

    int fd = connect_tcp_any(a->socks_addr, a->socks_port);
    if (fd < 0) goto fail;

    if (socks5_handshake_auth(fd, "admin", "admin") < 0) {
        close(fd);
        goto fail;
    }

    if (socks5_connect_domain(fd, a->target_host, a->target_port) < 0) {
        close(fd);
        goto fail;
    }

    atomic_fetch_add(&ok_tunnels, 1);

    // barrier: esperar start_flag
    atomic_fetch_add(&ready_cnt, 1);
    while (atomic_load(&start_flag) == 0) {
        // busy wait corto
        sched_yield();
    }

    uint64_t s = 0, r = 0;
    int rc = run_echo_loop(fd, a->duration_sec, a->payload_bytes, &s, &r);
    close(fd);

    if (rc == 0) {
        atomic_fetch_add(&total_sent, s);
        atomic_fetch_add(&total_recv, r);
    } else {
        atomic_fetch_add(&fail_tunnels, 1);
    }

    free(a);
    return NULL;

fail:
    atomic_fetch_add(&fail_tunnels, 1);
    atomic_fetch_add(&ready_cnt, 1); // para no colgar el barrier
    free(a);
    return NULL;
}

int main(int argc, const char *argv[]) {
    ProgramArgs args;

    if (parse_arguments_ex(argc, argv, &args, &STRESS_TP_CFG) < 0) return EXIT_FAILURE;

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
        if (v > 0) payload_bytes = (size_t)v;
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

    printf("=== SOCKS5 Throughput Test ===\n");
    printf("SOCKS:  %s:%u\n", args.socks_addr, (unsigned)args.socks_port);
    printf("Target: %s:%u (ECHO esperado)\n", args.aux_addr, (unsigned)args.aux_port);
    printf("Concurrency: %d\n", concurrency);
    printf("Duration:    %d sec\n", duration_sec);
    printf("Payload:     %zu bytes\n", payload_bytes);
    printf("------------------------------------\n");

    pthread_t *ths = calloc((size_t)concurrency, sizeof(pthread_t));
    if (!ths) {
        perror("calloc");
        args_destroy(&args, &STRESS_TP_CFG);
        return EXIT_FAILURE;
    }

    uint64_t t0 = now_ms();

    for (int i = 0; i < concurrency; i++) {
        thread_arg_t *a = malloc(sizeof(*a));
        if (!a) {
            perror("malloc");
            atomic_fetch_add(&fail_tunnels, 1);
            atomic_fetch_add(&ready_cnt, 1);
            continue;
        }
        a->id = i;
        a->socks_addr = args.socks_addr;
        a->socks_port = args.socks_port;
        a->target_host = args.aux_addr;
        a->target_port = args.aux_port;
        a->duration_sec = duration_sec;
        a->payload_bytes = payload_bytes;

        if (pthread_create(&ths[i], NULL, worker, a) != 0) {
            perror("pthread_create");
            free(a);
            atomic_fetch_add(&fail_tunnels, 1);
            atomic_fetch_add(&ready_cnt, 1);
        }
    }

    // esperar que "todos" pasen por ready (aunque fallen)
    while (atomic_load(&ready_cnt) < concurrency) {
        usleep(1000);
        // opcional: timeout
        if (now_ms() - t0 > 30000) break;
    }

    uint64_t start = now_ms();
    atomic_store(&start_flag, 1);

    for (int i = 0; i < concurrency; i++) {
        if (ths[i]) pthread_join(ths[i], NULL);
    }
    uint64_t end = now_ms();

    free(ths);

    uint64_t sent = atomic_load(&total_sent);
    uint64_t recvd = atomic_load(&total_recv);
    int ok = atomic_load(&ok_tunnels);
    int fail = atomic_load(&fail_tunnels);

    double elapsed = (double)(end - start) / 1000.0;
    if (elapsed <= 0.0) elapsed = (double)duration_sec;

    double mib_sent = (double)sent / (1024.0 * 1024.0);
    double mib_recv = (double)recvd / (1024.0 * 1024.0);

    double thr_sent = mib_sent / elapsed;
    double thr_recv = mib_recv / elapsed;
    double thr_total = (mib_sent + mib_recv) / elapsed;

    printf("\n------------------------------------\n");
    printf("RESULTADOS:\n");
    printf("Tunnels OK: %d\n", ok);
    printf("Fails:      %d\n", fail);
    printf("Elapsed:    %.3f s\n", elapsed);
    printf("Sent:       %.2f MiB\n", mib_sent);
    printf("Recv:       %.2f MiB\n", mib_recv);
    printf("Throughput: sent=%.2f MiB/s  recv=%.2f MiB/s  total=%.2f MiB/s\n",
           thr_sent, thr_recv, thr_total);

    args_destroy(&args, &STRESS_TP_CFG);

    // si hubo 0 túneles ok, fallo duro
    return (ok > 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
