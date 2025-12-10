#include "../../include/metrics.h"
#include <stdio.h>
#include <stdatomic.h>
#include <inttypes.h>

static atomic_uint_least64_t total_connections;
static atomic_uint_least64_t concurrent_connections;
static atomic_uint_least64_t total_bytes_received;
static atomic_uint_least64_t total_bytes_sent;

void metrics_init(void) {
    atomic_store_explicit(&total_connections, 0, memory_order_relaxed);
    atomic_store_explicit(&concurrent_connections, 0, memory_order_relaxed);
    atomic_store_explicit(&total_bytes_received, 0, memory_order_relaxed);
    atomic_store_explicit(&total_bytes_sent, 0, memory_order_relaxed);
}

void metrics_inc_total_connections(void) {
    atomic_fetch_add_explicit(&total_connections, 1, memory_order_relaxed);
}

void metrics_inc_concurrent_connections(void) {
    atomic_fetch_add_explicit(&concurrent_connections, 1, memory_order_relaxed);
}

void metrics_dec_concurrent_connections(void) {
    atomic_fetch_sub_explicit(&concurrent_connections, 1, memory_order_relaxed);
}

void metrics_add_bytes_received(uint64_t n) {
    atomic_fetch_add_explicit(&total_bytes_received, n, memory_order_relaxed);
}

void metrics_add_bytes_sent(uint64_t n) {
    atomic_fetch_add_explicit(&total_bytes_sent, n, memory_order_relaxed);
}

void metrics_print(void) {
    printf("=== Server metrics ===\n");
    printf("Total connections: %" PRIu64 "\n", (uint64_t)atomic_load_explicit(&total_connections, memory_order_relaxed));
    printf("Concurrent connections: %" PRIu64 "\n", (uint64_t)atomic_load_explicit(&concurrent_connections, memory_order_relaxed));
    printf("Total bytes received: %" PRIu64 "\n", (uint64_t)atomic_load_explicit(&total_bytes_received, memory_order_relaxed));
    printf("Total bytes sent: %" PRIu64 "\n", (uint64_t)atomic_load_explicit(&total_bytes_sent, memory_order_relaxed));
}
