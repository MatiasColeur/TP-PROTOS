#ifndef __metrics_h_
#define __metrics_h_

#include <stdint.h>
#include "errors.h"

#define ACCESS_FILE "log/access.txt"
#define CONCURRENCIES_FILE "log/concurrencies.txt"

void metrics_init(const char *access_log_path);

uint64_t metrics_get_total_connections(void);

void metrics_inc_concurrent_connections(void);
void metrics_dec_concurrent_connections(void);

void metrics_add_bytes_received(uint64_t n);
void metrics_add_bytes_sent(uint64_t n);

uint64_t metrics_get_concurrent_connections(void);
uint64_t metrics_get_total_bytes_received(void);
uint64_t metrics_get_total_bytes_sent(void);

void metrics_print(void);

#endif
