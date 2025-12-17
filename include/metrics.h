#ifndef __metrics_h_
#define __metrics_h_

#include <stdint.h>
#include <string.h>
#include "errors.h"

#define ACCESS_FILE "log/access.txt"
#define CONCURRENCIES_FILE "log/concurrencies.txt"
#define BYTES_FILE "log/bytes.txt"

#define MAX_LINE 256

uint64_t metrics_get_total_connections(void);

uint64_t metrics_get_concurrent_connections(void);

uint64_t metrics_get_bytes(void);

int metrics_find_user(const char *username, uint8_t **out_buf, size_t *out_len, uint64_t *out_matches);


#endif
