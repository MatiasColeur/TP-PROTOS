#ifndef __metrics_h_
#define __metrics_h_

#include <stdint.h>
#include "errors.h"

#define ACCESS_FILE "log/access.txt"
#define CONCURRENCIES_FILE "log/concurrencies.txt"
#define BYTES_FILE "log/concurrencies.txt"

#define MAX_LINE 512

uint64_t metrics_get_total_connections(void);

uint64_t metrics_get_concurrent_connections(void);

uint64_t metrics_get_bytes(void);

void metrics_find_user(const char *filename, const char *username);


#endif
