#ifndef __metrics_h_
#define __metrics_h_

void metrics_init(void);

void metrics_inc_connections(void);

void metrics_inc_concurrent_connections(void);

void metrics_dec_concurrent_connections(void);

void metrics_add_bytes_received(uint64_t n);

void metrics_add_bytes_sent(uint64_t n);

void metrics_print(void);

#endif // __metrics_h_