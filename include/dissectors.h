#ifndef DISSECTORS_H
#define DISSECTORS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DISSECTOR_LINE_MAX 2048
#define DISSECTOR_USER_MAX 255
#define DISSECTOR_PASS_MAX 255
#define DISSECTOR_TOKEN_MAX 255

typedef struct dissector_state {
    bool enabled;
    bool pop3_candidate;
    bool http_candidate;

    /* Line accumulator (used for POP3 and HTTP headers) */
    char line_buf[DISSECTOR_LINE_MAX];
    size_t line_len;
    bool line_drop;

    /* POP3 state */
    bool pop3_logged;
    bool pop3_user_set;
    char pop3_user[DISSECTOR_USER_MAX + 1];

    /* HTTP header/body state */
    bool http_logged;
    bool http_header_done;
    bool http_first_line;
    bool http_is_post;
    bool http_is_urlencoded;
    size_t http_content_length;
    size_t http_body_read;
    size_t http_body_parse_limit;

    /* Captured HTTP form credentials */
    bool http_user_set;
    bool http_pass_set;
    char http_user[DISSECTOR_USER_MAX + 1];
    char http_pass[DISSECTOR_PASS_MAX + 1];

    /* URL-encoded body parser state */
    bool url_in_value;
    char url_key[DISSECTOR_TOKEN_MAX + 1];
    size_t url_key_len;
    char url_val[DISSECTOR_TOKEN_MAX + 1];
    size_t url_val_len;
    int pct_state;
    char pct_hi;
} dissector_state;

void dissectors_init(dissector_state *st, bool enabled);
void dissectors_on_request(dissector_state *st, uint16_t port);
void dissectors_feed(dissector_state *st,
                     const uint8_t *data, size_t len,
                     const char *requester_user,
                     const char *dst_host,
                     uint16_t dst_port);

#endif
