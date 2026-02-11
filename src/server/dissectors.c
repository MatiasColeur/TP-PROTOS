#include "../../include/dissectors.h"
#include "../../include/logger.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define POP3_PORT     110
#define HTTP_PORT     80
#define HTTP_PORT_ALT 8080

#define HTTP_BODY_SCAN_LIMIT 8192

static inline int ascii_tolower_int(int c) {
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

static bool starts_with_ci(const char *line, size_t len, const char *kw) {
    size_t klen = strlen(kw);
    if (len < klen) return false;
    for (size_t i = 0; i < klen; i++) {
        if (ascii_tolower_int(line[i]) != ascii_tolower_int(kw[i])) return false;
    }
    return true;
}

static void line_reset(dissector_state *st) {
    st->line_len = 0;
    st->line_drop = false;
}

static bool line_push(dissector_state *st, char c, char **out_line, size_t *out_len) {
    if (st->line_drop) {
        if (c == '\n') {
            st->line_drop = false;
            st->line_len = 0;
        }
        return false;
    }

    if (c == '\r') return false;
    if (c == '\n') {
        st->line_buf[st->line_len] = '\0';
        *out_line = st->line_buf;
        *out_len = st->line_len;
        st->line_len = 0;
        return true;
    }

    if (st->line_len + 1 >= DISSECTOR_LINE_MAX) {
        st->line_drop = true;
        st->line_len = 0;
        return false;
    }

    st->line_buf[st->line_len++] = c;
    return false;
}

static void pop3_reset(dissector_state *st) {
    st->pop3_logged = false;
    st->pop3_user_set = false;
    st->pop3_user[0] = '\0';
    line_reset(st);
}

static void url_reset(dissector_state *st) {
    st->url_in_value = false;
    st->url_key_len = 0;
    st->url_val_len = 0;
    st->pct_state = 0;
    st->pct_hi = 0;
}

static void http_reset(dissector_state *st) {
    st->http_logged = false;
    st->http_header_done = false;
    st->http_first_line = true;
    st->http_is_post = false;
    st->http_is_urlencoded = false;
    st->http_content_length = 0;
    st->http_body_read = 0;
    st->http_body_parse_limit = 0;
    st->http_user_set = false;
    st->http_pass_set = false;
    st->http_user[0] = '\0';
    st->http_pass[0] = '\0';
    url_reset(st);
    line_reset(st);
}

void dissectors_init(dissector_state *st, bool enabled) {
    if (st == NULL) return;
    memset(st, 0, sizeof(*st));
    st->enabled = enabled;
    pop3_reset(st);
    http_reset(st);
}

void dissectors_on_request(dissector_state *st, uint16_t port) {
    if (st == NULL) return;
    st->pop3_candidate = st->enabled && (port == POP3_PORT);
    st->http_candidate = st->enabled && (port == HTTP_PORT || port == HTTP_PORT_ALT);
    pop3_reset(st);
    http_reset(st);
}

static void pop3_handle_line(dissector_state *st,
                             const char *line, size_t len,
                             const char *requester_user,
                             const char *dst_host,
                             uint16_t dst_port) {
    if (!st->pop3_candidate || st->pop3_logged || len == 0) return;

    if (len == 0) return;

    if (starts_with_ci(line, len, "USER")) {
        size_t idx = 4;
        while (idx < len && line[idx] == ' ') idx++;
        size_t ulen = (len > idx) ? (len - idx) : 0;
        if (ulen >= sizeof(st->pop3_user)) ulen = sizeof(st->pop3_user) - 1;
        memcpy(st->pop3_user, line + idx, ulen);
        st->pop3_user[ulen] = '\0';
        st->pop3_user_set = (ulen > 0);
    } else if (starts_with_ci(line, len, "PASS")) {
        if (!st->pop3_user_set || st->pop3_logged) return;
        size_t idx = 4;
        while (idx < len && line[idx] == ' ') idx++;
        size_t plen = (len > idx) ? (len - idx) : 0;
        if (plen == 0) return;

        char password[DISSECTOR_PASS_MAX + 1];
        if (plen >= sizeof(password)) plen = sizeof(password) - 1;
        memcpy(password, line + idx, plen);
        password[plen] = '\0';

        log_credentials(requester_user,
                        "POP3",
                        dst_host,
                        dst_port,
                        st->pop3_user_set ? st->pop3_user : "",
                        password);
        st->pop3_logged = true;
    }
}

static void pop3_feed(dissector_state *st,
                      const uint8_t *data, size_t len,
                      const char *requester_user,
                      const char *dst_host,
                      uint16_t dst_port) {
    if (!st->enabled || !st->pop3_candidate || data == NULL) return;
    if (st->pop3_logged) return;

    for (size_t i = 0; i < len; i++) {
        char c = (char)data[i];
        char *line = NULL;
        size_t line_len = 0;
        if (line_push(st, c, &line, &line_len)) {
            pop3_handle_line(st, line, line_len, requester_user, dst_host, dst_port);
            if (st->pop3_logged) return;
        }
    }
}

static int hex_value(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int b64_index(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static bool base64_decode(const char *in, size_t in_len,
                          unsigned char *out, size_t out_cap, size_t *out_len) {
    size_t i = 0, o = 0;
    int val = 0, valb = -8;
    while (i < in_len) {
        int c = (unsigned char)in[i++];
        if (c == '=') break;
        int d = b64_index(c);
        if (d < 0) continue;
        val = (val << 6) | d;
        valb += 6;
        if (valb >= 0) {
            if (o >= out_cap) return false;
            out[o++] = (unsigned char)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    if (out_len) *out_len = o;
    return true;
}

static bool header_line_ci(const char *line, size_t len, const char *name) {
    size_t nlen = strlen(name);
    if (len < nlen + 1) return false;
    if (!starts_with_ci(line, len, name)) return false;
    return line[nlen] == ':';
}

static void http_parse_header_line(dissector_state *st,
                                   const char *line, size_t len,
                                   const char *requester_user,
                                   const char *dst_host,
                                   uint16_t dst_port) {
    if (st->http_first_line) {
        st->http_first_line = false;
        if (len >= 4 && starts_with_ci(line, len, "POST") &&
            (line[4] == ' ' || line[4] == '\t')) {
            st->http_is_post = true;
        }
        return;
    }

    if (header_line_ci(line, len, "Content-Length")) {
        const char *v = line + strlen("Content-Length") + 1;
        while (v < line + len && (*v == ' ' || *v == '\t')) v++;
        st->http_content_length = (size_t)strtoul(v, NULL, 10);
        if (st->http_content_length > HTTP_BODY_SCAN_LIMIT) {
            st->http_body_parse_limit = HTTP_BODY_SCAN_LIMIT;
        } else {
            st->http_body_parse_limit = st->http_content_length;
        }
        return;
    }

    if (header_line_ci(line, len, "Content-Type")) {
        const char *v = line + strlen("Content-Type") + 1;
        while (v < line + len && (*v == ' ' || *v == '\t')) v++;
        if ((size_t)(line + len - v) >= 33 &&
            strncasecmp(v, "application/x-www-form-urlencoded", 33) == 0) {
            st->http_is_urlencoded = true;
        }
        return;
    }

    if (!st->http_logged && header_line_ci(line, len, "Authorization")) {
        const char *v = line + strlen("Authorization") + 1;
        while (v < line + len && (*v == ' ' || *v == '\t')) v++;
        if ((size_t)(line + len - v) >= 6 && strncasecmp(v, "Basic ", 6) == 0) {
            const char *b64 = v + 6;
            size_t b64_len = (size_t)(line + len - b64);
            unsigned char decoded[512];
            size_t decoded_len = 0;
            if (base64_decode(b64, b64_len, decoded, sizeof(decoded) - 1, &decoded_len)) {
                decoded[decoded_len] = '\0';
                char *sep = strchr((char *)decoded, ':');
                if (sep != NULL) {
                    *sep = '\0';
                    const char *u = (const char *)decoded;
                    const char *pw = sep + 1;
                    if (*u != '\0' && *pw != '\0') {
                        log_credentials(requester_user, "HTTP", dst_host, dst_port, u, pw);
                        st->http_logged = true;
                    }
                }
            }
        }
    }
}

static void url_append(dissector_state *st, char c) {
    if (!st->url_in_value) {
        if (st->url_key_len < DISSECTOR_TOKEN_MAX) {
            st->url_key[st->url_key_len++] = c;
        }
    } else {
        if (st->url_val_len < DISSECTOR_TOKEN_MAX) {
            st->url_val[st->url_val_len++] = c;
        }
    }
}

static bool key_is_user(const char *k) {
    static const char *user_keys[] = {"user", "username", "email", "login", "uid"};
    for (size_t i = 0; i < sizeof(user_keys) / sizeof(user_keys[0]); i++) {
        if (strcasecmp(k, user_keys[i]) == 0) return true;
    }
    return false;
}

static bool key_is_pass(const char *k) {
    static const char *pass_keys[] = {"pass", "password", "pwd", "passwd"};
    for (size_t i = 0; i < sizeof(pass_keys) / sizeof(pass_keys[0]); i++) {
        if (strcasecmp(k, pass_keys[i]) == 0) return true;
    }
    return false;
}

static void url_emit_pair(dissector_state *st,
                          const char *requester_user,
                          const char *dst_host,
                          uint16_t dst_port) {
    if (st->url_key_len == 0 && st->url_val_len == 0) {
        st->url_in_value = false;
        return;
    }

    st->url_key[st->url_key_len] = '\0';
    st->url_val[st->url_val_len] = '\0';

    if (!st->http_user_set && key_is_user(st->url_key)) {
        strncpy(st->http_user, st->url_val, sizeof(st->http_user) - 1);
        st->http_user[sizeof(st->http_user) - 1] = '\0';
        st->http_user_set = true;
    } else if (!st->http_pass_set && key_is_pass(st->url_key)) {
        strncpy(st->http_pass, st->url_val, sizeof(st->http_pass) - 1);
        st->http_pass[sizeof(st->http_pass) - 1] = '\0';
        st->http_pass_set = true;
    }

    if (st->http_user_set && st->http_pass_set && !st->http_logged) {
        log_credentials(requester_user,
                        "HTTP",
                        dst_host,
                        dst_port,
                        st->http_user,
                        st->http_pass);
        st->http_logged = true;
    }

    st->url_key_len = 0;
    st->url_val_len = 0;
    st->url_in_value = false;
}

static void url_finish(dissector_state *st,
                       const char *requester_user,
                       const char *dst_host,
                       uint16_t dst_port) {
    if (st->pct_state == 1) {
        url_append(st, '%');
    } else if (st->pct_state == 2) {
        url_append(st, '%');
        url_append(st, st->pct_hi);
    }
    st->pct_state = 0;
    url_emit_pair(st, requester_user, dst_host, dst_port);
}

static void url_feed_char(dissector_state *st, char c,
                          const char *requester_user,
                          const char *dst_host,
                          uint16_t dst_port) {
    if (st->pct_state == 0) {
        if (c == '&') {
            url_emit_pair(st, requester_user, dst_host, dst_port);
            return;
        }
        if (c == '=' && !st->url_in_value) {
            st->url_in_value = true;
            return;
        }
        if (c == '+') {
            url_append(st, ' ');
            return;
        }
        if (c == '%') {
            st->pct_state = 1;
            st->pct_hi = 0;
            return;
        }
        url_append(st, c);
        return;
    }

    if (st->pct_state == 1) {
        if (hex_value(c) < 0) {
            url_append(st, '%');
            url_append(st, c);
            st->pct_state = 0;
            return;
        }
        st->pct_hi = c;
        st->pct_state = 2;
        return;
    }

    if (hex_value(c) < 0) {
        url_append(st, '%');
        url_append(st, st->pct_hi);
        url_append(st, c);
        st->pct_state = 0;
        return;
    }

    int hi = hex_value(st->pct_hi);
    int lo = hex_value(c);
    char decoded = (char)((hi << 4) | lo);
    url_append(st, decoded);
    st->pct_state = 0;
}

static void http_body_feed(dissector_state *st,
                           const uint8_t *data, size_t len,
                           const char *requester_user,
                           const char *dst_host,
                           uint16_t dst_port) {
    if (st->http_logged || !st->http_is_post || !st->http_is_urlencoded) {
        st->http_body_read += len;
        return;
    }

    size_t parse_limit = st->http_body_parse_limit;
    size_t parsed_so_far = st->http_body_read;

    for (size_t i = 0; i < len; i++) {
        if (parsed_so_far >= parse_limit) break;
        url_feed_char(st, (char)data[i], requester_user, dst_host, dst_port);
        parsed_so_far++;
    }

    st->http_body_read += len;
}

static void http_feed(dissector_state *st,
                      const uint8_t *data, size_t len,
                      const char *requester_user,
                      const char *dst_host,
                      uint16_t dst_port) {
    if (!st->enabled || !st->http_candidate || data == NULL) return;

    size_t i = 0;
    while (i < len) {
        if (!st->http_header_done) {
            char c = (char)data[i++];
            char *line = NULL;
            size_t line_len = 0;
            if (line_push(st, c, &line, &line_len)) {
                if (line_len == 0) {
                    st->http_header_done = true;
                    st->http_body_read = 0;
                    if (!st->http_is_post || !st->http_is_urlencoded ||
                        st->http_content_length == 0) {
                        http_reset(st);
                        return;
                    }
                    if (st->http_body_parse_limit == 0) {
                        if (st->http_content_length > HTTP_BODY_SCAN_LIMIT) {
                            st->http_body_parse_limit = HTTP_BODY_SCAN_LIMIT;
                        } else {
                            st->http_body_parse_limit = st->http_content_length;
                        }
                    }
                    url_reset(st);
                } else {
                    http_parse_header_line(st, line, line_len,
                                           requester_user, dst_host, dst_port);
                }
            }
            continue;
        }

        if (st->http_content_length == 0) {
            http_reset(st);
            return;
        }

        size_t remaining = st->http_content_length - st->http_body_read;
        if (remaining == 0) {
            url_finish(st, requester_user, dst_host, dst_port);
            http_reset(st);
            return;
        }

        size_t take = len - i;
        if (take > remaining) take = remaining;
        http_body_feed(st, data + i, take, requester_user, dst_host, dst_port);
        i += take;

        if (st->http_body_read >= st->http_content_length) {
            url_finish(st, requester_user, dst_host, dst_port);
            http_reset(st);
            return;
        }
    }
}

void dissectors_feed(dissector_state *st,
                     const uint8_t *data, size_t len,
                     const char *requester_user,
                     const char *dst_host,
                     uint16_t dst_port) {
    if (st == NULL || data == NULL || len == 0) return;
    if (!st->enabled) return;

    if (st->pop3_candidate) {
        pop3_feed(st, data, len, requester_user, dst_host, dst_port);
    } else if (st->http_candidate) {
        http_feed(st, data, len, requester_user, dst_host, dst_port);
    }
}
