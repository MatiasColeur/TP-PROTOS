#include "../../include/api.h"
#include "../../include/errors.h"
#include "../../include/shared.h"

void admin_send_request(int sockfd,
                               uint32_t id,
                               uint8_t cmd,
                               const char *payload) {
    struct admin_req_header req;
    struct admin_resp_header resp;

    size_t payload_len = payload ? strlen(payload) : 0;
    if (payload_len > UINT16_MAX) {
        fprintf(stderr, "[ERR] Payload too large\n");
        return;
    }

    req.id  = htonl(id);
    req.cmd = cmd;
    req.len = htons((uint16_t)payload_len);

    // Enviar header
    if (!write_exact(sockfd, &req, sizeof(req))) {
        print_error("Error escribiendo header admin");
        exit(1);
    }

    // Enviar payload, si hay
    if (payload_len > 0) {
        if (!write_exact(sockfd, payload, payload_len)) {
            print_error("Error escribiendo payload admin");
            exit(1);
        }
    }

    // Leer header de respuesta
    if (!read_exact(sockfd, &resp, sizeof(resp))) {
        print_error("Error leyendo header de respuesta admin");
        exit(1);
    }

    uint32_t resp_id  = ntohl(resp.id);
    uint16_t resp_len = ntohs(resp.len);

    printf("[ADMIN] Resp id=%u status=%u len=%u\n",
           resp_id, resp.status, resp_len);

    // Leer payload de respuesta si lo hay
    if (resp_len > 0) {
        char buf[512];
        if (resp_len >= sizeof(buf)) {
            resp_len = sizeof(buf) - 1;
        }

        if (!read_exact(sockfd, buf, resp_len)) {
            print_error("Error leyendo payload de respuesta");
            exit(1);
        }
        buf[resp_len] = '\0';
        printf("[ADMIN] Payload: %s", buf);
        if (buf[resp_len-1] != '\n') {
            printf("\n");
        }
    }
}

/**
 * Convierte un Request Header + Body a un stream de bytes para enviar por socket.
 */
int admin_serialize_req(const struct admin_req_header *h, const uint8_t *body, uint8_t *buf, size_t size) {
    if (size < ADMIN_HEADER_SIZE + h->len) return -1;

    uint8_t *p = buf;

    // 1. ID (32 bit)
    uint32_t net_id = htonl(h->id);
    memcpy(p, &net_id, 4);
    p += 4;

    // 2. CMD (8 bit)
    *p++ = h->cmd;

    // 3. LEN (16 bit)
    uint16_t net_len = htons(h->len);
    memcpy(p, &net_len, 2);
    p += 2;

    // 4. Body
    if (h->len > 0 && body != NULL) {
        memcpy(p, body, h->len);
    }

    return ADMIN_HEADER_SIZE + h->len;
}

/**
 * Lee bytes del socket y llena la estructura del Header.
 * NOTA: Solo lee el header. El body se lee aparte según el campo 'len'.
 */
int admin_deserialize_req(const uint8_t *buf, size_t size, struct admin_req_header *h) {
    if (size < ADMIN_HEADER_SIZE) return -1;

    const uint8_t *p = buf;

    // 1. ID
    uint32_t net_id;
    memcpy(&net_id, p, 4);
    h->id = ntohl(net_id); 
    p += 4;

    // 2. CMD
    h->cmd = *p++;

    // 3. LEN
    uint16_t net_len;
    memcpy(&net_len, p, 2);
    h->len = ntohs(net_len);

    return ADMIN_HEADER_SIZE;
}

/**
 * Serializa la Respuesta del servidor hacia el cliente
 */
int admin_serialize_resp(const struct admin_resp_header *h, const uint8_t *body, uint8_t *buf, size_t size) {
    if (size < ADMIN_HEADER_SIZE + h->len) return -1;

    uint8_t *p = buf;

    // ID
    uint32_t net_id = htonl(h->id);
    memcpy(p, &net_id, 4);
    p += 4;

    // Status
    *p++ = h->status;

    // Len
    uint16_t net_len = htons(h->len);
    memcpy(p, &net_len, 2);
    p += 2;

    // Body
    if (h->len > 0 && body != NULL) {
        memcpy(p, body, h->len);
    }

    return ADMIN_HEADER_SIZE + h->len;
}

// Deserializa respuesta (Para el cliente CLI)
int admin_deserialize_resp(const uint8_t *buf, size_t size, struct admin_resp_header *h) {
    if (size < ADMIN_HEADER_SIZE) return -1;

    const uint8_t *p = buf;

    uint32_t net_id;
    memcpy(&net_id, p, 4);
    h->id = ntohl(net_id);
    p += 4;

    h->status = *p++;

    uint16_t net_len;
    memcpy(&net_len, p, 2);
    h->len = ntohs(net_len);

    return ADMIN_HEADER_SIZE;
}