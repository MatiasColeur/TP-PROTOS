#include "../../include/api.h"
#include "../../include/errors.h"
#include "../../include/shared.h"

void admin_send_request(int sockfd, uint32_t id, uint8_t cmd, const char *payload) {
    size_t payload_len = payload ? strlen(payload) : 0;
    
    struct admin_req_header req_h;
    req_h.id = id;
    req_h.cmd = cmd;
    req_h.len = (uint16_t)payload_len;
    uint8_t send_buf[1024]; 
    
    int bytes_to_send = admin_serialize_req(&req_h, (const uint8_t*)payload, send_buf, sizeof(send_buf));

    if (bytes_to_send < 0) {
        print_error("Error: Payload demasiado grande o buffer insuficiente");
        return;
    }

    // 3. Enviar los bytes serializados
    if (!write_exact(sockfd, send_buf, bytes_to_send)) {
        print_error("Error enviando request al servidor");
        return; // O exit(1)
    }
    uint8_t header_buf[ADMIN_HEADER_SIZE];
    
    if (!read_exact(sockfd, header_buf, ADMIN_HEADER_SIZE)) {
        print_error("Error leyendo header de respuesta admin (Posible desconexión del servidor)");
        return;
    }

    // 5. Deserializar el header (Bytes -> Struct)
    struct admin_resp_header resp_h;
    if (admin_deserialize_resp(header_buf, ADMIN_HEADER_SIZE, &resp_h) < 0) {
        print_error("Error deserializando respuesta");
        return;
    }

    printf("[ADMIN] Resp id=%u status=%u len=%u\n", resp_h.id, resp_h.status, resp_h.len);

    if (resp_h.len > 0) {
        // Reservar memoria o usar buffer estático según prefieras
        char body_buf[1024]; 
        size_t to_read = (resp_h.len < sizeof(body_buf) - 1) ? resp_h.len : sizeof(body_buf) - 1;

        if (!read_exact(sockfd, body_buf, to_read)) {
            print_error("Error leyendo cuerpo de respuesta");
            return;
        }
        
        
        body_buf[to_read] = '\0'; // Null-terminate para imprimir
        printf("[ADMIN] Payload: %s\n", body_buf);
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