#include "../../include/api.h"

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