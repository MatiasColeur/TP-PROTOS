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

    /* -------- Envío del request -------- */

    req.id  = htonl(id);
    req.cmd = cmd;
    req.len = htons((uint16_t)payload_len);

    if (!write_exact(sockfd, &req, sizeof(req))) {
        print_error("Error escribiendo header admin");
        exit(1);
    }

    if (payload_len > 0) {
        if (!write_exact(sockfd, payload, payload_len)) {
            print_error("Error escribiendo payload admin");
            exit(1);
        }
    }

    /* -------- Recepción del response -------- */

    if (!read_exact(sockfd, &resp, sizeof(resp))) {
        print_error("Error leyendo header de respuesta admin");
        exit(1);
    }

    uint32_t resp_id  = ntohl(resp.id);
    uint16_t resp_len = ntohs(resp.len);

    printf("[ADMIN] Resp id=%u status=%u len=%u\n",
           resp_id, resp.status, resp_len);

    if (resp_len == 0)
        return;

    /* -------- Leer payload completo -------- */

    uint8_t *buf = malloc(resp_len + 1); // +1 para '\0'
    if (buf == NULL) {
        print_error("No memory leyendo payload admin");
        exit(1);
    }

    if (!read_exact(sockfd, buf, resp_len)) {
        free(buf);
        print_error("Error leyendo payload de respuesta admin");
        exit(1);
    }

    buf[resp_len] = '\0';

    /* -------- Mostrar -------- */

    printf("[ADMIN] Payload:\n%s", buf);
    if (resp_len > 0 && buf[resp_len - 1] != '\n') {
        printf("\n");
    }

    free(buf);
}
