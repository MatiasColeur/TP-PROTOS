#include "../../include/socks5.h"
#include "../../include/dissectors.h"


#define BUFFER_SIZE         16384

#define ADDR_BUFFER_LEN     64

#define MAX_HOSTNAME_LENGTH 255
#define MAX_USERNAME_LENGTH 255
#define MAX_PASSWORD_LENGTH 255

#define SOCKS5_STATES  (sizeof(socks5_states) / sizeof(socks5_states[0]))
#define ATTACHMENT(key) ((struct socks5_connection *)(key)->data)

static char management_host[MAX_HOSTNAME_LENGTH + 1] = LOOPBACK_IPV4;
static uint16_t management_port = ADMIN_API_PORT;
static bool dissectors_enabled = true;

/**
 * @brief Per-connection state and resources for a SOCKS5 session.
 */
struct socks5_connection {

/* -------- Infrastructure -------- */

    /** 
     * @brief Client socket endpoint. 
     */
    int client_fd;

    /** 
     * @brief Remote destination socket (after CONNECT). 
     */
    int remote_fd;

    /** 
     * @brief SOCKS5 state machine instance. 
     */
    struct state_machine stm;

    /** 
     * @brief Selector used for I/O multiplexing and notify_block. 
     */
    fd_selector selector;

/* -------- Buffers -------- */

    /** 
     * @brief High-level I/O buffers for client/remote traffic. 
     */
    buffer client_read_buf, client_write_buf;
    buffer remote_read_buf, remote_write_buf;

    /** 
     * @brief Raw backing storage for each buffer. 
     */
    uint8_t client_read_raw [BUFFER_SIZE];
    uint8_t client_write_raw[BUFFER_SIZE];
    uint8_t remote_read_raw [BUFFER_SIZE];
    uint8_t remote_write_raw[BUFFER_SIZE];

/* -------- Auth (RFC 1929) -------- */

    /** 
     * @brief Username received during authentication. 
     */
    char username[MAX_USERNAME_LENGTH + 1];

    /** 
     * @brief Password received during authentication. 
     */
    char password[MAX_PASSWORD_LENGTH + 1];

    /** * @brief Role from the authenticated user (ADMIN/USER).
     */
    client_role role;

/* -------- Request fields (RFC 1928) -------- */

    /** 
     * @brief Address type (IPv4, IPv6, DOMAIN). 
     */
    uint8_t atyp;

    /** 
     * @brief Parsed destination host (DOMAIN/IP). 
     */
    char host[MAX_HOSTNAME_LENGTH + 1];

    /** 
     * @brief Destination port. 
     */
    uint16_t port;

/* -------- Resolution & connect() -------- */

    /** 
     * @brief Results from getaddrinfo(). 
     */
    struct addrinfo *addr_list;

    /** 
     * @brief Next candidate address to try. 
     */
    struct addrinfo *addr_next;

    /**
     * @brief Destination sockaddr for literal IPv4/IPv6 (ATYP = 0x01 / 0x04).
     */
    struct sockaddr_storage dst_addr;

    /**
     * @brief Length of dst_addr.
     */
    socklen_t dst_addr_len;

    /** 
     * @brief Non-blocking connect() in progress (EINPROGRESS). 
     */
    int connect_pending;

    /** 
     * @brief SO_ERROR result for building the SOCKS5 reply. 
     */
    int connect_status;

    /**
     * @brief True when closing remote_fd to retry another address.
     */
    bool retry_connect;

/* -------- Auxiliary -------- */

    /** 
     * @brief True if client closed its half of the connection. 
     */
    bool client_closed;

    /** 
     * @brief True if remote closed its half. 
     */
    bool remote_closed;

    /** 
     * @brief String-formatted BND.ADDR for the reply. 
     */
    char bnd_addr_str[ADDR_BUFFER_LEN];

/* -------- Dissectors -------- */

    /** 
     * @brief Per-connection dissector state.
     */
    struct dissector_state dissector;
};

typedef struct socks5_connection * socks5_connection_ptr;

/**
 * @brief SOCKS5 per-connection state machine.
 *
 * @details This state machine follows the flow defined in
 * RFC 1928 (SOCKS Protocol Version 5) and RFC 1929 (Username/Password Authentication).
 *
 * Each state represents a well-defined phase of the SOCKS5 handshake,
 * request processing, and subsequent client–remote data relaying.
 */
enum socks5_state {

    /**
     * @brief Initial greeting negotiation.
     * @see RFC1928 Section 3
     */
    SOCKS5_HELLO,
    
    /**
     * @brief Username/Password authentication phase.
     * @see RFC1929
     */
    SOCKS5_AUTH,

    /**
     * @brief Parse the client request (CMD, ATYP, ADDR, PORT).
     * @note Only CONNECT is implemented in this TP.
     * @see RFC1928 Section 4
     */
    SOCKS5_REQUEST,

    /**
     * @brief Attempt connection to the target host.
     */
    SOCKS5_CONNECT,

    /**
     * @brief Send the SOCKS5 reply back to the client.
     * @see RFC1928 Section 6
     */
    SOCKS5_REPLY,

    /**
     * @brief Bidirectional relay between client and remote.
     */
    SOCKS5_RELAY,

    /**
     * @brief Normal termination state.
     */
    SOCKS5_DONE,

    /**
     * @brief Error termination state.
     */
    SOCKS5_ERROR,
};

/* -------- Prototypes for per-state handlers -------- */

static void     hello_on_arrival   (const unsigned state, struct selector_key *key);
static unsigned hello_on_read      (struct selector_key *key);

static void     auth_on_arrival    (const unsigned state, struct selector_key *key);
static unsigned auth_on_read       (struct selector_key *key);

static void     request_on_arrival (const unsigned state, struct selector_key *key);
static unsigned request_on_read    (struct selector_key *key);

static void     connect_on_arrival (const unsigned state, struct selector_key *key);
static unsigned connect_on_block   (struct selector_key *key);
static unsigned connect_on_write   (struct selector_key *key);

static void     reply_on_arrival   (const unsigned state, struct selector_key *key);
static unsigned reply_on_write     (struct selector_key *key);

static void     relay_on_arrival   (const unsigned state, struct selector_key *key);
static unsigned relay_on_read      (struct selector_key *key);
static unsigned relay_on_write     (struct selector_key *key);

static void     done_on_arrival    (const unsigned state, struct selector_key *key);
static void     error_on_arrival   (const unsigned state, struct selector_key *key);

/* Dissectors */


/**
 * @brief Handles read events for the SOCKS5 connection.
 */
static const struct state_definition socks5_states[] = {
    
    [SOCKS5_HELLO] = {
        .state          = SOCKS5_HELLO,
        .on_arrival     = hello_on_arrival,
        .on_read_ready  = hello_on_read,
    },

    [SOCKS5_AUTH] = {
        .state          = SOCKS5_AUTH,
        .on_arrival     = auth_on_arrival,
        .on_read_ready  = auth_on_read,
    },

    [SOCKS5_REQUEST] = {
        .state          = SOCKS5_REQUEST,
        .on_arrival     = request_on_arrival,
        .on_read_ready  = request_on_read,
    },

    [SOCKS5_CONNECT] = {
        .state          = SOCKS5_CONNECT,
        .on_arrival     = connect_on_arrival,
        .on_block_ready = connect_on_block,
        .on_write_ready = connect_on_write,
    },

    [SOCKS5_REPLY] = {
        .state          = SOCKS5_REPLY,
        .on_arrival     = reply_on_arrival,
        .on_write_ready = reply_on_write,
    },

    [SOCKS5_RELAY] = {
        .state          = SOCKS5_RELAY,
        .on_arrival     = relay_on_arrival,
        .on_read_ready  = relay_on_read,
        .on_write_ready = relay_on_write,
    },

    [SOCKS5_DONE] = {
        .state          = SOCKS5_DONE,
        .on_arrival     = done_on_arrival,
    },

    [SOCKS5_ERROR] = {
        .state          = SOCKS5_ERROR,
        .on_arrival     = error_on_arrival,
    },
};

/* -------- SOCKS5 fd_handler -------- */

static void socks5_read   (struct selector_key *key);
static void socks5_write  (struct selector_key *key);
static void socks5_close  (struct selector_key *key);
static void socks5_block  (struct selector_key *key);

const struct fd_handler socks5_handler = {
    .handle_read  = socks5_read,
    .handle_write = socks5_write,
    .handle_close = socks5_close,
    .handle_block = socks5_block,
};

/* -------- handle_new_connection() auxiliares prototypes -------- */

static socks5_connection_ptr new_socks5_connection(fd_selector selector, int client_fd);

static void socks5_stm_init(socks5_connection_ptr conn);
static void socks5_buffers_init(socks5_connection_ptr conn);

static bool socks5_selector_register(socks5_connection_ptr conn);

static void socks5_jump_to_initial_state(socks5_connection_ptr conn);

static void inline socks5_kill_connection(socks5_connection_ptr conn);

/**
 * @brief Principal function, called when a new client connects.
 * @details Initializes the per-connection state, state machine, buffers,
 */

void handle_new_client(fd_selector selector, int client_fd) {

    socks5_connection_ptr conn = new_socks5_connection(selector, client_fd);

    if(conn != NULL) {

        socks5_stm_init(conn);        
        socks5_buffers_init(conn);
        if(socks5_selector_register(conn)) {
            socks5_jump_to_initial_state(conn);
            return;
        }
        else{
            close(client_fd);
        }
    }
}

/* -------- SOCKS5_HELLO state handlers --------*/

static void hello_on_arrival(const unsigned state, struct selector_key *key) {
    socks5_connection_ptr conn = ATTACHMENT(key);
    (void) state;

    /* reset de buffers de entrada/salida del cliente para el saludo */
    buffer_reset(&conn->client_read_buf);
    buffer_reset(&conn->client_write_buf);

    /* seteamos interes de lectura sobre el fd del cliente */
    selector_set_interest_key(key, OP_READ);

    log_info("[SOCKS5] esperando HELLO en fd %d", key->fd);  
}

static unsigned hello_on_read(struct selector_key *key) {
    /* recupero info de la conexion */
    socks5_connection_ptr conn = ATTACHMENT(key);

    /* uso el buffer client_read_buff para guardar lo leido */
    buffer *rb = &conn->client_read_buf;

    /* leer lo disponible */
    size_t n;
    uint8_t *wptr = buffer_write_ptr(rb, &n); // esta funcion encuentra un espacio contiguo de tam n para escribir en rb 
    ssize_t r = recv(key->fd, wptr, n, 0);   // lee desde el fd del cliente al buffer de recien 
     if (r <= 0) {
        log_print_error("Invalid Connection");
        return SOCKS5_ERROR;  // error o cierre del cliente
    }
    buffer_write_adv(rb, r); // avanza el puntero de escritura del buffer 

    /* ver si ya hay datos suficientes */
    size_t avail;
    uint8_t *rptr = buffer_read_ptr(rb, &avail);
    if (avail < 2) {
        return SOCKS5_HELLO;  // esperar más
    }

    uint8_t ver      = rptr[0];
    uint8_t nmethods = rptr[1];
    if (avail < (size_t)(2 + nmethods)) {
        return SOCKS5_HELLO;  // esperar todos los métodos
    }

    if (ver != VER) {
        (void) send(key->fd, "\x05\xff", 2, 0);  // versión no soportada
        buffer_read_adv(rb, 2 + nmethods);
        log_print_error("Invalid Version");
        return SOCKS5_ERROR;
    }

    bool has_userpass = false;
    for (uint8_t i = 0; i < nmethods; i++) {
        // dentro de los metodos de auth que ofrece el cliente (que están guardados en rptr) busco si está el de user/pass (0x02)
        if (rptr[2 + i] == 0x02) {
            has_userpass = true;
            break;
        }
    }

    uint8_t resp[2] = {VER, has_userpass ? 0x02 : 0xff};
    (void) send(key->fd, resp, 2, 0); // responder al cliente con el método elegido

    buffer_read_adv(rb, 2 + nmethods); // avanza el puntero de lectura para descartar el saludo ya procesado

    if (!has_userpass) {
        return SOCKS5_ERROR; // cerrás después en handle_close
    }

    selector_set_interest_key(key, OP_READ);  // mantenemos interes de lectura sobre el fd del cliente
    return SOCKS5_AUTH; 
}


/* -------- SOCKS5_AUTH state handlers --------*/

static void auth_on_arrival(const unsigned state, struct selector_key *key) {
    socks5_connection_ptr conn = ATTACHMENT(key);
    (void) state;

    if (buffer_can_read(&conn->client_read_buf)) { // If there's bytes from another state, compacts and reset it
        buffer_compact(&conn->client_read_buf);
    } else {
        buffer_reset(&conn->client_read_buf);
    }
    buffer_reset(&conn->client_write_buf); // Reset write buffer

    selector_set_interest_key(key, OP_READ); // Indicates read in the socket
}
/**
 * @brief reads and process the message from auth user/password
 * format: VER (1) | ULEN (1) | UNAME (Var) | PLEN (1) | PASSWD (Var)
 */
static unsigned auth_on_read(struct selector_key *key) {
    socks5_connection_ptr conn = ATTACHMENT(key);
    buffer *buffer = &conn->client_read_buf;

    size_t count;
    uint8_t *wptr = buffer_write_ptr(buffer, &count);    
    ssize_t n = recv(key->fd, wptr, count, 0);//writes from socket to buffer

    if (n <= 0) {       // connection validation
        log_print_error("Invalid Connection");
        return SOCKS5_ERROR;
    }
    buffer_write_adv(buffer, n);

    size_t len;
    uint8_t *ptr = buffer_read_ptr(buffer, &len);   //get read pointer

    if (len < 2) return SOCKS5_AUTH; //if its smaller than 2, its incomplete

    uint8_t ver = ptr[0];
    uint8_t ulen = ptr[1];

    if (ver != SUBNEGOTIATION_VER) {
        log_print_error("Invalid Auth Negotiation Version");
        return SOCKS5_ERROR; //Invalid version
    }
    if (len < 2 + ulen + 1) return SOCKS5_AUTH; // its incomplete

    uint8_t plen = ptr[2 + ulen];

    size_t total_msg_len = 2 + ulen + 1 + plen;
    if (len < total_msg_len) return SOCKS5_AUTH; //its incomplete

    // copying to the struct
    memcpy(conn->username, ptr + 2, ulen);
    conn->username[ulen] = '\0';

    memcpy(conn->password, ptr + 2 + ulen + 1, plen);
    conn->password[plen] = '\0';

    buffer_read_adv(buffer, total_msg_len); //finish buffer usage

    
    int status = auth_validate_user(conn->username,conn->password, (int *) &conn->role);; // 0= SUCCESS;  1 = Fail

    //send answer
    uint8_t resp[2] = {SUBNEGOTIATION_VER , status};
    if (send(key->fd, resp, 2, 0) == -1) {
        log_print_error("Send Error");
        return SOCKS5_ERROR;
    }

    if (status != SUCCESS) {
        log_print_error("Invalid Password");
        return SOCKS5_ERROR; // failed auth
    }

    // if auth its successful, awaits for request
    selector_set_interest_key(key, OP_READ);
    return SOCKS5_REQUEST;
}

/* -------- SOCKS5_REQUEST state handlers --------*/
static void request_on_arrival(const unsigned state, struct selector_key *key) {
    socks5_connection_ptr conn = ATTACHMENT(key);
    (void) state;
    if (buffer_can_read(&conn->client_read_buf)) {
        buffer_compact(&conn->client_read_buf);
    } else {
        buffer_reset(&conn->client_read_buf);
    }
    buffer_reset(&conn->client_write_buf); // Reset write buffer

    selector_set_interest_key(key, OP_READ);
}

static unsigned request_on_read(struct selector_key *key) {
    socks5_connection_ptr conn = ATTACHMENT(key);
    buffer *b = &conn->client_read_buf;

    size_t count;
    uint8_t *wptr = buffer_write_ptr(b, &count);
    ssize_t n = recv(key->fd, wptr, count, 0);

    if (n <= 0) {
        log_print_error("Invalid Connection");
        return SOCKS5_ERROR;
    }
    buffer_write_adv(b, n);

    size_t len;
    uint8_t *ptr = buffer_read_ptr(b, &len);

    if (len < 4) return SOCKS5_REQUEST;

    uint8_t ver = ptr[0];
    uint8_t cmd = ptr[1];
    uint8_t rsv = ptr[2];
    uint8_t atyp = ptr[3];

    if (ver != VER || rsv != 0x00) return SOCKS5_ERROR;

    if (cmd != CMD) {
        log_print_error("Command not supported: %d", cmd);
        return SOCKS5_ERROR;
    }

    conn->atyp = atyp;
    size_t required_len = 4; // Header base (VER, CMD, RSV, ATYP)
    size_t addr_len = 0;


    // ptr + 4 init direction (IPv4/IPv6) or Domain
    uint8_t *addr_ptr = ptr + 4;

    switch (atyp) {
        case IPV4_N: { // IPv4
            addr_len = 4;
            required_len += addr_len + 2; // +2 port

            inet_ntop(AF_INET, addr_ptr, conn->host, sizeof(conn->host));

            struct sockaddr_in *sa = (struct sockaddr_in *)&conn->dst_addr;
            memset(sa, 0, sizeof(*sa));
            sa->sin_family = AF_INET;
            memcpy(&sa->sin_addr, addr_ptr, 4);

            conn->dst_addr_len = sizeof(*sa);
            break;
        }
        case FQDN_N: {// Domain Name
            if (len < 5) return SOCKS5_REQUEST; 
            addr_len = ptr[4];
            required_len += 1 + addr_len + 2; // 1 (len) + Domain + 2 (port)

            memcpy(conn->host, addr_ptr + 1, addr_len);
            conn->host[addr_len] = '\0';
            break;
        }
        case IPV6_N: { // IPv6
            addr_len = 16;
            required_len += addr_len + 2; // +2 port

            inet_ntop(AF_INET6, addr_ptr, conn->host, sizeof(conn->host));

            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&conn->dst_addr;
            memset(sa6, 0, sizeof(*sa6));
            sa6->sin6_family = AF_INET6;
            memcpy(&sa6->sin6_addr, addr_ptr, 16);

            conn->dst_addr_len = sizeof(*sa6);
            break;
        }
        default:
            log_print_error("ATYP desconocido: %d", atyp);
            return SOCKS5_ERROR;
    }

    uint16_t port_n;    //Last two bytes
    memcpy(&port_n, ptr + required_len - 2, 2);
    conn->port = ntohs(port_n); 

    // setear puerto en la sockaddr guardada (solo IPv4/IPv6; FQDN va por getaddrinfo)
    if (conn->atyp == IPV4_N) {
        struct sockaddr_in *sa = (struct sockaddr_in *)&conn->dst_addr;
        sa->sin_port = htons(conn->port);
    } else if (conn->atyp == IPV6_N) {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&conn->dst_addr;
        sa6->sin6_port = htons(conn->port);
    }

    dissectors_on_request(&conn->dissector, conn->port);

    buffer_read_adv(b, required_len);

    log_print_info("Request processed: CONNECT %s:%d (ATYP: %d)", conn->host, conn->port, atyp);
    struct sockaddr_storage addr;
    socklen_t addr_len2 = sizeof(addr);

    char client_ip[INET6_ADDRSTRLEN] = {0};
    int client_port = 0;

    if (getsockname(conn->client_fd, (struct sockaddr *)&addr, &addr_len2) == 0) {
        if (addr.ss_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)&addr;
            inet_ntop(AF_INET, &(ipv4->sin_addr), client_ip, sizeof(client_ip));
            client_port = ntohs(ipv4->sin_port);
        } else if (addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&addr;
            inet_ntop(AF_INET6, &(ipv6->sin6_addr), client_ip, sizeof(client_ip));
            client_port = ntohs(ipv6->sin6_port);
        }
    }

    log_access(
        conn->username,     // username
        conn->host,         // hostname (destino)
        conn->port,         // port (destino)
        client_port,        // client_port
        client_ip,          // client_ip
        conn->connect_status // status
    );
    selector_set_interest_key(key, OP_NOOP);
    return SOCKS5_CONNECT;
}

/* -------- SOCKS5_CONNECT state handlers --------*/

//thread function
static void * resolution_thread(void *arg) {
    struct selector_key *key = (struct selector_key *) arg;
    
    socks5_connection_ptr conn = ATTACHMENT(key);

    pthread_detach(pthread_self()); 

    struct addrinfo hints = {
        .ai_family   = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags    = AI_PASSIVE,
        .ai_protocol = 0
    };

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", conn->port);

    // delete prev results
    if (conn->addr_list != NULL) {
        freeaddrinfo(conn->addr_list);
        conn->addr_list = NULL;
    }

    // get host addresses
    int err = getaddrinfo(conn->host, port_str, &hints, &conn->addr_list);

    // save the result or error
    if (err != 0) {
        conn->connect_status = errno_to_socks_status(err); 
    } else {
        conn->connect_status = SUCCESS; // 0 success
        conn->addr_next = conn->addr_list;
    }
    // notify principal thread
    selector_notify_block(key->s, key->fd);

    free(key); //free key created in connect_on_arrival

    return NULL;
}


static void connect_on_arrival(const unsigned state, struct selector_key *key) {
    socks5_connection_ptr conn = ATTACHMENT(key);
    (void) state;

    // Bloqueo de acceso a la API de management para no-admin
    if (conn->port == management_port &&
        strcmp(conn->host, management_host) == 0 &&
        conn->role != ROLE_ADMIN) {

        conn->connect_status = STATUS_CONNECTION_NOT_ALLOWED;

        // forzar armado + envío de reply
        conn->stm.current = &socks5_states[SOCKS5_REPLY];
        reply_on_arrival(SOCKS5_REPLY, key);
        return;
    }

    // FQDN, thread 
    if (conn->atyp == FQDN_N) {
        struct selector_key *k = malloc(sizeof(*k));
        if (k == NULL) {
            conn->connect_status = STATUS_GENERAL_SERVER_FAILURE;
            conn->stm.current = &socks5_states[SOCKS5_REPLY];
            reply_on_arrival(SOCKS5_REPLY, key);
            return;
        }
        *k = *key;

        pthread_t tid;
        if (pthread_create(&tid, NULL, resolution_thread, k) != 0) {
            free(k);
            conn->connect_status = STATUS_GENERAL_SERVER_FAILURE;
            conn->stm.current = &socks5_states[SOCKS5_REPLY];
            reply_on_arrival(SOCKS5_REPLY, key);
            return;
        }

        // Pausar el client_fd hasta que el thread haga notify_block()
        selector_set_interest_key(key, OP_NOOP);
        return;
    }

    // IPv4/IPv6

    int family = (conn->atyp == IPV4_N) ? AF_INET : AF_INET6;

    int fd = socket(family, SOCK_STREAM, 0);
    if (fd == -1) {
        conn->connect_status = errno_to_socks_status(errno);
        conn->stm.current = &socks5_states[SOCKS5_REPLY];
        reply_on_arrival(SOCKS5_REPLY, key);
        return;
    }

    if (selector_fd_set_nio(fd) == -1) {
        conn->connect_status = errno_to_socks_status(errno);
        close(fd);
        conn->stm.current = &socks5_states[SOCKS5_REPLY];
        reply_on_arrival(SOCKS5_REPLY, key);
        return;
    }

    int rc = connect(fd, (struct sockaddr *)&conn->dst_addr, conn->dst_addr_len);

    if (rc == 0) {
        // conectó inmediato
        conn->remote_fd = fd;
        conn->connect_status = SUCCESS;

        selector_status ss = selector_register(key->s, conn->remote_fd, &socks5_handler, OP_NOOP, conn);
        if (ss != SELECTOR_SUCCESS) {
            close(conn->remote_fd);
            conn->remote_fd = -1;
            conn->connect_status = STATUS_GENERAL_SERVER_FAILURE;
        }

        conn->stm.current = &socks5_states[SOCKS5_REPLY];
        reply_on_arrival(SOCKS5_REPLY, key);
        return;
    }

    if (rc == -1 && errno == EINPROGRESS) {

        // connect no bloqueante: esperar a que el remote_fd sea write-ready
        conn->remote_fd = fd;
        conn->connect_status = SUCCESS; // “optimista”; se confirma en connect_on_write con SO_ERROR

        selector_status ss = selector_register(key->s, conn->remote_fd, &socks5_handler, OP_WRITE, conn);
        if (ss != SELECTOR_SUCCESS) {
            close(conn->remote_fd);
            conn->remote_fd = -1;
            conn->connect_status = STATUS_GENERAL_SERVER_FAILURE;

            conn->stm.current = &socks5_states[SOCKS5_REPLY];
            reply_on_arrival(SOCKS5_REPLY, key);
            return;
        }

        // No queremos más eventos del client_fd hasta confirmar connect
        selector_set_interest(key->s, conn->client_fd, OP_NOOP);
        return;
    }

    // error real inmediato
    conn->connect_status = errno_to_socks_status(errno);
    close(fd);

    conn->stm.current = &socks5_states[SOCKS5_REPLY];
    reply_on_arrival(SOCKS5_REPLY, key);
}


static unsigned connect_on_block(struct selector_key *key) {
    socks5_connection_ptr conn = ATTACHMENT(key);

    // Verify dns results
    if (conn->connect_status != SUCCESS) {
        log_print_error("Error using DNS: %d", conn->connect_status);
        return SOCKS5_REPLY;
    }

    int sock = -1;
    struct addrinfo *rp;
    //trying to conect to the posibles ips
    for (rp = conn->addr_next; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);


        // --- PREPARAR DATOS PARA LOG (IP y Puerto) ---
        char ip_str[INET6_ADDRSTRLEN] = "unknown";
        uint16_t port_log = 0;

        if (rp->ai_family == AF_INET) {
            struct sockaddr_in *v4 = (struct sockaddr_in *)rp->ai_addr;
            inet_ntop(AF_INET, &v4->sin_addr, ip_str, sizeof(ip_str));
            port_log = ntohs(v4->sin_port);
        } else if (rp->ai_family == AF_INET6) {
            struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)rp->ai_addr;
            inet_ntop(AF_INET6, &v6->sin6_addr, ip_str, sizeof(ip_str));
            port_log = ntohs(v6->sin6_port);
        }

        if (sock == -1) continue;

        if (selector_fd_set_nio(sock) == -1) {
            close(sock);
            continue;
        }

        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == -1) {
            if (errno == EINPROGRESS) {
                conn->addr_next = rp->ai_next; 
                conn->remote_fd = sock; // Guardamos el FD temporalmente
                
                // Registrar interés de escritura para saber cuándo termina el connect
                selector_status ss = selector_register(key->s, conn->remote_fd, &socks5_handler, OP_WRITE, conn);
                if (ss != SELECTOR_SUCCESS) {
                    close(conn->remote_fd);
                    conn->remote_fd = -1;
                    print_info("Error interno conectando a %s:%d. Probando siguiente...", ip_str, port_log);
                    continue; 
                }
                return SOCKS5_CONNECT;
            } else {
                close(sock);
                sock = -1;
            }
        } else {
            conn->remote_fd = sock;
            conn->connect_status = SUCCESS;
            conn->addr_next = rp->ai_next; // Por si acaso
            
            // Registramos el socket remoto (aunque ya conectó, pasamos a REPLY)
            selector_status ss = selector_register(key->s, conn->remote_fd, &socks5_handler, OP_NOOP, conn);
            if (ss != SELECTOR_SUCCESS) {
                close(conn->remote_fd);
                return SOCKS5_ERROR;
            }
            return SOCKS5_REPLY;
        }
    }
    conn->addr_next = rp;

    if (sock == -1) {
        conn->connect_status = STATUS_CONNECTION_REFUSED;
        return SOCKS5_REPLY;
    }

    conn->remote_fd = sock;
    
    selector_status ss = selector_register(key->s, conn->remote_fd, &socks5_handler, OP_WRITE, conn);
    
    if (ss != SELECTOR_SUCCESS) {
        close(conn->remote_fd);
        conn->remote_fd = -1;
        conn->connect_status = STATUS_GENERAL_SERVER_FAILURE;
        return SOCKS5_REPLY;
    }

    return SOCKS5_CONNECT; // stay in connect
}

static unsigned connect_on_write(struct selector_key *key) {
    socks5_connection_ptr conn = ATTACHMENT(key);

    // if the event comes from the remote socket, its confirms connect()
    if (key->fd == conn->remote_fd) {
        int error = 0;
        socklen_t len = sizeof(error);
        
        getsockopt(conn->remote_fd, SOL_SOCKET, SO_ERROR, &error, &len);

        if (error == 0) {
            conn->connect_status =SUCCESS; 
            
            selector_set_interest_key(key, OP_NOOP);
            return SOCKS5_REPLY;
        } else {            
            log_print_error("Failed connecting: %s", strerror(error));

            if (conn->addr_next != NULL) {
                conn->retry_connect = true;
                selector_unregister_fd(key->s, conn->remote_fd);
                conn->retry_connect = false;
                conn->remote_fd = -1;
                selector_notify_block(key->s, conn->client_fd);
                return SOCKS5_CONNECT; 
            }

            // 3. No quedan más IPs, reportamos el error final
            conn->retry_connect = true;
            selector_unregister_fd(key->s, conn->remote_fd);
            conn->retry_connect = false;
            conn->remote_fd = -1;
            conn->connect_status = errno_to_socks_status(error);
            return SOCKS5_REPLY;
        }
    }

    return SOCKS5_CONNECT;
}

/* -------- SOCKS5_REPLY state handlers --------*/

static void reply_on_arrival(const unsigned state, struct selector_key *key) {
    socks5_connection_ptr conn = ATTACHMENT(key);
    (void) state;

    buffer_reset(&conn->client_write_buf);

    // Variables para armar la respuesta (Valores por defecto para error: 0.0.0.0:0)
    uint8_t atyp = 0x01;        // IPv4
    uint8_t bnd_addr[16] = {0};
    uint8_t bnd_port[2] = {0};
    size_t addr_len = 4;

    
    if (conn->connect_status == SUCCESS && conn->remote_fd != -1) {
        struct sockaddr_storage local_addr;
        socklen_t len = sizeof(local_addr);
        
        if (getsockname(conn->remote_fd, (struct sockaddr *)&local_addr, &len) == 0) {
            if (local_addr.ss_family == AF_INET) {
                struct sockaddr_in *s = (struct sockaddr_in *)&local_addr;
                atyp = IPV4_N;
                addr_len = 4;
                memcpy(bnd_addr, &s->sin_addr, 4);
                memcpy(bnd_port, &s->sin_port, 2);
            } else if (local_addr.ss_family == AF_INET6) {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *)&local_addr;
                atyp = IPV6_N;
                addr_len = 16;
                memcpy(bnd_addr, &s->sin6_addr, 16);
                memcpy(bnd_port, &s->sin6_port, 2);
            }
        }
    }
    // Format: VER(1) | REP(1) | RSV(1) | ATYP(1) | BND.ADDR(Var) | BND.PORT(2)
    size_t required = 4 + addr_len + 2;
    size_t space;
    uint8_t *ptr = buffer_write_ptr(&conn->client_write_buf, &space);

    if (space >= required) {
        ptr[0] = VER;                  // VER
        ptr[1] = conn->connect_status;  // REP (0x00 = Success, others = Error)
        ptr[2] = 0x00;                  // RSV
        ptr[3] = atyp;                  // ATYP
        memcpy(ptr + 4, bnd_addr, addr_len);
        memcpy(ptr + 4 + addr_len, bnd_port, 2);
        
        buffer_write_adv(&conn->client_write_buf, required);
        
        if (conn->connect_status == SUCCESS) {
            log_print_success("Reply: Success");
        } else {
            log_print_error("Reply: Error (0x%02x) %s", conn->connect_status,strerror(conn->connect_status));
        }
    } else {
        log_print_error("Buffer overflow");
    }
    selector_set_interest(key->s, conn->client_fd, OP_WRITE);
    
    if (conn->remote_fd != -1) {
        selector_set_interest(key->s, conn->remote_fd, OP_NOOP);
    }}

static unsigned reply_on_write(struct selector_key *key) {
    socks5_connection_ptr conn = ATTACHMENT(key);

    buffer *b = &conn->client_write_buf;
    size_t count;
    uint8_t *ptr = buffer_read_ptr(b, &count);

    ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL);

    if (n == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return SOCKS5_REPLY;
        }
        log_print_error("Failed sending Reply: %s", strerror(errno));
        return SOCKS5_DONE;
    }

    buffer_read_adv(b, n);

    //verify still things to send
    if (buffer_can_read(b)) {
        return SOCKS5_REPLY;
    }

    if (conn->connect_status == SUCCESS) {
        // Handshake finished
        log_print_success("Handshake finished");
        return SOCKS5_RELAY;
    } else {
        // ERROR: finishing connection
        log_print_info("Reply error, finishing connection");
        return SOCKS5_DONE;
    }
}

/* -------- SOCKS5_RELAY state handlers --------*/

static void relay_on_arrival(const unsigned state, struct selector_key *key) {
    socks5_connection_ptr conn = ATTACHMENT(key);
    (void) state;

    log_print_success("Tunnel Established: %d <-> %d", conn->client_fd, conn->remote_fd);
    fd_interest client_int = OP_READ;
    fd_interest remote_int = OP_READ;

    // Verify if there are data
    if (buffer_can_read(&conn->client_read_buf)) {
        remote_int |= OP_WRITE;
    }

    selector_set_interest(key->s, conn->client_fd, client_int);
    selector_set_interest(key->s, conn->remote_fd, remote_int);
}

static unsigned relay_on_read(struct selector_key *key) {
    socks5_connection_ptr conn = ATTACHMENT(key);

    buffer *b_read;
    int other_fd;

    // Determinar origen y destino
    if (key->fd == conn->client_fd) {
        b_read   = &conn->client_read_buf;
        other_fd = conn->remote_fd;
    } else {
        b_read   = &conn->remote_read_buf;
        other_fd = conn->client_fd;
    }

    // Leer del origen
    size_t size;
    uint8_t *ptr = buffer_write_ptr(b_read, &size);
    ssize_t n = recv(key->fd, ptr, size, 0);

    if (n > 0) {
        // Success
        if (key->fd == conn->client_fd) {
            dissectors_feed(&conn->dissector, ptr, (size_t)n,
                            conn->username, conn->host, conn->port);
        }
        buffer_write_adv(b_read, n);

        // ===== WRITE OPTIMISTA =====
        size_t wsize;
        uint8_t *wptr = buffer_read_ptr(b_read, &wsize);

        ssize_t wn = send(other_fd, wptr, wsize, MSG_NOSIGNAL);
        
        if (wn > 0) {
            log_bytes((uint64_t)wn);
            buffer_read_adv(b_read, wn);
        }

        // ¿Quedaron datos sin enviar?
        if (buffer_can_read(b_read)) {
            selector_set_interest(key->s, other_fd, OP_WRITE | OP_READ);
        }

        // Si el buffer se llenó, pausar lectura
        if (!buffer_can_write(b_read)) {
            selector_set_interest_key(key, OP_NOOP);
        }

    } else if (n == 0) {
        // EOF
        shutdown(other_fd, SHUT_WR);

        selector_set_interest_key(key, OP_NOOP);

        if (key->fd == conn->client_fd) conn->client_closed = true;
        else conn->remote_closed = true;

        if (conn->client_closed && conn->remote_closed) {
            return SOCKS5_DONE;
        }

    } else {
        if (errno == ECONNRESET) {
            printf("[INF] Connection reset by peer\n");
            return SOCKS5_DONE;
        }

        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log_print_error("Error en túnel recv: %s", strerror(errno));
            return SOCKS5_DONE;
        }
    }

    return SOCKS5_RELAY;
}


static unsigned relay_on_write(struct selector_key *key) {
    socks5_connection_ptr conn = ATTACHMENT(key);

    buffer *b_write;

    // Determinar buffer a enviar
    if (key->fd == conn->client_fd) {
        b_write  = &conn->remote_read_buf;
    } else {
        b_write  = &conn->client_read_buf;
    }

    size_t size;
    uint8_t *ptr = buffer_read_ptr(b_write, &size);

    ssize_t n = send(key->fd, ptr, size, MSG_NOSIGNAL);
    log_bytes((uint64_t)n);

    if (n > 0) {
        buffer_read_adv(b_write, n);

        // Si ya no queda nada por enviar → dejar de escuchar OP_WRITE
        if (!buffer_can_read(b_write)) {
            selector_set_interest_key(key, OP_READ);
        }

    } else if (n == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log_print_error("Error in tunnel send: %s", strerror(errno));
            return SOCKS5_DONE;
        }
    }

    return SOCKS5_RELAY;
}


/* -------- SOCKS5_DONE state handlers --------*/

/**
 * @note handle_close() will take care of cleaning up the connection.
 */
static void done_on_arrival(const unsigned state, struct selector_key *key) {
    (void) state;
    
    // this calls socks5_close
    if (key->fd != -1) {
        selector_unregister_fd(key->s, key->fd);
    }
}

/* -------- SOCKS5_ERROR state handlers --------*/

/**
 * @note handle_close() will take care of cleaning up the connection.
 */
static void error_on_arrival(const unsigned state, struct selector_key *key) {
    (void) state;
    
    log_print_error("Error state on fd %d, closing...\n", key->fd);
    
    if (key->fd != -1) {
        selector_unregister_fd(key->s, key->fd);
    }
}

/* -------- per-state handlers -------- */

static void
socks5_read(struct selector_key *key) {
    struct socks5_connection *conn = ATTACHMENT(key);
    stm_handler_read(&conn->stm, key);
}

static void
socks5_write(struct selector_key *key) {
    struct socks5_connection *conn = ATTACHMENT(key);
    stm_handler_write(&conn->stm, key);
}

static void
socks5_block(struct selector_key *key) {
    struct socks5_connection *conn = ATTACHMENT(key);
    stm_handler_block(&conn->stm, key);
}

static void 
socks5_close(struct selector_key *key) {
    socks5_connection_ptr conn = ATTACHMENT(key);
    const bool closing_remote = (key->fd == conn->remote_fd);

    close(key->fd);

    stm_handler_close(&conn->stm, key);

    if (key->fd == conn->client_fd) {
        conn->client_fd = -1;
    } else if (closing_remote) {
        conn->remote_fd = -1;
    }

    if (closing_remote && conn->retry_connect) {
        return;
    }

    // verify if theres another socket open
    int other_fd = -1;
    if (conn->client_fd != -1) other_fd = conn->client_fd;
    else if (conn->remote_fd != -1) other_fd = conn->remote_fd;

    if (other_fd != -1) {
        selector_unregister_fd(key->s, other_fd);
        return;
    }
    //finish if both are closed
    if (conn->client_fd == -1 && conn->remote_fd == -1) {
        socks5_kill_connection(conn);
    }

    log_exit();
}

/* -------- handle_new_connection() auxiliares -------- */

static socks5_connection_ptr 
new_socks5_connection(fd_selector selector, int client_fd) {
    
    socks5_connection_ptr conn = calloc(1, sizeof(*conn));
    
    if (conn == NULL) {

        perror("[ERR] malloc socks5_connection");
        close(client_fd);
        return NULL;
    }

    conn->client_fd = client_fd;
    conn->remote_fd = -1;
    conn->selector = selector;
    dissectors_init(&conn->dissector, dissectors_enabled);

    return conn;
}

static void
socks5_stm_init(socks5_connection_ptr conn) {
    
    conn->stm.initial = SOCKS5_HELLO;
    conn->stm.states =  socks5_states;
    conn->stm.max_state = SOCKS5_ERROR;
    stm_init(&conn->stm);
}

static void
socks5_buffers_init(socks5_connection_ptr conn) {
    
    buffer_init(&conn->client_read_buf, sizeof(conn->client_read_raw), conn->client_read_raw);
    buffer_init(&conn->client_write_buf, sizeof(conn->client_write_raw), conn->client_write_raw);
    buffer_init(&conn->remote_read_buf, sizeof(conn->remote_read_raw), conn->remote_read_raw);
    buffer_init(&conn->remote_write_buf, sizeof(conn->remote_write_raw), conn->remote_write_raw);
}

static bool
socks5_selector_register(socks5_connection_ptr conn) {
    selector_status st = selector_register(conn->selector, conn->client_fd,
        &socks5_handler, OP_READ, conn);

    if (st != SELECTOR_SUCCESS) {
        fprintf(stderr, "selector_register(client_fd) error: %s\n", selector_error(st));
        socks5_kill_connection(conn);
        return false;
    }

    return true;
}

static void 
socks5_jump_to_initial_state(socks5_connection_ptr conn) {

    conn->stm.current = conn->stm.states + conn->stm.initial;
            if (conn->stm.current->on_arrival != NULL) {
                struct selector_key key = {
                    .s    = conn->selector,
                    .fd   = conn->client_fd,
                    .data = conn,
                };
                conn->stm.current->on_arrival(conn->stm.current->state, &key);
            }
}

static void inline
socks5_kill_connection(socks5_connection_ptr conn) {
    if(conn != NULL) {
        if(conn->client_fd != -1) {
            close(conn->client_fd);
            conn->client_fd = -1;
        }
        if(conn->remote_fd != -1) {
            close(conn->remote_fd);
            conn->remote_fd = -1;
        }

        free(conn);
    }
}

uint8_t errno_to_socks_status(int err) {
    switch (err) {
        case 0: return STATUS_SUCCEDED;
        case ECONNREFUSED: return STATUS_CONNECTION_REFUSED;
        case EHOSTUNREACH: return STATUS_HOST_UNREACHABLE;
        case ENETUNREACH:  return STATUS_NETWORK_UNREACHABLE;
        case ETIMEDOUT:    return STATUS_HOST_UNREACHABLE; // O TTL expired
        case ENETDOWN:     return STATUS_NETWORK_UNREACHABLE;
        case EADDRNOTAVAIL: return STATUS_ADDRESS_TYPE_NOT_SUPPORTED;
        default:           return STATUS_GENERAL_SERVER_FAILURE;
    }
}

void socks5_set_dissectors_enabled(bool enabled) {
    dissectors_enabled = enabled;
}

void socks5_set_management_endpoint(const char *addr, uint16_t port) {
    if (addr != NULL) {
        strncpy(management_host, addr, sizeof(management_host) - 1);
        management_host[sizeof(management_host) - 1] = '\0';
    }
    management_port = port;
}
