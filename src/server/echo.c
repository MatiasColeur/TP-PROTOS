#include "../../include/echo.h"

struct connection_info {
    struct state_machine stm;

    uint8_t read_buffer[4096];
    uint8_t write_buffer[4096];

    size_t read_bytes;
    size_t write_bytes;
    size_t write_offset;
};

enum echo_state {
    ECHO_HELLO = 0,
    ECHO_READ,     
    ECHO_WRITE,    
    ECHO_DONE,     
    ECHO_ERROR,
};

static void echo_handle_read (struct selector_key *key);
static void echo_handle_write(struct selector_key *key);
static void echo_handle_block(struct selector_key *key);
static void echo_handle_close(struct selector_key *key);

static const fd_handler echo_handler = {
    .handle_read  = echo_handle_read,
    .handle_write = echo_handle_write,
    .handle_block = echo_handle_block,
    .handle_close = echo_handle_close,
};

static void     echo_hello_on_arrival(const unsigned state, struct selector_key *key);
static unsigned echo_hello_on_read   (struct selector_key *key);

static void     echo_read_on_arrival (const unsigned state, struct selector_key *key);
static unsigned echo_read_on_read    (struct selector_key *key);

static void     echo_write_on_arrival(const unsigned state, struct selector_key *key);
static unsigned echo_write_on_write  (struct selector_key *key);

static void     echo_done_on_arrival (const unsigned state, struct selector_key *key);
static void     echo_error_on_arrival(const unsigned state, struct selector_key *key);

static const struct state_definition echo_states[] = {
    {
        .state          = ECHO_HELLO,
        .on_arrival     = echo_hello_on_arrival,
        .on_read_ready  = echo_hello_on_read,
    },
    {
        .state          = ECHO_READ,
        .on_arrival     = echo_read_on_arrival,
        .on_read_ready  = echo_read_on_read,
    },
    {
        .state          = ECHO_WRITE,
        .on_arrival     = echo_write_on_arrival,
        .on_write_ready = echo_write_on_write,
    },
    {
        .state          = ECHO_DONE,
        .on_arrival     = echo_done_on_arrival,
    },
    {
        .state          = ECHO_ERROR,
        .on_arrival     = echo_error_on_arrival,
    },
};


void handle_new_client(fd_selector selector, int client_fd) {
    struct connection_info * client = malloc(sizeof(*client));
    if (client == NULL) {
        perror("[ERR] malloc connection_info");
        close(client_fd);
        return;
    }

    client->stm.initial   = ECHO_HELLO;
    client->stm.states    = echo_states;
    client->stm.max_state = ECHO_ERROR;
    stm_init(&client->stm);

    selector_status st = selector_register(selector, client_fd, 
        &echo_handler, OP_READ, client);

    if (st != SELECTOR_SUCCESS) {
        fprintf(stderr, "selector_register(client_fd) error: %s\n", selector_error(st));
        close(client_fd);
        free(client);
        return;
    }

    // Ejecutamos el estado inicial apenas se acepta la conexión (antes de que llegue un read).
    client->stm.current = client->stm.states + client->stm.initial;
    if (client->stm.current->on_arrival != NULL) {
        struct selector_key key = {
            .s    = selector,
            .fd   = client_fd,
            .data = client,
        };
        client->stm.current->on_arrival(client->stm.current->state, &key);
    }
}

static void echo_handle_read(struct selector_key *key) {
    struct connection_info *client = key->data;
    stm_handler_read(&client->stm, key);
}

static void echo_handle_write(struct selector_key *key) {
    struct connection_info *client = key->data;
    stm_handler_write(&client->stm, key);
}

static void echo_handle_block(struct selector_key *key) {
    struct connection_info *client = key->data;
    stm_handler_block(&client->stm, key);
}

static void echo_handle_close(struct selector_key *key) {
    struct connection_info *client = key->data;
    free(client);
    close(key->fd);
    printf("[INF] Closed connection on fd %d\n", key->fd);
}


//------------------ ECHO_HELLO state handlers --------------------------------------------

static void echo_hello_on_arrival(const unsigned state, struct selector_key *key) {
    (void) state;
    const char *msg = "Echo server ready. Escribí algo y lo devuelvo.";
    ssize_t n = send(key->fd, msg, strlen(msg), 0);
    (void)n;

    selector_set_interest_key(key, OP_READ);
}

static unsigned echo_hello_on_read(struct selector_key *key) {
    (void)key;
    // primer evento de lectura → pasamos al estado de lectura normal
    return ECHO_READ;
}

//------------------ ECHO_READ state handlers --------------------------------------------

static void echo_read_on_arrival(const unsigned state, struct selector_key *key) {
    (void) state;
    // nos aseguramos de que solo nos interese leer
    selector_set_interest_key(key, OP_READ);
}

static unsigned echo_read_on_read(struct selector_key *key) {
    struct connection_info *client = key->data;

    ssize_t n = recv(key->fd, client->read_buffer, sizeof(client->read_buffer), 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no hay datos ahora, seguimos en el mismo estado
            return ECHO_READ;
        }
        perror("[ERR] recv");
        return ECHO_DONE;
    }

    if (n == 0 || (n == 1 && client->read_buffer[0] == EOF)) {
        // EOF → cliente cerró la conexión
        return ECHO_DONE;
    }

    // copiamos lo recibido al buffer de escritura
    memcpy(client->write_buffer, client->read_buffer, (size_t)n);
    client->write_bytes  = (size_t)n;
    client->write_offset = 0;

    // ahora nos interesa escribir
    selector_set_interest_key(key, OP_WRITE);

    return ECHO_WRITE;
}

//------------------ ECHO_WRITE state handlers -------------------------------------------

static void echo_write_on_arrival(const unsigned state, struct selector_key *key) {
    (void) state;
    // aseguramos que tenemos interés en escribir
    selector_set_interest_key(key, OP_WRITE);
}

static unsigned echo_write_on_write(struct selector_key *key) {
    struct connection_info *client = key->data;

    while (client->write_offset < client->write_bytes) {
        ssize_t n = send(
            key->fd,
            client->write_buffer + client->write_offset,
            client->write_bytes - client->write_offset,
            0
        );

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // no podemos escribir más ahora, seguimos en WRITE
                return ECHO_WRITE;
            }
            perror("[ERR] send");
            return ECHO_DONE;
        }

        if (n == 0) {
            return ECHO_DONE;
        }

        client->write_offset += (size_t)n;
    }

    // ya mandamos todo → volvemos a leer
    selector_set_interest_key(key, OP_READ);
    return ECHO_READ;
}

//------------------ ECHO_DONE state handlers --------------------------------------------

static void echo_done_on_arrival(const unsigned state, struct selector_key *key) {
    (void) state;
    selector_unregister_fd(key->s, key->fd);
}

//------------------ ECHO_ERROR state handlers -------------------------------------------

static void echo_error_on_arrival(const unsigned state, struct selector_key *key) {
    (void) state;
    fprintf(stderr, "[ERR] echo: error state on fd %d, closing...\n", key->fd);
    // ante un error liberamos el fd del selector; handle_close se encarga del free
    selector_unregister_fd(key->s, key->fd);
}
