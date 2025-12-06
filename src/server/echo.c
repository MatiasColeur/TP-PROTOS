#include "../../include/echo.h"

struct connection_info {
    struct state_machine stm;

    buffer  read_buf;
    buffer  write_buf;
    uint8_t read_raw[4096];
    uint8_t write_raw[4096];
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

// State machine:

    client->stm.initial   = ECHO_HELLO;
    client->stm.states    = echo_states;
    client->stm.max_state = ECHO_ERROR;
    stm_init(&client->stm);

// Buffer:

    buffer_init(&client->read_buf,  sizeof(client->read_raw),  client->read_raw);
    buffer_init(&client->write_buf, sizeof(client->write_raw), client->write_raw);

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
    selector_set_interest_key(key, OP_READ);
}



static unsigned echo_read_on_read(struct selector_key *key) {
    struct connection_info *client = key->data;

    size_t wbytes;
    uint8_t *wptr = buffer_write_ptr(&client->read_buf, &wbytes);

    if (wbytes == 0) {
        // read_buf lleno -> no podemos leer más, pasemos a escribir
        selector_set_interest_key(key, OP_WRITE);
        return ECHO_WRITE;
    }

    ssize_t n = recv(key->fd, wptr, wbytes, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return ECHO_READ; // no hay datos ahora
        }
        perror("[ERR] recv");
        return ECHO_DONE;
    }

    if (n == 0) {
        return ECHO_DONE;
    }

    buffer_write_adv(&client->read_buf, n);

    // Copiar del read_buf al write_buf (echo)
    while (buffer_can_read(&client->read_buf) && buffer_can_write(&client->write_buf)) {
        uint8_t c = buffer_read(&client->read_buf);
        buffer_write(&client->write_buf, c);
    }

    // Si hay que mandar datos, vamos a ECHO_WRITE
    if (buffer_can_read(&client->write_buf)) {
        selector_set_interest_key(key, OP_WRITE);
        return ECHO_WRITE;
    }

    // si no hay nada para escribir, seguimos leyendo
    selector_set_interest_key(key, OP_READ);
    return ECHO_READ;
}


//------------------ ECHO_WRITE state handlers -------------------------------------------

static void echo_write_on_arrival(const unsigned state, struct selector_key *key) {
    (void) state;
    // aseguramos que tenemos interés en escribir
    selector_set_interest_key(key, OP_WRITE);
}

static unsigned echo_write_on_write(struct selector_key *key) {
    struct connection_info *client = key->data;

    while (buffer_can_read(&client->write_buf)) {
        size_t rbytes;
        uint8_t *rptr = buffer_read_ptr(&client->write_buf, &rbytes);

        if (rbytes == 0) {
            break;
        }

        ssize_t n = send(key->fd, rptr, rbytes, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // no podemos escribir más ahora
                return ECHO_WRITE;
            }
            perror("[ERR] send");
            return ECHO_DONE;
        }

        if (n == 0) {
            // no sé que pasó
            return ECHO_DONE;
        }

        buffer_read_adv(&client->write_buf, n);
    }

    // si ya no queda nada para escribir, volvemos a leer
    if (!buffer_can_read(&client->write_buf)) {
        selector_set_interest_key(key, OP_READ);
        return ECHO_READ;
    }

    // todavía queda algo por escribir
    return ECHO_WRITE;
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
