#include "../../include/socks5.h"
#include "../../include/errors.h"

#define BUFFER_SIZE         4096

#define ADDR_BUFFER_LEN     64

#define MAX_HOSTNAME_LENGTH 255
#define MAX_USERNAME_LENGTH 255
#define MAX_PASSWORD_LENGTH 255

#define SOCKS5_STATES  (sizeof(socks5_states) / sizeof(socks5_states[0]))
#define ATTACHMENT(key) ((struct socks5_connection *)(key)->data)

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
     * @brief Non-blocking connect() in progress (EINPROGRESS). 
     */
    int connect_pending;

    /** 
     * @brief SO_ERROR result for building the SOCKS5 reply. 
     */
    int connect_status;

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
static unsigned connect_on_write(struct selector_key *key);

static void     reply_on_arrival   (const unsigned state, struct selector_key *key);
static unsigned reply_on_write     (struct selector_key *key);

static void     relay_on_arrival   (const unsigned state, struct selector_key *key);
static unsigned relay_on_read      (struct selector_key *key);
static unsigned relay_on_write     (struct selector_key *key);

static void     done_on_arrival    (const unsigned state, struct selector_key *key);
static void     error_on_arrival   (const unsigned state, struct selector_key *key);


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


/**
 * @deprecated no longer used
 * Receives a full buffer of data from a socket, by receiving data until the requested amount
 * of bytes is reached. Returns the amount of bytes received, or -1 if receiving failed before
 * that amount was reached.
 */
static ssize_t recvFull(int fd, void* buf, size_t n, int flags) {
    size_t totalReceived = 0;

    while (totalReceived < n) {
        ssize_t nowReceived = recv(fd, buf + totalReceived, n - totalReceived, flags);
        if (nowReceived < 0) {
            perror("[ERR] recv()");
            return -1;
        }

        if (nowReceived == 0) {
            printf("[ERR] Failed to recv(), client closed connection unexpectedly\n");
            return -1;
        }

        totalReceived += nowReceived;
    }

    return totalReceived;
}

/**
 * @deprecated no longer used
 * Sends a full buffer of data from a socket, by sending data until the requested amount
 * of bytes is reached. Returns the amount of bytes sent, or -1 if sending failed before
 * that amount was reached.
 */
static ssize_t sendFull(int fd, const void* buf, size_t n, int flags) {
    size_t totalSent = 0;

    while (totalSent < n) {
        ssize_t nowSent = send(fd, buf + totalSent, n - totalSent, flags);
        if (nowSent < 0) {
            perror("[ERR] send()");
            return -1;
        }

        if (nowSent == 0) {
            printf("[ERR] Failed to send(), client closed connection unexpectedly\n");
            return -1;
        }

        totalSent += nowSent;
    }

    return totalSent;
}

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
    }
}

/**
 * @deprecated
 * @todo refactor into SOCKS5_AUTH state handlers
 */
int handleAuthNegotiation(int clientSocket, char * clientUsername, char * clientPassword) {
    ssize_t received;
    char receiveBuffer[BUFFER_SIZE + 1];

    // Socks5 starts with the client sending VER, NMETHODS followed by that amount of METHODS. Let's read VER and NMETHODS.
    received = recvFull(clientSocket, receiveBuffer, 2, 0);
    if (received < 0)
        return -1;

    // Check if that version is 5
    if (receiveBuffer[0] != VER) {
        printf("[ERR] Client specified invalid version: %d\n", receiveBuffer[0]);
        return -1;
    }

    // Read NMETHODS methods.
    int nmethods = receiveBuffer[1];
    received = recvFull(clientSocket, receiveBuffer, nmethods, 0);
    if (received < 0)
        return -1;

    // We check that the methods specified by the client contains method 2, which is "username/password".
    int hasValidAuthMethod = 0;
    printf("[INF] Client specified auth methods: ");
    for (int i = 0; i < nmethods; i++) {
        hasValidAuthMethod = hasValidAuthMethod || (receiveBuffer[i] == 2);
        printf("%x%s", receiveBuffer[i], i + 1 == nmethods ? "\n" : ", ");
    }

    // If the client didn't specify "username/password", send an error and wait for the client to close the connection.
    if (!hasValidAuthMethod) {
        printf("[ERR] No valid auth method detected!\n");
        if (sendFull(clientSocket, "\x05\xFF", 2, 0) < 0) // VER, METHOD
            return -1;

        // TODO: Investigate if we should shutdown to wait for the client to close the TCP connection,
        // and if so how can we know when the connection was finally closed (since we can't recv() anymore).
        // shutdown(clientSocket, SHUT_RDWR);

        // Wait for the client to close the TCP connection.
        printf("[INF] Waiting for client to close the connection.\n");
        while (recv(clientSocket, receiveBuffer, BUFFER_SIZE, 0) > 0) {}
        return -1;
    }

    // Tell the client we're using auth method 02 ("username/password").
    if (sendFull(clientSocket, "\x05\x02", 2, 0) < 0)
        return -1;

    char username[255];
    char password[255];
    if (handleUsernamePasswordAuth(clientSocket, username, password, sizeof(username)) < 0)
        return -1;

    strncpy(clientUsername, username, 255);
    clientUsername[254] = '\0';

    strncpy(clientPassword, password, 255);
    clientPassword[254] = '\0';

    return 0;
}

/**
 * @deprecated
 * @todo refactor into SOCKS5_REQUEST state handlers
 */
int handleRequest(int clientSocket, struct addrinfo** connectAddresses, int * clientPort, char * clientHostname) {
    ssize_t received;
    char receiveBuffer[BUFFER_SIZE + 1];

    // Read from a client request: VER, CMD, RSV, ATYP.
    received = recvFull(clientSocket, receiveBuffer, 4, 0);
    if (received < 0)
        return -1;

    // Check that the CMD the client specified is X'01' "connect". Otherwise, send and error and close the TCP connection.
    if (receiveBuffer[1] != 1) {
        // The reply specified REP as X'07' "Command not supported", ATYP as IPv4 and BND as 0.0.0.0:0.
        sendFull(clientSocket, "\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
        return -1;
    }

    // We will store the hostname and port in these variables. If the client asked to connect to an IP, we
    // will print it into hostname and then pass it throught getaddrinfo().
    // Is this the best option? Definitely not, but it's kinda easier ;)
    char hostname[MAX_HOSTNAME_LENGTH + 1];
    int port = 0;

    // The hints for getaddrinfo. We will specify we want a stream TCP socket.
    struct addrinfo addrHints;
    memset(&addrHints, 0, sizeof(addrHints));
    addrHints.ai_socktype = SOCK_STREAM;
    addrHints.ai_protocol = IPPROTO_TCP;

    // Check ATYP and print the address/hostname the client asked to connect to.
    if (receiveBuffer[3] == 1) {
        // Client requested to connect to an IPv4 address.
        addrHints.ai_family = AF_INET;

        // Read the IPv4 address (4 bytes).
        struct in_addr addr;
        received = recvFull(clientSocket, &addr, 4, 0);
        if (received < 0)
            return -1;

        // Read the port number (2 bytes).
        in_port_t portBuf;
        received = recvFull(clientSocket, &portBuf, 2, 0);
        if (received < 0)
            return -1;

        // Store the port and convert the IP to a hostname string.
        port = ntohs(portBuf);
        *clientPort = port;

        inet_ntop(AF_INET, &addr, hostname, INET_ADDRSTRLEN);

        strncpy(clientHostname, hostname, MAX_HOSTNAME_LENGTH);
        clientHostname[MAX_HOSTNAME_LENGTH] = '\0';

    } else if (receiveBuffer[3] == 3) {

        // Client requested to connect to a domain name.
        // Read one byte, the length of the domain name string.
        received = recvFull(clientSocket, receiveBuffer, 1, 0);
        if (received < 0)
            return -1;

        // Read the domain name string into the 'hostname' buffer.
        int hostnameLength = receiveBuffer[0];
        received = recvFull(clientSocket, hostname, hostnameLength, 0);
        if (received < 0)
            return -1;

        // Read the port number.
        in_port_t portBuffer;
        received = recvFull(clientSocket, &portBuffer, 2, 0);
        if (received < 0)
            return -1;

        // Store the port number and hostname.
        port = ntohs(portBuffer);
        *clientPort = port;

        hostname[hostnameLength] = '\0';
        
        strncpy(clientHostname, hostname, hostnameLength);
        clientHostname[hostnameLength] = '\0';

    } else if (receiveBuffer[3] == 4) {

        // Client requested to connect to an IPv6 address.
        addrHints.ai_family = AF_INET6;

        // Read the IPv6 address (16 bytes).
        struct in6_addr addr;
        received = recvFull(clientSocket, &addr, 16, 0);
        if (received < 0)
            return -1;

        // Read the port number (2 bytes).
        in_port_t portBuf;
        received = recvFull(clientSocket, &portBuf, 2, 0);
        if (received < 0)
            return -1;

        // Store the port and convert the IP to a hostname string.
        port = ntohs(portBuf);
        *clientPort = port;

        inet_ntop(AF_INET6, &addr, hostname, INET6_ADDRSTRLEN);

        strncpy(clientHostname, hostname, MAX_HOSTNAME_LENGTH);
        clientHostname[MAX_HOSTNAME_LENGTH] = '\0';

    } else {

        // The reply specified REP as X'08' "Address type not supported", ATYP as IPv4 and BND as 0.0.0.0:0.
        sendFull(clientSocket, "\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
        return -1;
    }

    printf("[INF] Client asked to connect to: %s:%d\n", hostname, port);

    // For "service", we will indicate the port number
    char service[6] = {0};
    snprintf(service, sizeof(service), "%d", port);

    // Call getaddrinfo to get the prepared addrinfo structures to connect to.
    int getAddrStatus = getaddrinfo(hostname, service, &addrHints, connectAddresses);
    if (getAddrStatus != 0) {
        printf("[ERR] getaddrinfo() failed: %s\n", gai_strerror(getAddrStatus));

        // The reply specifies ATYP as IPv4 and BND as 0.0.0.0:0.
        char errorMessage[10] = "\x05 \x00\x01\x00\x00\x00\x00\x00\x00";
        // We calculate the REP value based on the type of error returned by getaddrinfo
        errorMessage[1] =
            getAddrStatus == EAI_FAMILY   ? '\x08'  // REP is "Address type not supported"
            : getAddrStatus == EAI_NONAME ? '\x04'  // REP is "Host Unreachable"
                                          : '\x01'; // REP is "General SOCKS server failure"
        sendFull(clientSocket, errorMessage, 10, 0);
        return -1;
    }

    return 0;
}

/**
 * @deprecated
 * @todo refactor into SOCKS5_CONNECT and SOCKS5_REPLY state handlers
 */
int handleConnectAndReply(int clientSocket, struct addrinfo** connectAddresses, int* remoteSocket) {
    char addrBuf[64];
    int aipIndex = 0;

    // Print all the addrinfo options, just for debugging.
    for (struct addrinfo* aip = *connectAddresses; aip != NULL; aip = aip->ai_next) {
        printf("[INF] Option %i: %s (%s %s) %s %s (Flags: ", aipIndex++, printFamily(aip), printType(aip), printProtocol(aip), aip->ai_canonname ? aip->ai_canonname : "-", printAddressPort(aip, addrBuf, sizeof(addrBuf)));
        printFlags(aip);
        printf(")\n");
    }

    // Find the first addrinfo option in which we can both open a socket, and connect to the remote server.
    int sock = -1;
    char addrBuffer[128];
    for (struct addrinfo* addr = *connectAddresses; addr != NULL && sock == -1; addr = addr->ai_next) {
        sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sock < 0) {
            printf("[INF] Failed to create remote socket on %s\n", printAddressPort(addr, addrBuffer, sizeof(addrBuf)));
        } else {
            errno = 0;
            if (connect(sock, addr->ai_addr, addr->ai_addrlen) != 0) {
                printf("[INF] Failed to connect() remote socket to %s: %s\n", printAddressPort(addr, addrBuffer, sizeof(addrBuf)), strerror(errno));
                close(sock);
                sock = -1;
            } else {
                printf("[INF] Successfully connected to: %s (%s %s) %s %s (Flags: ", printFamily(addr), printType(addr), printProtocol(addr), addr->ai_canonname ? addr->ai_canonname : "-", printAddressPort(addr, addrBuf, sizeof(addrBuf)));
                printFlags(addr);
                printf(")\n"); 
            }
        }
    }

    freeaddrinfo(*connectAddresses);

    if (sock == -1) {
        printf("[ERR] Failed to connect to any of the available options.\n");
        // The reply specified REP as X'05' "Connection refused", ATYP as IPv4 and BND as 0.0.0.0:0.
        sendFull(clientSocket, "\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
        return -1;
    }

    *remoteSocket = sock;

    // Get and print the address and port at which our socket got bound.
    struct sockaddr_storage boundAddress;
    socklen_t boundAddressLen = sizeof(boundAddress);
    if (getsockname(sock, (struct sockaddr*)&boundAddress, &boundAddressLen) >= 0) {
        printSocketAddress((struct sockaddr*)&boundAddress, addrBuffer);
        printf("[INF] Remote socket bound at %s\n", addrBuffer);
    } else
        perror("[WRN] Failed to getsockname() for remote socket");

    // Send a server reply: SUCCESS, then send the address to which our socket is bound.
    if (sendFull(clientSocket, "\x05\x00\x00", 3, 0) < 0)
        return -1;

    switch (boundAddress.ss_family) {
        case AF_INET:
            // Send: '\x01' (ATYP identifier for IPv4) followed by the IP and PORT.
            if (sendFull(clientSocket, "\x01", 1, 0) < 0) return -1;
            if (sendFull(clientSocket, &((struct sockaddr_in*)&boundAddress)->sin_addr, 4, 0) < 0) return -1;
            if (sendFull(clientSocket, &((struct sockaddr_in*)&boundAddress)->sin_port, 2, 0) < 0) return -1;
            break;

        case AF_INET6:
            // Send: '\x04' (ATYP identifier for IPv6) followed by the IP and PORT.
            if (sendFull(clientSocket, "\x04", 1, 0) < 0) return -1;
            if (sendFull(clientSocket, &((struct sockaddr_in6*)&boundAddress)->sin6_addr, 16, 0) < 0) return -1;
            if (sendFull(clientSocket, &((struct sockaddr_in6*)&boundAddress)->sin6_port, 2, 0) < 0) return -1;
            break;

        default:
            // We don't know the address type? Send IPv4 0.0.0.0:0.
            if (sendFull(clientSocket, "\x01\x00\x00\x00\x00\x00\x00", 7, 0) < 0) return -1;
            break;
    }

    return 0;
}

/**
 * @deprecated
 * @todo refactor into SOCKS5_RELAY state handlers (maybe also SOCKS5_REPLY)
 */
int handleConnectionData(int clientSocket, int remoteSocket) {
    ssize_t received;
    char receiveBuffer[4096];

    // Create poll structures to say we are waiting for bytes to read on both sockets.
    struct pollfd pollFds[2];
    pollFds[0].fd = clientSocket;
    pollFds[0].events = POLLIN;
    pollFds[0].revents = 0;
    pollFds[1].fd = remoteSocket;
    pollFds[1].events = POLLIN;
    pollFds[1].revents = 0;

    // What comes in through clientSocket, we send to remoteSocket. What comes in through remoteSocket, we send to clientSocket.
    // This gets repeated until either the client or remote server closes the connection, at which point we close both connections.
    int alive = 1;
    do {
        int pollResult = poll(pollFds, 2, -1);
        if (pollResult < 0) {
            printf("[ERR] Poll returned %d: ", pollResult);
            perror(NULL);
            return -1;
        }

        for (int i = 0; i < 2 && alive; i++) {
            if (pollFds[i].revents == 0)
                continue;

            received = recv(pollFds[i].fd, receiveBuffer, sizeof(receiveBuffer), 0);
            if (received <= 0) {
                alive = 0;
            } else {
                int otherSocket = pollFds[i].fd == clientSocket ? remoteSocket : clientSocket;
                send(otherSocket, receiveBuffer, received, 0);
            }
        }
    } while (alive);

    return 0;
}


/**
 * @deprecated
 */
int handleUsernamePasswordAuth(int clientSocket, char * username, char * password, size_t maxLen) {
    char buffer[BUFFER_SIZE + 1];

    ssize_t received = recvFull(clientSocket, buffer, 2, 0);

    // VAR, ULEN, UNAME, PLEN, PASSWD

    if (buffer[0] != 0x01) {
        printf("[ERR] Invalid subnegotiation version: %d\n", buffer[0]);
        return -1;
    }

    uint8_t ulen = buffer[1];

    // Read username
    received = recvFull(clientSocket, buffer, ulen, 0);
    if (received < 0)
        return -1;
    
    // Truncate username if it's too long
    if (ulen >= maxLen) {
        fprintf(stderr, "[ERR] Username is too long\n");
        return -1;
    }

    memcpy(username, buffer, ulen);
    username[ulen] = '\0';

    // Read PLEN
    received = recvFull(clientSocket, buffer, 1, 0);
    if (received < 0)
        return -1;
    
    uint8_t plen = buffer[0];

    // Read PASSWD
    received = recvFull(clientSocket, buffer, plen, 0);
    if (received < 0)
        return -1;

    if (plen >= maxLen) {
        fprintf(stderr, "[ERR] Password is too long\n");
        return -1;
    }

    memcpy(password, buffer, plen);
    password[plen] = '\0';
    client_role role;

    // Validate credentials. In this implementation we accept every user.
    // VER, STATUS
    int authSuccess = auth_validate_user(username,password,&role);

    if (authSuccess) {
        sendFull(clientSocket, "\x01\x00", 2, 0);
        return 0;
    } else {
        sendFull(clientSocket, "\x01\x01", 2, 0);
        return 1;
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

    /**
     * @todo implement logging
     */
    // log_info("[SOCKS5] esperando HELLO en fd %d", key->fd);  
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

    
    int status = auth_validate_user(conn->username,conn->password,&conn->role);; // 0= SUCCESS;  1 = Fail

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
        case IPV4_N: // IPv4
            addr_len = 4;
            required_len += addr_len + 2; // +2 from port

            inet_ntop(AF_INET, addr_ptr, conn->host, sizeof(conn->host));
            break;
        case FQDN_N: // Domain Name
            if (len < 5) return SOCKS5_REQUEST; 
            addr_len = ptr[4];
            required_len += 1 + addr_len + 2; // 1 (len) + Domain + 2 (port)

            memcpy(conn->host, addr_ptr + 1, addr_len);
            conn->host[addr_len] = '\0';
            break;
        case IPV6_N: // IPv6
            addr_len = 16;
            required_len += addr_len + 2;
            inet_ntop(AF_INET6, addr_ptr, conn->host, sizeof(conn->host));

            break;
        default:
            log_print_error("ATYP desconocido: %d", atyp);
            return SOCKS5_ERROR;
    }

    uint16_t port_n;    //Last two bytes
    memcpy(&port_n, ptr + required_len - 2, 2);
    conn->port = ntohs(port_n); 

    buffer_read_adv(b, required_len);

    log_print_info("Request processed: CONNECT %s:%d (ATYP: %d)", conn->host, conn->port, atyp);
    logAccess(conn->username,conn->password,conn->host,conn->port);

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
    }
    // notify principal thread
    selector_notify_block(key->s, key->fd);

    free(key); //free key created in connect_on_arrival

    return NULL;
}


static void connect_on_arrival(const unsigned state, struct selector_key *key) {
    socks5_connection_ptr conn = ATTACHMENT(key);
    (void) state;

    // original key will disapear
    struct selector_key *k = malloc(sizeof(*key));
    if (k == NULL) {
        conn->connect_status = STATUS_GENERAL_SERVER_FAILURE; // Error interno
        selector_set_interest_key(key, OP_WRITE);
        conn->stm.current = &socks5_states[SOCKS5_REPLY]; // Salto de emergencia
        return;
    }
    *k = *key;

    pthread_t tid;
    // new thread
    if (pthread_create(&tid, NULL, resolution_thread, k) != 0) {
        log_print_error("Failed creating thread");
        free(k);
        conn->connect_status = STATUS_GENERAL_SERVER_FAILURE;
        // Force reply to report error
        selector_set_interest_key(key, OP_WRITE);
        return;
    }

    // pause socket while finishing thread
    selector_set_interest_key(key, OP_NOOP);
}

static unsigned connect_on_block(struct selector_key *key) {
    socks5_connection_ptr conn = ATTACHMENT(key);

    // Verify dns results
    if (conn->connect_status != SUCCESS) {
        log_print_error("Error using DNS: %d", conn->connect_status);
        return SOCKS5_REPLY;
    }

    conn->addr_next = conn->addr_list; 

    int sock = -1;
    struct addrinfo *rp;
    //trying to conect to the posibles ips
    for (rp = conn->addr_next; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1) continue;

        if (selector_fd_set_nio(sock) == -1) {
            close(sock);
            continue;
        }

        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == -1) {
            if (errno == EINPROGRESS) {
                // success
                break;
            } else {
                close(sock);
                sock = -1;
            }
        } else {
            break;
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
            selector_unregister_fd(key->s, conn->remote_fd);
            close(conn->remote_fd);
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
            log_print_error("Reply: Error (0x%02x)", conn->connect_status);
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
        // Error in the socket 
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

    // 1. Identificar quién envía datos (Origen) y quién los recibe (Destino)
    if (key->fd == conn->client_fd) {
        b_read = &conn->client_read_buf;
        other_fd = conn->remote_fd;
    } else {
        b_read = &conn->remote_read_buf;
        other_fd = conn->client_fd;
    }

    // 2. Intentar leer del socket origen
    size_t size;
    uint8_t *ptr = buffer_write_ptr(b_read, &size);
    ssize_t n = recv(key->fd, ptr, size, 0);

    if (n > 0) {
        // Success
        buffer_write_adv(b_read, n);

        // Set write in the other socket
        selector_set_interest(key->s, other_fd, OP_WRITE | OP_READ);

        if (!buffer_can_write(b_read)) {
            selector_set_interest_key(key, OP_NOOP); // Simplificación: pausar lectura
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
        // ERROR: recv got -1
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
    int other_fd;

    if (key->fd == conn->client_fd) {
        b_write = &conn->remote_read_buf;
        other_fd = conn->remote_fd;
    } else {
        b_write = &conn->client_read_buf;
        other_fd = conn->client_fd;
    }

    size_t size;
    uint8_t *ptr = buffer_read_ptr(b_write, &size);
    ssize_t n = send(key->fd, ptr, size, MSG_NOSIGNAL);

    if (n > 0) {
        buffer_read_adv(b_write, n);
        selector_set_interest(key->s, other_fd, OP_READ | OP_WRITE); // Activamos lectura en origen

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

    stm_handler_close(&conn->stm, key);

    if (key->fd == conn->client_fd) {
        conn->client_fd = -1;
    } else if (key->fd == conn->remote_fd) {
        conn->remote_fd = -1;
    }

    if (stm_state(&conn->stm) == SOCKS5_CONNECT && conn->client_fd != -1) {
        // El struct 'conn' sigue vivo y el cliente conectado.
        // The struct conn still alive and client its connected
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

static uint8_t errno_to_socks_status(int err) {
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