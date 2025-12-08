include ./Makefile.inc

UNAME_S := $(shell uname -s)

SERVER_SOURCES=$(wildcard src/server/*.c)
CLIENT_SOURCES=$(wildcard src/client/*.c)
SHARED_SOURCES=$(wildcard src/shared/*.c)

OBJECTS_FOLDER=./obj
OUTPUT_FOLDER=./bin

SERVER_OBJECTS=$(SERVER_SOURCES:src/%.c=obj/%.o)
CLIENT_OBJECTS=$(CLIENT_SOURCES:src/%.c=obj/%.o)
SHARED_OBJECTS=$(SHARED_SOURCES:src/%.c=obj/%.o)

SERVER_OUTPUT_FILE=$(OUTPUT_FOLDER)/socks5
CLIENT_OUTPUT_FILE=$(OUTPUT_FOLDER)/client

# --- Config OpenSSL según SO ---

ifeq ($(UNAME_S),Darwin)
    OPENSSL_INC_PATH = /opt/homebrew/opt/openssl/include
    OPENSSL_LIB_PATH = /opt/homebrew/opt/openssl/lib

    COMPILERFLAGS += -I$(OPENSSL_INC_PATH)
    LDFLAGS += -L$(OPENSSL_LIB_PATH) -lssl -lcrypto
else ifeq ($(UNAME_S),Linux)
    # Usar pkg-config si está disponible
    OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
    OPENSSL_LIBS   := $(shell pkg-config --libs openssl 2>/dev/null)

    COMPILERFLAGS += $(OPENSSL_CFLAGS)
    LDFLAGS += $(OPENSSL_LIBS)
endif

all: server client
server: $(SERVER_OUTPUT_FILE)
client: $(CLIENT_OUTPUT_FILE)

$(SERVER_OUTPUT_FILE): $(SERVER_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) $(SERVER_OBJECTS) $(SHARED_OBJECTS) -o $(SERVER_OUTPUT_FILE) $(LDFLAGS)

$(CLIENT_OUTPUT_FILE): $(CLIENT_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) $(CLIENT_OBJECTS) $(SHARED_OBJECTS) -o $(CLIENT_OUTPUT_FILE) $(LDFLAGS)

clean:
	rm -rf $(OUTPUT_FOLDER)
	rm -rf $(OBJECTS_FOLDER)

obj/%.o: src/%.c
	mkdir -p $(OBJECTS_FOLDER)/server
	mkdir -p $(OBJECTS_FOLDER)/client
	mkdir -p $(OBJECTS_FOLDER)/shared
	$(COMPILER) $(COMPILERFLAGS) -c $< -o $@

.PHONY: all server client clean
