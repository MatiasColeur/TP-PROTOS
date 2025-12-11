include ./Makefile.inc

UNAME_S := $(shell uname -s)

SERVER_SOURCES=$(wildcard src/server/*.c)
CLIENT_SOURCES=$(wildcard src/client/*.c)
API_SOURCES=$(wildcard src/api/*.c)
SHARED_SOURCES=$(wildcard src/shared/*.c)

OBJECTS_FOLDER=./obj
OUTPUT_FOLDER=./bin

SERVER_OBJECTS=$(SERVER_SOURCES:src/%.c=obj/%.o)
CLIENT_OBJECTS=$(CLIENT_SOURCES:src/%.c=obj/%.o)
API_OBJECTS=$(API_SOURCES:src/%.c=obj/%.o)
SHARED_OBJECTS=$(SHARED_SOURCES:src/%.c=obj/%.o)

SERVER_OUTPUT_FILE=$(OUTPUT_FOLDER)/socks5

CLIENT_EXECUTABLES=$(patsubst src/client/%.c,$(OUTPUT_FOLDER)/%,$(CLIENT_SOURCES))

API_OUTPUT_FILE=$(OUTPUT_FOLDER)/api

ifeq ($(UNAME_S),Darwin)
    OPENSSL_INC_PATH = /opt/homebrew/opt/openssl/include
    OPENSSL_LIB_PATH = /opt/homebrew/opt/openssl/lib

    COMPILERFLAGS += -I$(OPENSSL_INC_PATH)
    LDFLAGS += -L$(OPENSSL_LIB_PATH) -lssl -lcrypto
else ifeq ($(UNAME_S),Linux)
    OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
    OPENSSL_LIBS   := $(shell pkg-config --libs openssl 2>/dev/null)

    COMPILERFLAGS += $(OPENSSL_CFLAGS)
    LDFLAGS += $(OPENSSL_LIBS)
endif

all: server client api

server: $(SERVER_OUTPUT_FILE)

client: $(CLIENT_EXECUTABLES)

api: $(API_OUTPUT_FILE)

$(SERVER_OUTPUT_FILE): $(SERVER_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) $(SERVER_OBJECTS) $(SHARED_OBJECTS) -o $(SERVER_OUTPUT_FILE) $(LDFLAGS)

$(CLIENT_EXECUTABLES): $(OUTPUT_FOLDER)/%: obj/client/%.o $(SHARED_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) $< $(SHARED_OBJECTS) -o $@ $(LDFLAGS)

$(API_OUTPUT_FILE): $(API_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) $(API_OBJECTS) $(SHARED_OBJECTS) -o $(API_OUTPUT_FILE) $(LDFLAGS)

clean:
	rm -rf $(OUTPUT_FOLDER)
	rm -rf $(OBJECTS_FOLDER)

obj/%.o: src/%.c
	mkdir -p $(dir $@)
	$(COMPILER) $(COMPILERFLAGS) -c $< -o $@

.PHONY: all server client api clean