# Compilador y flags
CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -I./src

# Directorios
SRC_DIR = src
OBJ_DIR = obj
BIN = main

# Archivos fuente y objetos
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

# Regla principal
all: $(BIN)

# Compilación del ejecutable
$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Compilación de cada .c a .o
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Limpieza de archivos compilados
clean:
	rm -rf $(OBJ_DIR) $(BIN)

# Limpieza total
fclean: clean

# Recompilación total
re: fclean all

.PHONY: all clean fclean re
