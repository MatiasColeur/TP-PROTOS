COMPILER=gcc

COMPILERFLAGS=-Wall -pedantic -fsanitize=address -g  -pthread -Wno-pointer-arith

LDFLAGS= -pthread -lcrypto
