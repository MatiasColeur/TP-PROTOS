COMPILER=gcc

COMPILERFLAGS=-Wall -std=c11 -pedantic -fsanitize=address -g -pthread -Wno-pointer-arith

LDFLAGS=-lm