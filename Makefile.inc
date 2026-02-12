COMPILER=gcc

COMPILERFLAGS=-Wall -pedantic -g -std=c11 -pthread -Wno-pointer-arith -D_POSIX_C_SOURCE=200809L -O2

LDFLAGS= -pthread -lcrypto
