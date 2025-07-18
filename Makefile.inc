COMPILER=gcc

COMPILERFLAGS=-Wall -std=c11 -pedantic -fsanitize=address -g -pthread -Wno-pointer-arith

LDFLAGS=-lm

CHECK_INCLUDE_PATH=/opt/homebrew/include
CHECK_LIB_PATH=/opt/homebrew/lib