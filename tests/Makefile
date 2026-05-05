CC      ?= clang
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -std=c99
INCLUDES = -I..

bfhash_test: bfhash_test.c ../bfhash.h common.h
	$(CC) $(CFLAGS) $(INCLUDES) -o bfhash_test bfhash_test.c

.PHONY: all
all: bfhash_test

.PHONY: run
run: bfhash_test
	./bfhash_test

.PHONY: clean
clean:
	rm -f bfhash_test
