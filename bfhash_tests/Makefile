CC      ?= clang
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -std=c99
INCLUDES = -I..

tests: tests.c ../bfhash.h ../test_common/test_harness.h
	$(CC) $(CFLAGS) $(INCLUDES) -o tests tests.c

.PHONY: run
run: tests
	./tests

.PHONY: clean
clean:
	rm -f tests
