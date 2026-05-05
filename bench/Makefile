CC      ?= clang
CFLAGS  ?= -O3 -Wall -Wextra -std=c99
INCLUDES = -I.. -I../third_party/rapidhash

bench: bench.c ../bfhash.h ../third_party/rapidhash/rapidhash.h
	$(CC) $(CFLAGS) $(INCLUDES) -o bench bench.c

.PHONY: run
run: bench
	./bench

.PHONY: csv
csv: bench
	./bench > results.csv

latency.pdf: results.csv latency.gp
	gnuplot latency.gp

speedup.pdf: results.csv speedup.gp
	gnuplot speedup.gp

.PHONY: plot
plot: latency.pdf speedup.pdf

.PHONY: clean
clean:
	rm -f bench

.PHONY: clean-results
clean-results:
	rm -f results.csv latency.pdf speedup.pdf