CC      ?= clang
CFLAGS  ?= -O3 -Wall -Wextra -std=c99
INCLUDES = -I.. -I../third_party/rapidhash

bfhash_bench: bfhash_bench.c ../bfhash.h ../third_party/rapidhash/rapidhash.h aeshash.h
	$(CC) $(CFLAGS) $(INCLUDES) -o bfhash_bench bfhash_bench.c

.PHONY: all
all: bfhash_bench

.PHONY: run
run: bfhash_bench
	./bfhash_bench

.PHONY: csv
csv: bfhash_bench
	./bfhash_bench > bfhash_results.csv

# Each gp script emits both PDF for archival and paper figures and PNG
# for README embedding via raw.githubusercontent URLs. The multi-target
# rule tells make that one gnuplot invocation produces both files.
bfhash_latency.pdf bfhash_latency.png: bfhash_results.csv bfhash_latency.gp
	gnuplot bfhash_latency.gp

bfhash_speedup.pdf bfhash_speedup.png: bfhash_results.csv bfhash_speedup.gp
	gnuplot bfhash_speedup.gp

.PHONY: plot
plot: bfhash_latency.pdf bfhash_latency.png bfhash_speedup.pdf bfhash_speedup.png

.PHONY: clean
clean: clean-results
	rm -f bfhash_bench

.PHONY: clean-results
clean-results:
	rm -f bfhash_results.csv \
	      bfhash_latency.pdf bfhash_latency.png \
	      bfhash_speedup.pdf bfhash_speedup.png
