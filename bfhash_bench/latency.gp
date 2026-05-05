# USENIX-style latency plot for bflib bench results.
#
# Usage:
#   ./bench > results.csv
#   gnuplot plot.gp
#   open latency.pdf
#
# Produces latency.pdf with size on a log x-axis and ns/call on a
# linear y-axis, with one line per hash variant.

set datafile separator ","

set terminal pdfcairo size 5.0in,3.2in font "Helvetica,11"
set output "latency.pdf"

# set title "Per-call latency, dependency-chained, lower is better"
set xlabel "Input Size in Bytes (log_2 scaled)"
set ylabel "Per-call Latency in ns"

set logscale x 2
set xtics (8, 16, 32, 64, 128, 256, 1024)
set format x "%g"
set yrange [0:*]
set xrange[4:2048]

set grid xtics ytics linestyle 0 linecolor "gray70"
set key top left box linecolor "gray50" opaque
set border 3 linecolor "black"
set xtics nomirror
set ytics nomirror

# Header skipping. `every ::1` starts at record 1, so the CSV header at
# record 0 is dropped. We deliberately do NOT also set commentschars to
# include "s" because then the header would be filtered as a comment
# and `every ::1` would skip the first real data row on top of that,
# silently dropping the smallest-size datapoint.

# Three series from columns: rapidhash (col 2), rapidhash*2 (col 3), bfhash (col 4).
plot \
    "results.csv" using 1:2 every ::1 with linespoints pointtype 1 pointsize 0.7 linewidth 1.5 linecolor "#1f77b4" title "rapidhash", \
    "" using 1:3 every ::1 with linespoints pointtype 2 pointsize 0.7 linewidth 1.5 linecolor "#d62728" title "rapidhash x2", \
    "" using 1:4 every ::1 with linespoints pointtype 3 pointsize 0.8 linewidth 1.5 linecolor "#2ca02c" title "bfhash"
