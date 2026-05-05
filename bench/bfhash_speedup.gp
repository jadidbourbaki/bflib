# USENIX-style speedup plot for bflib bench results.
#
# Usage:
#   ./bfhash_bench > bfhash_results.csv
#   gnuplot bfhash_speedup.gp
#   open bfhash_speedup.pdf
#
# Produces bfhash_speedup.pdf with size on a log x-axis and the
# speedup ratio on a linear y-axis. The single line plots column 5 of
# the CSV, which is rapidhash*2 latency divided by bfhash latency.
# Values above 1 mean bfhash is faster than the rapidhash*2 Kirsch-
# Mitzenmacher peer. A dashed gray reference line at y=1 marks parity.

set datafile separator ","

# Emit both PDF for archival and paper figures and PNG for README
# embedding. PNG is rendered after the PDF via replot, which re-runs
# the same plot command against the new terminal and output.

set terminal pdfcairo size 5.0in,3.2in font "Helvetica,11"
set output "bfhash_speedup.pdf"

set xlabel "Input Size in Bytes (log_2 scaled)"
set ylabel "Speedup Ratio of bfhash vs rapidhash_{x2}"

set logscale x 2
set xtics (8, 16, 32, 64, 128, 256, 1024)
set format x "%g"
set yrange [0.8:2.2]
set xrange [4:2048]

set grid xtics ytics linestyle 0 linecolor "gray70"
set key off
set border 3 linecolor "black"
set xtics nomirror
set ytics nomirror

# Parity reference line at y = 1.
set arrow from graph 0, first 1 to graph 1, first 1 nohead linecolor "gray50" dashtype 2

# Header skipping. The every ::1 modifier starts at record 1, so the
# CSV header at record 0 is dropped.
plot \
    "bfhash_results.csv" using 1:5 every ::1 with linespoints pointtype 7 pointsize 0.7 linewidth 1.5 linecolor "#2ca02c"

# Re-render the same plot to PNG for README embedding.
set terminal pngcairo size 1000,640 font "Helvetica,11"
set output "bfhash_speedup.png"
replot
