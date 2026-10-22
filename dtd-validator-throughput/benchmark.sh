#!/usr/bin/env bash
# benchmark.sh — validate every .dita topic of the Oxygen user guide with each
# validator; prints one result line per run. REPS runs per config (default 5).
set -euo pipefail
cd "$(dirname "$0")"
export XML_CATALOG_FILES=$PWD/work-ditaot/dita-ot-4.2.4/catalog-dita.xml
REPS=${REPS:-5}
F=work-files.txt
n=$(wc -l < $F)

cat $(cat $F) > /dev/null   # warm the page cache

for t in 1 2 4; do
  for r in $(seq "$REPS"); do
    ./work-libxml2_cached $t work-dtdmap.tsv < $F | tail -1
    rust-bench/target/release/rust-bench xmloxide $t work-dtdmap.tsv < $F | tail -1
  done
done
for t in 1 4; do
  rust-bench/target/release/rust-bench rusty_xml $t work-dtdmap.tsv < $F | tail -1
done

# Stock xmllint: one process per 50 files, DTD re-read from the catalog per file.
for p in 1 4; do
  s=$(date +%s.%N)
  xargs -a $F -P$p -n 50 xmllint --noout --valid --nonet 2>/dev/null || true
  e=$(date +%s.%N)
  awk -v n="$n" -v s="$s" -v e="$e" -v p="$p" \
    'BEGIN { printf "validator=xmllint-stock procs=%d files=%d seconds=%.3f files_per_s=%.0f\n", p, n, e-s, n/(e-s) }'
done

./benchmark-xerces.sh
./benchmark-compiled.sh
