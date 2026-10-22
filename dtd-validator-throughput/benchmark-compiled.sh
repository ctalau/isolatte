#!/usr/bin/env bash
# benchmark-compiled.sh — the validators compiled from the DTDs (compiled/).
# Rust: REPS runs per thread count. JS and Java: PASSES whole-corpus passes
# per process (pass 1 cold, later JIT-warm). PARSE_ONLY rows are the parsers alone.
set -euo pipefail
cd "$(dirname "$0")"
REPS=${REPS:-5}
P=${PASSES:-5}
B=compiled/rust/target/release/dita-compiled-validator
F=work-files.txt
cat $(cat $F) > /dev/null   # warm the page cache

for t in 1 2 4; do
  for r in $(seq "$REPS"); do $B $t < $F | tail -1; done
done
for r in $(seq "$REPS"); do PARSE_ONLY=1 $B 1 < $F | tail -1; done
for t in 1 4; do node compiled/js/bench.js $t "$P" < $F | grep '^validator='; done
PARSE_ONLY=1 node compiled/js/bench.js 1 "$P" < $F | grep '^validator='
J="java -cp work-java-compiled CompiledValidator"
for t in 1 4; do $J $t "$P" < $F 2>/dev/null | grep '^validator='; done
PARSE_ONLY=1 $J 1 "$P" < $F 2>/dev/null | grep '^validator='

# Wall clock of one fresh process each, startup included.
for cmd in "$B 4" "node compiled/js/bench.js 4 1" "$J 4 1"; do
  for r in 1 2 3; do
    s=$(date +%s.%N); $cmd < $F > /dev/null 2>&1; e=$(date +%s.%N)
    awk -v c="$cmd" -v s="$s" -v e="$e" 'BEGIN { printf "wall_clock cmd=\"%s\" seconds=%.3f\n", c, e-s }'
  done
done
