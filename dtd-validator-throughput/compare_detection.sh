#!/usr/bin/env bash
# compare_detection.sh MUTANT-DIR — how many mutants of each kind every
# validator flags as invalid ("ok-*" kinds are valid controls: expect 0).
set -euo pipefail
cd "$(dirname "$0")"
M=$1
export XML_CATALOG_FILES=$PWD/work-ditaot/dita-ot-4.2.4/catalog-dita.xml
L=work-ditaot/dita-ot-4.2.4/lib
CP=work-java:$L/xercesImpl-2.12.2.jar:$L/xml-apis-1.4.01.jar:$L/xml-resolver-1.2.jar
flagged() { grep '^INVALID' | cut -d' ' -f2 | sort -u; }
declare -A out
# Ground truth: stock xmllint, which loads the full DTD (and its entities) per file.
out[xmllint]=$(xargs -a $M/files.txt -n 25 xmllint --noout --valid --nonet 2>&1 >/dev/null \
  | grep -oE "^$M/[^:]*\.dita" | sort -u || true)
out[libxml2]=$(./work-libxml2_cached 4 work-dtdmap.tsv < $M/files.txt | flagged)
out[xmloxide]=$(rust-bench/target/release/rust-bench xmloxide 4 work-dtdmap.tsv < $M/files.txt | flagged)
out[xerces]=$(java -cp "$CP" XercesBench 4 work-dtdmap.tsv flat x publicid < $M/files.txt 2>/dev/null | flagged)
out[compiled-rust]=$(compiled/rust/target/release/dita-compiled-validator 4 < $M/files.txt | flagged)
out[compiled-js]=$(node compiled/js/bench.js 4 < $M/files.txt | flagged)
printf '%-22s %6s' kind total; for v in xmllint libxml2 xmloxide xerces compiled-rust compiled-js; do printf ' %13s' $v; done; echo
for k in $(ls -d $M/*/ | xargs -n1 basename); do
  printf '%-22s %6d' $k $(grep -c "/$k/" $M/files.txt)
  for v in xmllint libxml2 xmloxide xerces compiled-rust compiled-js; do
    printf ' %13d' $(grep -c "/$k/" <<< "${out[$v]}" || true)
  done
  echo
done
