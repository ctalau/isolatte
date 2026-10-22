#!/usr/bin/env bash
# fuzz_compare.sh DIR — validity of every DIR/files.txt document according to
# stock xmllint (real modular DTDs via the DITA-OT catalog: the ground truth)
# versus the compiled validators (native Rust, wasm, JS, Java). Prints the
# disagreements and a summary.
set -euo pipefail
cd "$(dirname "$0")"
D=$1
export XML_CATALOG_FILES=$PWD/work-ditaot/dita-ot-4.2.4/catalog-dita.xml
xargs -a $D/files.txt -P4 -n1 sh -c 'if xmllint --noout --valid --nonet "$0" >/dev/null 2>&1; then echo "$0 0"; else echo "$0 1"; fi' \
  | sort > $D/truth.txt
flagged() { grep '^INVALID' | cut -d' ' -f2 | sort -u; }
compiled/rust/target/release/dita-compiled-validator 4 < $D/files.txt | flagged > $D/rust.txt
node compiled/wasm-check.js compiled/rust/target/wasm32-unknown-unknown/release/dita_compiled_validator.wasm \
  < $D/files.txt | flagged > $D/wasm.txt
node compiled/js/bench.js 4 < $D/files.txt | flagged > $D/js.txt
java -cp work-java-compiled CompiledValidator 4 < $D/files.txt 2>/dev/null | flagged > $D/java.txt
total=$(wc -l < $D/truth.txt)
bad=$(awk '$2 == 1' $D/truth.txt | wc -l)
echo "documents=$total invalid_per_xmllint=$bad"
for v in rust wasm js java; do
  awk -v F=$D/$v.txt 'BEGIN { while ((getline l < F) > 0) f[l] = 1 }
       { mine = ($1 in f) ? 1 : 0; if (mine != $2) { n++; if (n <= 8) printf "  %s: %s xmllint=%s compiled=%s\n", V, $1, $2, mine } }
       END { printf "%s: %d disagreements\n", V, n + 0 }' V=$v $D/truth.txt
done
