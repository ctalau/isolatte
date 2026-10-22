#!/usr/bin/env bash
# learningdita_compare.sh — correctness of the compiled validators against
# plain Xerces-J (no grammar pool, so DTD-declared entities are known) and
# stock xmllint on every .dita/.ditamap file of ScriptoriumDev/LearningDITA.
# All three references resolve DTDs through work-catalog-all.xml (the DITA-OT
# catalog plus the aliases from all_shells.py). Prints per-file disagreements.
set -euo pipefail
cd "$(dirname "$0")"
export LC_ALL=C.UTF-8   # the corpus has non-ASCII file names; the JVM needs this to open them
[ -d work-learningdita ] || git clone -q --depth 1 https://github.com/ScriptoriumDev/LearningDITA.git work-learningdita
find "$PWD/work-learningdita" \( -name '*.dita' -o -name '*.ditamap' \) | sort > work-learningdita-files.txt
L=work-ditaot/dita-ot-4.2.4/lib
CP="$L/xercesImpl-2.12.2.jar:$L/xml-apis-1.4.01.jar:$L/xml-resolver-1.2.jar"
flagged() { grep '^INVALID' | sed -E 's/  .*$//; s/^INVALID (.*) [0-9]+$/\1/' | sort; }
counts() { grep '^INVALID' | sed -E 's/^INVALID //' | sort; }

VERBOSE=1 java -Dsun.jnu.encoding=UTF-8 -cp work-java:$CP XercesCheck 4 work-catalog-all.xml \
  < work-learningdita-files.txt 2>/dev/null > work-ld-xerces.txt
VERBOSE=1 compiled/rust/target/release/dita-compiled-validator 4 < work-learningdita-files.txt > work-ld-rust.txt
node compiled/wasm-check.js compiled/rust/target/wasm32-unknown-unknown/release/dita_compiled_validator.wasm \
  < work-learningdita-files.txt > work-ld-wasm.txt
node compiled/js/bench.js 4 1 < work-learningdita-files.txt > work-ld-js.txt
java -Dsun.jnu.encoding=UTF-8 -cp work-java-compiled CompiledValidator 4 1 < work-learningdita-files.txt \
  2>/dev/null > work-ld-java.txt
XML_CATALOG_FILES=$PWD/work-catalog-all.xml xargs -d '\n' -a work-learningdita-files.txt -P4 -n1 \
  sh -c 'xmllint --noout --valid --nonet "$0" >/dev/null 2>&1 || echo "INVALID $0 1"' > work-ld-xmllint.txt

echo "files=$(wc -l < work-learningdita-files.txt)"
flagged < work-ld-xerces.txt > work-ld-xerces.flag
for v in xerces rust wasm js java xmllint; do
  flagged < work-ld-$v.txt > work-ld-$v.flag
  printf '%-8s invalid=%-4s disagreements_vs_xerces=%s\n' $v "$(wc -l < work-ld-$v.flag)" \
    "$(comm -3 work-ld-xerces.flag work-ld-$v.flag | wc -l)"
  comm -3 work-ld-xerces.flag work-ld-$v.flag | head -5 | sed 's/^/  /'
done
# Same number of errors per invalid file (Xerces and the compiled Rust validator
# both keep going after a validity error).
echo "rust_vs_xerces_error_count_mismatches=$(comm -3 <(counts < work-ld-xerces.txt) <(counts < work-ld-rust.txt) | wc -l)"
