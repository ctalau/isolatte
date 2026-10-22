#!/usr/bin/env bash
# benchmark-xerces.sh — Xerces-J 2.12.2 (from DITA-OT's lib/) with one grammar
# pool shared by all threads. PASSES whole-corpus passes per JVM (default 5):
# pass 1 is a cold JVM, later passes are JIT-warmed.
set -euo pipefail
cd "$(dirname "$0")"
L=work-ditaot/dita-ot-4.2.4/lib
CP=work-java:$L/xercesImpl-2.12.2.jar:$L/xml-apis-1.4.01.jar:$L/xml-resolver-1.2.jar
C=work-ditaot/dita-ot-4.2.4/catalog-dita.xml
P=${PASSES:-5}
x() { java -cp "$CP" XercesBench "$@" < work-files.txt 2>/dev/null | grep '^validator='; }

for t in 1 4; do
  x $t work-dtdmap.tsv flat "$C" publicid "$P"
  x $t work-dtdmap.tsv flat "$C" stock "$P"
done
x 4 work-dtdmap.tsv catalog "$C" publicid "$P"
x 4 work-dtdmap.tsv flat "$C" stock-locked 1
