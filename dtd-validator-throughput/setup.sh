#!/usr/bin/env bash
# setup.sh — fetch the corpus + DITA DTDs, flatten the DTDs, build the validators.
set -euo pipefail
cd "$(dirname "$0")"

[ -d work-userguide ] || git clone -q --depth 1 https://github.com/oxygenxml/userguide.git work-userguide
if [ ! -d work-ditaot/dita-ot-4.2.4 ]; then
  mkdir -p work-ditaot
  curl -sSL -o work-ditaot/dita-ot.zip https://github.com/dita-ot/dita-ot/releases/download/4.2.4/dita-ot-4.2.4.zip
  (cd work-ditaot && unzip -q dita-ot.zip)
fi
export XML_CATALOG_FILES=$PWD/work-ditaot/dita-ot-4.2.4/catalog-dita.xml
find work-userguide -name '*.dita' | sort > work-files.txt

command -v xml2-config >/dev/null || apt-get install -y -q libxml2-dev
gcc -O2 -Wall -o work-flatten_dtd c/flatten_dtd.c $(xml2-config --cflags --libs)
gcc -O2 -Wall -pthread -o work-libxml2_cached c/libxml2_cached.c $(xml2-config --cflags --libs)

# One flattened DTD per DOCTYPE public id used by the corpus.
mkdir -p work-flat
: > work-dtdmap.tsv
for p in "DITA Topic:topic.dtd" "DITA Concept:concept.dtd" "DITA Task:task.dtd" \
         "DITA Reference:reference.dtd" "DITA Glossary:glossary.dtd" \
         "DITA Troubleshooting:troubleshooting.dtd" "DITA 1.3 Troubleshooting:troubleshooting.dtd" \
         "LIGHTWEIGHT DITA Topic:topic.dtd"; do
  name=${p%%:*}; out=$PWD/work-flat/$(echo "$name" | tr ' .' '__').dtd
  ./work-flatten_dtd "-//OASIS//DTD $name//EN" "${p##*:}" > "$out"
  printf -- '-//OASIS//DTD %s//EN\t%s\n' "$name" "$out" >> work-dtdmap.tsv
done

# xmloxide 0.5.0 + the prefixed-attribute fix (see patches/).
(cd rust-bench && cargo fetch -q)
src=$(ls -d ~/.cargo/registry/src/*/xmloxide-0.5.0 | head -1)
rm -rf work-xmloxide-patched && cp -r "$src" work-xmloxide-patched
patch -s -d work-xmloxide-patched -p1 < patches/xmloxide-0.5.0-prefixed-attr-names.patch
(cd rust-bench && cargo build --release -q)

# Xerces-J harness, built against the jars DITA-OT ships.
L=work-ditaot/dita-ot-4.2.4/lib
mkdir -p work-java
javac -cp "$L/xercesImpl-2.12.2.jar:$L/xml-apis-1.4.01.jar:$L/xml-resolver-1.2.jar" -d work-java java/XercesBench.java

# Validators compiled from the flattened DTDs.
mkdir -p work-gen
python3 -I compiled/gen.py work-dtdmap.tsv work-gen/generated.rs work-gen/generated.js
(cd compiled/rust && cargo build --release -q)
(cd compiled/js && npm ci -q)

python3 -I make_mutants.py work-files.txt work-mutants 50
python3 -I make_mutants2.py work-files.txt work-mutants2 30
