#!/usr/bin/env bash
# Runs ./run.sh and checks every expected outcome. Exits 1 on any mismatch. Run ./build.sh first.
set -uo pipefail
cd "$(dirname "$0")"
mkdir -p results
./run.sh 2>&1 | grep -v '^Picked up JAVA_TOOL_OPTIONS' | sed "s#$(pwd)#<experiment>#g" > results/run.txt
jailed=$(sed -n '/^### HotSpot/,/^### Control/p' results/run.txt)
control=$(sed -n '/^### Control/,$p' results/run.txt)
fails=0
exec > >(tee results/verification.txt)

# expect <section text> <description> <pattern...>: each pattern must occur, in order, on one line
# following the "== <doc>" header given as the first pattern.
expect() {
  local text="$1" what="$2" doc="$3" result="$4"
  if printf '%s\n' "$text" | grep -A2 -F -- "$doc" | grep -q -F -- "$result"; then
    echo "PASS  $what"
  else
    echo "FAIL  $what (expected '$result' after '$doc')"
    fails=$((fails + 1))
  fi
}

expect "$jailed" "java.io.File is TeaVM's class" "== java.io probe" "File.class source: TFile.java"
expect "$jailed" "\"/\" lists the jail folder" "new File(\"/\").list()" "chapters escape-absolute.xml"
expect "$jailed" "\"..\" cannot climb above the jail root" "getCanonicalPath()" 'getCanonicalPath(): /'
expect "$jailed" "file inside the jail is readable" "read /main.xml" "read /main.xml: 230 bytes"
expect "$jailed" "/etc/passwd is not visible" "read /etc/passwd" "read /etc/passwd: FileNotFoundException"
expect "$jailed" "File.toPath() refuses to map to host NIO" "File.toPath()" "UnsupportedOperationException"
# Known gaps, asserted so a change in behaviour is noticed: these are outside java.io.
expect "$jailed" "known gap: OpenJDK NIO is not jailed" "NIO Files.isReadable" "isReadable(/etc/passwd): true"
expect "$jailed" "known gap: processes can be started" "ProcessBuilder" 'ProcessBuilder("true") exit: 0'
expect "$jailed" "XInclude inside the jail (XML + text)" "== file:///main.xml" \
  '<chapter id="c1">Café — included from chapters/chapter1.xml</chapter>plain text included from chapters/notes.txt'
for doc in escape-dotdot escape-absolute escape-symlink; do
  expect "$jailed" "XInclude escape via $doc fails" "== file:///$doc.xml" \
    "FAILED org.xml.sax.SAXParseException: An 'include' failed, and no 'fallback' element was found."
  expect "$control" "control: $doc reaches the outside file on stock OpenJDK" "$doc.xml" "<secret>outside the jail</secret>"
done
expect "$jailed" "blocked XInclude uses xi:fallback" "== file:///escape-fallback.xml" "OK <book xmlns:xi=\"http://www.w3.org/2001/XInclude\"><blocked></blocked></book>"
expect "$control" "control: main.xml identical on stock OpenJDK" "main.xml" \
  '<chapter id="c1">Café — included from chapters/chapter1.xml</chapter>plain text included from chapters/notes.txt'

echo "$fails failure(s)"
[ "$fails" -eq 0 ]
