#!/usr/bin/env bash
# Runs the XInclude demo, the sandbox probe and a smoke test on miniJVM with TeaVM's class library as
# its entire JRE, and checks every expected outcome. Run ./minijvm-build.sh first.
set -uo pipefail
cd "$(dirname "$0")"
mkdir -p results
HERE="$(pwd)"

# Same jail as run.sh, including the generated escapes.
rm -rf work/sample && cp -r sample work/sample
cat > work/sample/jail/escape-absolute.xml <<XML
<?xml version="1.0" encoding="UTF-8"?>
<book xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file://$HERE/work/sample/outside/secret.xml"/>
</book>
XML
ln -s ../outside/secret.xml work/sample/jail/linked-secret.xml
cat > work/sample/jail/escape-symlink.xml <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<book xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="linked-secret.xml"/>
</book>
XML
DOCS="main.xml escape-dotdot.xml escape-absolute.xml escape-symlink.xml escape-fallback.xml"

{
  echo "### miniJVM + TeaVM class library, jail root = work/sample/jail"
  start=$(date +%s%N)
  ./minijvm-run.sh --jail work/sample/jail org.isolatte.demo.XIncludeDemo --probe \
    $(for d in $DOCS; do printf 'file:///%s ' "$d"; done) 2>&1
  echo "[time] $(( ($(date +%s%N) - start) / 1000000 )) ms including VM startup"
  echo
  echo "### Sandbox probe: miniJVM, same jail"
  ./minijvm-run.sh --jail work/sample/jail org.isolatte.demo.SandboxProbe 2>&1
  echo
  echo "### Sandbox probe: stock HotSpot"
  java -cp work/demo org.isolatte.demo.SandboxProbe 2>&1
  echo
  echo "### Smoke test: miniJVM (no jail)"
  ./minijvm-run.sh org.isolatte.guest.Hello a b a 2>&1
  echo
  echo "### Smoke test: stock HotSpot"
  java -cp work/vm-guest org.isolatte.guest.Hello a b a 2>&1
} | grep -v '^Picked up JAVA_TOOL_OPTIONS\|^\[INFO\]' | sed -e "s#$HERE#<experiment>#g" \
    -e 's#^\(System.getenv("PATH") *ALLOWED  \)/.*#\1<host PATH>#' > results/minijvm-run.txt

# miniJVM prints a "method not exist" line when it links a reference to a class TeaVM lacks (e.g.
# Xerces' serialization hooks naming ObjectInputStream); they stay in the log but not in the checks.
section() { sed -n "/^### $1/,/^### /p" results/minijvm-run.txt | grep -v '^method not exist'; }
demo=$(section "miniJVM + TeaVM")
vmprobe=$(section "Sandbox probe: miniJVM")
jvmprobe=$(section "Sandbox probe: stock HotSpot")
vmhello=$(section "Smoke test: miniJVM")
fails=0
exec > >(tee results/minijvm-verification.txt)

# expect <text> <description> <anchor> <result>: <result> occurs within two lines after <anchor>.
expect() {
  local text="$1" what="$2" anchor="$3" result="$4"
  if printf '%s\n' "$text" | grep -A2 -F -- "$anchor" | grep -q -F -- "$result"; then
    echo "PASS  $what"
  else
    echo "FAIL  $what (expected '$result' after '$anchor')"
    fails=$((fails + 1))
  fi
}

expect "$demo" "java.io.File is TeaVM's class" "== java.io probe" "File.class source: TFile.java"
expect "$demo" "\"/\" lists the jail folder" "new File(\"/\").list()" "chapters escape-absolute.xml"
expect "$demo" "\"..\" cannot climb above the jail root" "getCanonicalPath()" 'getCanonicalPath(): /'
expect "$demo" "file inside the jail is readable" "read /main.xml" "read /main.xml: 230 bytes"
expect "$demo" "/etc/passwd is not visible" "read /etc/passwd" "read /etc/passwd: FileNotFoundException"
expect "$demo" "NIO is TeaVM's, on the same jail" "NIO Files.isReadable" "isReadable(/etc/passwd): false"
expect "$demo" "no ProcessBuilder in the class library" "ProcessBuilder:" "NoClassDefFoundError: java/lang/ProcessBuilder"
expect "$demo" "XInclude inside the jail (XML + text)" "== file:///main.xml" \
  '<chapter id="c1">Café — included from chapters/chapter1.xml</chapter>plain text included from chapters/notes.txt'
for doc in escape-dotdot escape-absolute escape-symlink; do
  expect "$demo" "XInclude escape via $doc fails" "== file:///$doc.xml" \
    "FAILED org.xml.sax.SAXParseException: An 'include' failed, and no 'fallback' element was found."
done
expect "$demo" "blocked XInclude uses xi:fallback" "== file:///escape-fallback.xml" \
  "OK <book xmlns:xi=\"http://www.w3.org/2001/XInclude\"><blocked></blocked></book>"
if printf '%s\n' "$demo" | grep -q '^\[native\] not bound'; then
  echo "FAIL  the demo needed a native that is missing or not allowlisted"; fails=$((fails + 1))
else
  echo "PASS  the demo needed no missing or blocked native"
fi

for probe in "java.io read /etc/passwd" "java.io write /tmp/isolatte-probe" "NIO read /etc/passwd" \
    "ProcessBuilder(\"true\")" "Runtime.exec(\"true\")" "Socket connect 127.0.0.1:9" "URL http://127.0.0.1:9/" \
    "System.loadLibrary(\"z\")" "Class.forName(\"sun.misc.Unsafe\")" "miniJVM file native via own class"; do
  expect "$vmprobe" "miniJVM blocks: $probe" "$probe" "blocked"
done
expect "$vmprobe" "NIO \"/\" is the jail (7 entries)" "NIO list /" "ALLOWED  7 entries"
expect "$vmprobe" "no host environment" "System.getenv" "ALLOWED  null"
expect "$vmprobe" "class path resources cannot climb out" "class path resource" "ALLOWED  null"
expect "$vmprobe" "native allowlist refuses miniJVM's own file native" "[native] not bound: org/mini/fs" "InnerFile.openFile"
for probe in "java.io read /etc/passwd" "NIO read /etc/passwd" "ProcessBuilder(\"true\")" "System.loadLibrary(\"z\")"; do
  expect "$jvmprobe" "control: stock HotSpot allows $probe" "$probe" "ALLOWED"
done
expect "$vmhello" "smoke test: lambdas, collections, Unicode case mapping" "args" "args [A, B, A] counts {A=2, B=1}"
expect "$vmhello" "smoke test: String.format via TeaVM's CLDR data" "00042" "00042|fmt|2.500"
expect "$vmhello" "smoke test: guest stack traces from miniJVM frames" "caught ArrayIndexOutOfBoundsException" "Hello.java:28"

echo "$fails failure(s)"
[ "$fails" -eq 0 ]
