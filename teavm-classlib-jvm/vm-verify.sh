#!/usr/bin/env bash
# Runs the XInclude demo, the sandbox probe and a smoke test on the interpreter with TeaVM's class
# library as the whole JRE, and checks every expected outcome. Run ./vm-build.sh first.
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
  echo "### Interpreter + TeaVM class library, jail root = work/sample/jail"
  VM_STATS=1 ./vm-run.sh --jail work/sample/jail --cp work/demo org.isolatte.demo.XIncludeDemo --probe \
    $(for d in $DOCS; do printf 'file:///%s ' "$d"; done) 2>&1
  echo
  echo "### Sandbox probe: interpreter, same jail"
  ./vm-run.sh --jail work/sample/jail --cp work/demo org.isolatte.demo.SandboxProbe 2>&1
  echo
  echo "### Sandbox probe: stock HotSpot"
  java -cp work/demo org.isolatte.demo.SandboxProbe 2>&1
  echo
  echo "### Smoke test: interpreter (no jail)"
  ./vm-run.sh org.isolatte.guest.Hello a b a 2>&1
  echo
  echo "### Smoke test: stock HotSpot"
  java -cp work/vm-guest org.isolatte.guest.Hello a b a 2>&1
} | grep -v '^Picked up JAVA_TOOL_OPTIONS' | sed -e "s#$HERE#<experiment>#g" \
    -e 's#^\(System.getenv("PATH") *ALLOWED  \)/.*#\1<host PATH>#' > results/vm-run.txt

section() { sed -n "/^### $1/,/^### /p" results/vm-run.txt; }
demo=$(section "Interpreter")
vmprobe=$(section "Sandbox probe: interpreter")
jvmprobe=$(section "Sandbox probe: stock HotSpot")
vmhello=$(section "Smoke test: interpreter")
fails=0
exec > >(tee results/vm-verification.txt)

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
expect "$demo" "no ProcessBuilder in the class library" "ProcessBuilder" "NoClassDefFoundError: java.lang.ProcessBuilder"
expect "$demo" "XInclude inside the jail (XML + text)" "== file:///main.xml" \
  '<chapter id="c1">Café — included from chapters/chapter1.xml</chapter>plain text included from chapters/notes.txt'
for doc in escape-dotdot escape-absolute escape-symlink; do
  expect "$demo" "XInclude escape via $doc fails" "== file:///$doc.xml" \
    "FAILED org.xml.sax.SAXParseException: An 'include' failed, and no 'fallback' element was found."
done
expect "$demo" "blocked XInclude uses xi:fallback" "== file:///escape-fallback.xml" \
  "OK <book xmlns:xi=\"http://www.w3.org/2001/XInclude\"><blocked></blocked></book>"
expect "$demo" "only the probed ProcessBuilder was missing (no native, no class Xerces needs)" "[vm] missing:" "[vm] missing: [java/lang/ProcessBuilder]"

for probe in "java.io read /etc/passwd" "java.io write /tmp/isolatte-probe" "NIO read /etc/passwd" \
    "ProcessBuilder(\"true\")" "Runtime.exec(\"true\")" "Socket connect 127.0.0.1:9" "URL http://127.0.0.1:9/" \
    "System.loadLibrary(\"z\")" "Class.forName(\"sun.misc.Unsafe\")"; do
  expect "$vmprobe" "interpreter blocks: $probe" "$probe" "blocked"
done
expect "$vmprobe" "NIO \"/\" is the jail (7 entries)" "NIO list /" "ALLOWED  7 entries"
expect "$vmprobe" "no host environment" "System.getenv" "ALLOWED  null"
expect "$vmprobe" "class path resources cannot climb out" "class path resource" "ALLOWED  null"
for probe in "java.io read /etc/passwd" "NIO read /etc/passwd" "ProcessBuilder(\"true\")" "System.loadLibrary(\"z\")"; do
  expect "$jvmprobe" "control: stock HotSpot allows $probe" "$probe" "ALLOWED"
done
expect "$vmhello" "smoke test: lambdas, collections, Unicode case mapping" "args" "args [A, B, A] counts {A=2, B=1}"
expect "$vmhello" "smoke test: String.format via TeaVM's CLDR data" "00042" "00042|fmt|2.500"
expect "$vmhello" "smoke test: guest stack traces" "caught ArrayIndexOutOfBoundsException" "Hello.java:28"

echo "$fails failure(s)"
[ "$fails" -eq 0 ]
