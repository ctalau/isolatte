#!/usr/bin/env bash
# Asserts the jail: XInclude inside the folder works, every way out fails, and strace shows the
# native binary never opens a user-space path outside the folder. Writes nothing but stdout.
set -uo pipefail
cd "$(dirname "$0")"
XI=$PWD/target/xi
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/outside"
cp -r sample/jail "$T/jail"
echo '<secret>SECRET-OUTSIDE-JAIL</secret>' > "$T/outside/secret.xml"
echo 'SECRET-OUTSIDE-JAIL' > "$T/outside/secret.txt"
J=$T/jail
inc() { printf '<?xml version="1.0"?>\n<book xmlns:xi="http://www.w3.org/2001/XInclude">%s</book>\n' "$2" > "$J/$1.xml"; }
inc escape-abs-xml  "<xi:include href=\"file://$T/outside/secret.xml\"/>"
inc escape-abs-text "<xi:include href=\"file://$T/outside/secret.txt\" parse=\"text\"/>"
inc escape-dotdot-text '<xi:include href="../outside/secret.txt" parse="text"/>'
inc escape-etc      '<xi:include href="file:///etc/passwd" parse="text"/>'
inc escape-symlink  '<xi:include href="out/secret.xml"/>'
inc escape-symlink-file '<xi:include href="secret-link.xml"/>'
inc escape-http     '<xi:include href="http://127.0.0.1:9/x.xml"/>'
inc inside-dotdot   '<xi:include href="chapters/../chapters/chapter1.xml"/>'
ln -s "$T/outside" "$J/out"                       # directory symlink pointing out
ln -s "$T/outside/secret.xml" "$J/secret-link.xml" # file symlink pointing out
pass=0; fail=0
check() { if [ "$2" = ok ]; then pass=$((pass+1)); echo "PASS $1"; else fail=$((fail+1)); echo "FAIL $1"; fi; }

echo "### jailed run (root=$J)"
OUT=$("$XI" --probe "$J" file:///main.xml file:///inside-dotdot.xml file:///escape-dotdot.xml file:///escape-dotdot-text.xml \
  file:///escape-abs-xml.xml file:///escape-abs-text.xml file:///escape-etc.xml file:///escape-symlink.xml \
  file:///escape-symlink-file.xml file:///escape-http.xml file:///escape-fallback.xml file:///../outside/secret.xml 2>&1)
echo "$OUT"
section() { echo "$OUT" | awk -v h="== $1" '$0==h{f=1;next} /^== /{f=0} f'; }
section file:///main.xml | grep -q 'OK <book.*Inside the jail.*Caf.u00e9.*included from chapters/chapter1.xml.*plain text included from chapters/notes.txt' && check "XML + text XInclude inside folder" ok || check "XML + text XInclude inside folder" no
section file:///inside-dotdot.xml | grep -q 'OK <book.*c1' && check "inside folder via chapters/../" ok || check "inside folder via chapters/../" no
for c in escape-dotdot escape-dotdot-text escape-abs-xml escape-abs-text escape-etc escape-symlink escape-symlink-file escape-http; do
  section "file:///$c.xml" | grep -q 'FAILED org.xml.sax.SAXParseException' && check "blocked: $c" ok || check "blocked: $c" no
done
section file:///escape-fallback.xml | grep -q 'OK <book.*<blocked>' && check "xi:fallback honoured for blocked include" ok || check "xi:fallback honoured for blocked include" no
section 'file:///../outside/secret.xml' | grep -q 'FAILED' && check "direct parse of file:///../outside/secret.xml fails" ok || check "direct parse of file:///../outside/secret.xml fails" no
echo "$OUT" | grep -q 'read /etc/passwd: FileNotFoundException' && check "java.io: /etc/passwd not readable" ok || check "java.io: /etc/passwd not readable" no
echo "$OUT" | grep -q 'read /../etc/passwd: FileNotFoundException' && check "java.io: /../etc/passwd not readable" ok || check "java.io: /../etc/passwd not readable" no
echo "$OUT" | grep -q 'SECRET-OUTSIDE-JAIL\|outside the jail<' && check "NO secret leaked" no || check "NO secret leaked" ok

echo; echo "### control: --no-jail (same binary, same includes, host paths)"
C=$("$XI" --no-jail / "file://$J/escape-abs-xml.xml" "file://$J/escape-abs-text.xml" "file://$J/escape-dotdot-text.xml" "file://$J/escape-symlink.xml" 2>&1)
echo "$C"
[ "$(echo "$C" | grep -c 'OK <book.*SECRET-OUTSIDE-JAIL\|OK <book.*secret')" -eq 4 ] && check "control: all 4 escapes succeed without the jail" ok || check "control: all 4 escapes succeed without the jail" no

echo; echo "### strace: every path the jailed binary touches"
strace -f -e trace=openat,open,stat,newfstatat,lstat,access,readlink,readlinkat,statx,getdents64,execve -o "$T/strace.txt" \
  "$XI" "$J" file:///main.xml file:///escape-abs-xml.xml file:///escape-etc.xml file:///escape-symlink.xml file:///escape-dotdot.xml >/dev/null 2>&1
grep -oE '(openat\([^"]*|open\(|stat\(|lstat\(|access\(|readlink\(|readlinkat\([^"]*|statx\([^"]*|newfstatat\([^"]*)"[^"]*"' "$T/strace.txt" | sed -E 's/^[^"]*"//; s/"$//' | sort | uniq -c | sort -rn > "$T/paths.txt"
cat "$T/paths.txt"
# allowed: the jail folder itself, and the dynamic loader's own startup files (before main)
BAD=$(awk '{print $2}' "$T/paths.txt" | grep -v "^$J" | grep -v '^/lib\|^/usr/lib\|^/etc/ld.so.cache\|^/etc/ld.so.preload\|^/proc/self/\|^/sys/devices/system/cpu\|^\.$\|^/$')
if [ -z "$BAD" ]; then check "strace: no path outside jail (excluding ld.so/libc startup)" ok; else echo "unexpected: $BAD"; check "strace: no path outside jail" no; fi
echo "$BAD" | grep -q 'passwd\|outside' && check "strace: /etc/passwd and outside/ never touched" no || check "strace: /etc/passwd and outside/ never touched" ok

echo; echo "passed: $pass, failed: $fail"
[ "$fail" -eq 0 ]
