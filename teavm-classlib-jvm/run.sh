#!/usr/bin/env bash
# Runs the Xerces XInclude demo on HotSpot with TeaVM's java.io, jailed to work/sample/jail, and the
# same demo on stock OpenJDK as a control. Run ./build.sh first.
set -euo pipefail
cd "$(dirname "$0")"
M2="${M2_REPO:-$HOME/.m2/repository}"
XERCES="$M2/xerces/xercesImpl/2.12.2/xercesImpl-2.12.2.jar"
HERE="$(pwd)"

rm -rf work/sample && cp -r sample work/sample
# Escapes that need the checkout's absolute path or a symlink are generated here.
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

echo "### HotSpot + TeaVM java.io, jail root = work/sample/jail"
# Xerces and the demo go on the boot class path: HotSpot reads it natively, whereas the application
# class path is opened by Java code through java.io.File, which now only sees the jail.
# -Xshare:off: the CDS archive was dumped for OpenJDK's own java.base classes.
java -Xshare:off \
  --patch-module java.base=work/overlay/java.base \
  -Xbootclasspath/a:"$XERCES":work/bundles:work/demo \
  -Dstdout.encoding=UTF-8 \
  -Djdk.internal.io.vfs.root=work/sample/jail \
  org.isolatte.demo.XIncludeDemo --probe $(for d in $DOCS; do printf 'file:///%s ' "$d"; done)

echo
echo "### Control: stock OpenJDK java.io, same files by host path"
java -Dstdout.encoding=UTF-8 -cp "$XERCES":work/demo org.isolatte.demo.XIncludeDemo \
  $(for d in $DOCS; do printf 'file://%s/work/sample/jail/%s ' "$HERE" "$d"; done)
