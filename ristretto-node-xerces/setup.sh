#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p vendor
ristretto_revision=dcd45fb452d6956122a9985096260310a22b4d44
if ! test -d vendor/ristretto/.git; then
  git clone https://github.com/theseus-rs/ristretto.git vendor/ristretto
  git -C vendor/ristretto checkout --detach "$ristretto_revision"
fi
if test "$(git -C vendor/ristretto rev-parse HEAD)" != "$ristretto_revision"; then
  printf '%s\n' 'vendor/ristretto is not at the pinned revision; use a fresh checkout.' >&2
  exit 1
fi
download() {
  local url="$1" destination="$2" expected="$3"
  if ! test -f "$destination"; then
    curl --fail --location --silent --show-error "$url" -o "$destination"
  fi
  printf '%s  %s\n' "$expected" "$destination" | sha256sum --check
}
download 'https://corretto.aws/downloads/resources/21.0.12.12.1/amazon-corretto-21.0.12.12.1-linux-x64.tar.gz' \
  vendor/jdk21.tar.gz '8785082c2fb999c024c8821e4a7c5391bda28f1667cceadafd78e2965b7669d2'
download 'https://repo.maven.apache.org/maven2/xerces/xercesImpl/2.12.2/xercesImpl-2.12.2.jar' \
  vendor/xercesImpl-2.12.2.jar '6fc991829af1708d15aea50c66f0beadcd2cfeb6968e0b2f55c1b0909883fe16'
download 'https://repo.maven.apache.org/maven2/xml-apis/xml-apis/1.4.01/xml-apis-1.4.01.jar' \
  vendor/xml-apis-1.4.01.jar 'a840968176645684bb01aed376e067ab39614885f9eee44abe35a5f20ebe7fad'
download 'https://repo.maven.apache.org/maven2/net/sf/saxon/Saxon-HE/10.9/Saxon-HE-10.9.jar' \
  vendor/Saxon-HE-10.9.jar '491d8edf4ec811d15c2b2417b007218b9b938f15e4dfbad004025beb4e70e960'
if ! test -x vendor/jdk21/bin/javac; then
  mkdir -p vendor/jdk21
  tar -xzf vendor/jdk21.tar.gz --strip-components=1 -C vendor/jdk21
fi
if ! test -f vendor/runtime/lib/modules; then
  vendor/jdk21/bin/jlink --add-modules java.base,java.xml --endian little \
    --disable-plugin compress --strip-debug --no-header-files --no-man-pages \
    --output vendor/runtime
fi
npm ci --no-audit --no-fund
