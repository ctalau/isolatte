#!/usr/bin/env bash
# TeaVM -> C -> native binary (target/xi). Needs JDK 21, Maven 3.9+, gcc.
set -euo pipefail
cd "$(dirname "$0")"
mvn -B -q clean package
(cd target/c && gcc -O2 -o ../xi all.c -lm -lrt -lpthread)
ls -l target/xi
