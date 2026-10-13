#!/usr/bin/env bash
# Runs a guest main class on miniJVM with TeaVM's class library as its entire JRE.
# Usage: ./minijvm-run.sh [--jail DIR] MainClass args...   (run ./minijvm-build.sh first)
# Without --jail the guest's file system is empty.
set -euo pipefail
cd "$(dirname "$0")"
if [[ ${1:-} == --jail ]]; then
  export ISOLATTE_JAIL="$(cd "$2" && pwd)" # miniJVM changes directory at startup: absolute paths only
  shift 2
else
  unset ISOLATTE_JAIL
fi
BOOT="$(pwd)/work/minijvm/boot.jar"
exec work/minijvm/mini_jvm -bootclasspath "$BOOT" -cp "$BOOT" org.isolatte.guest.Boot "$@"
