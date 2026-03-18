#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
# Docker Sandbox Proxy — Full test runner
#
# Builds the proxy image, brings up both containers, runs the
# escape test suite and the Maven/Guava download test, then tears
# everything down.
#
# Usage:
#   ./run_tests.sh              # default
#   MOUNT_DIR=/some/path ./run_tests.sh   # override mount point
# ──────────────────────────────────────────────────────────────────
set -euo pipefail

cd "$(dirname "$0")"

export MOUNT_DIR="${MOUNT_DIR:-$(pwd)}"
PROJECT="sandbox-proxy-test"

# Auto-detect host upstream proxy and pass it to Smokescreen.
if [ -z "${UPSTREAM_PROXY_URL:-}" ] && [ -n "${HTTPS_PROXY:-}" ]; then
  export UPSTREAM_PROXY_URL="$HTTPS_PROXY"
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { printf "${CYAN}▸ %s${NC}\n" "$*"; }
ok()    { printf "${GREEN}✓ %s${NC}\n" "$*"; }
fail()  { printf "${RED}✗ %s${NC}\n" "$*"; }

cleanup() {
  info "Tearing down containers …"
  docker compose -p "$PROJECT" down --volumes --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

# ── Build Smokescreen proxy binary on host ────────────────────────
if [ ! -f smokescreen-proxy ]; then
  info "Building Smokescreen proxy binary …"
  SMOKESCREEN_SRC=$(mktemp -d)
  git clone --depth 1 https://github.com/stripe/smokescreen.git "$SMOKESCREEN_SRC"
  cp main.go "$SMOKESCREEN_SRC/main.go"
  (cd "$SMOKESCREEN_SRC" && CGO_ENABLED=0 go build -mod=vendor -o "$OLDPWD/smokescreen-proxy" .)
  rm -rf "$SMOKESCREEN_SRC"
fi

# ── Copy host CA certificates for the proxy image ─────────────────
if [ ! -f ca-certificates.crt ]; then
  cp /etc/ssl/certs/ca-certificates.crt ca-certificates.crt
fi

# ── Build & start ─────────────────────────────────────────────────
info "Building proxy image …"
docker compose -p "$PROJECT" build --quiet

info "Starting containers …"
docker compose -p "$PROJECT" up -d

info "Waiting for proxy to become ready …"
for i in $(seq 1 30); do
  if docker compose -p "$PROJECT" exec -T sandbox \
       curl --proxy http://proxy:4750 --max-time 3 -s -o /dev/null https://repo1.maven.org/maven2/ 2>/dev/null; then
    ok "Proxy is ready (attempt $i)"
    break
  fi
  [ "$i" -eq 30 ] && { fail "Proxy did not become ready in time"; exit 1; }
  sleep 2
done

# ── Install test prereqs in sandbox ───────────────────────────────
info "Installing test prerequisites in sandbox …"
docker compose -p "$PROJECT" exec -T sandbox bash -c '
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends curl wget iputils-ping dnsutils iproute2 python3 ca-certificates >/dev/null 2>&1
'

# ── Run escape test suite ─────────────────────────────────────────
info "Running escape / proxy-bypass tests …"
ESCAPE_RC=0
docker compose -p "$PROJECT" exec -T sandbox bash /workspace/test_escape.sh || ESCAPE_RC=$?

echo ""

# ── Run Maven / Guava test ────────────────────────────────────────
info "Running Maven + Guava download test …"
MAVEN_RC=0
docker compose -p "$PROJECT" exec -T sandbox bash /workspace/test_maven.sh || MAVEN_RC=$?

# ── Summary ───────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════"
if [ "$ESCAPE_RC" -eq 0 ]; then
  ok "Escape tests: ALL PASSED"
else
  fail "Escape tests: SOME FAILED (rc=$ESCAPE_RC)"
fi
if [ "$MAVEN_RC" -eq 0 ]; then
  ok "Maven test:   PASSED"
else
  fail "Maven test:   FAILED (rc=$MAVEN_RC)"
fi
echo "════════════════════════════════════════════════"

exit $(( ESCAPE_RC + MAVEN_RC ))
