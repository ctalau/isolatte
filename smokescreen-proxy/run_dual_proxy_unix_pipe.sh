#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACL_FILE="$SCRIPT_DIR/acl.yaml"
SMOKESCREEN_LOG="$SCRIPT_DIR/smokescreen-dual.log"
A_LOG="$SCRIPT_DIR/proxy-a.log"
B_LOG="$SCRIPT_DIR/proxy-b.log"
SMOKESCREEN_BIN="$SCRIPT_DIR/.smokescreen-proxy-local"

SMOKESCREEN_PORT="4750"
PROXY_A_PORT="18080"
UNIX_SOCKET="/tmp/proxy_ab.sock"

SMOKESCREEN_PID=""
PROXY_A_PID=""
PROXY_B_PID=""

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"; }
pass() { echo -e "  ${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; }

cleanup() {
  log "Cleaning up..."
  [[ -n "$PROXY_A_PID" ]] && kill "$PROXY_A_PID" 2>/dev/null || true
  [[ -n "$PROXY_B_PID" ]] && kill "$PROXY_B_PID" 2>/dev/null || true
  [[ -n "$SMOKESCREEN_PID" ]] && kill "$SMOKESCREEN_PID" 2>/dev/null || true
  rm -f "$UNIX_SOCKET" "$SMOKESCREEN_BIN"
}
trap cleanup EXIT

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing command: $1"; exit 1; }
}

require_cmd curl
require_cmd socat
require_cmd go

rm -f "$UNIX_SOCKET" "$SMOKESCREEN_LOG" "$A_LOG" "$B_LOG"

log "Building smokescreen wrapper binary"
(
  cd "$SCRIPT_DIR"
  go build -o "$SMOKESCREEN_BIN" ./main.go
)

log "Starting Proxy B backend (smokescreen) on 127.0.0.1:${SMOKESCREEN_PORT}"
"$SMOKESCREEN_BIN" \
  --listen-ip 127.0.0.1 \
  --listen-port "$SMOKESCREEN_PORT" \
  --egress-acl-file "$ACL_FILE" \
  --unsafe-allow-private-ranges \
  >"$SMOKESCREEN_LOG" 2>&1 &
SMOKESCREEN_PID=$!

for _ in $(seq 1 30); do
  if (echo > /dev/tcp/127.0.0.1/"$SMOKESCREEN_PORT") >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

if (echo > /dev/tcp/127.0.0.1/"$SMOKESCREEN_PORT") >/dev/null 2>&1; then
  pass "Smokescreen is accepting connections"
else
  fail "Smokescreen failed to open port ${SMOKESCREEN_PORT}"
  tail -n 50 "$SMOKESCREEN_LOG" || true
  exit 1
fi

log "Starting Proxy B edge: UNIX socket -> smokescreen TCP"
socat UNIX-LISTEN:"$UNIX_SOCKET",fork,reuseaddr TCP:127.0.0.1:"$SMOKESCREEN_PORT" >"$B_LOG" 2>&1 &
PROXY_B_PID=$!
sleep 0.5
[[ -S "$UNIX_SOCKET" ]] && pass "Proxy B UNIX socket ready" || { fail "Proxy B socket missing"; exit 1; }

log "Starting Proxy A: TCP listener -> UNIX socket"
socat TCP-LISTEN:"$PROXY_A_PORT",fork,reuseaddr UNIX-CONNECT:"$UNIX_SOCKET" >"$A_LOG" 2>&1 &
PROXY_A_PID=$!
sleep 0.5
kill -0 "$PROXY_A_PID" 2>/dev/null && pass "Proxy A listening on ${PROXY_A_PORT}" || { fail "Proxy A failed"; exit 1; }

echo ""
log "Running curl tests through Proxy A"

set +e
ALLOWED_OUTPUT=$(curl -sS -x "http://127.0.0.1:${PROXY_A_PORT}" https://example.com -m 20 2>&1)
ALLOWED_RC=$?
BLOCKED_OUTPUT=$(curl -sS -x "http://127.0.0.1:${PROXY_A_PORT}" https://google.com -m 20 2>&1)
BLOCKED_RC=$?
set -e

if [[ $ALLOWED_RC -eq 0 ]] && echo "$ALLOWED_OUTPUT" | grep -qi "example domain"; then
  pass "ALLOWED: example.com works through A -> unix -> B"
  T1="PASS"
else
  fail "ALLOWED request failed (rc=$ALLOWED_RC)"
  echo "$ALLOWED_OUTPUT" | head -n 10
  T1="FAIL"
fi

if [[ $BLOCKED_RC -ne 0 ]] && echo "$BLOCKED_OUTPUT" | grep -Eqi "denied|blocked|forbidden|proxy|abort|refused|407"; then
  pass "BLOCKED: google.com denied by smokescreen ACL"
  T2="PASS"
else
  fail "BLOCKED request was not denied as expected (rc=$BLOCKED_RC)"
  echo "$BLOCKED_OUTPUT" | head -n 10
  T2="FAIL"
fi

echo ""
echo "Results:"
echo "  example.com via Proxy A: $T1"
echo "  google.com via Proxy A:  $T2"

if [[ "$T1" != "PASS" || "$T2" != "PASS" ]]; then
  echo "--- smokescreen log tail ---"
  tail -n 30 "$SMOKESCREEN_LOG" || true
  exit 1
fi

pass "Dual-proxy unix-pipe system validated"
