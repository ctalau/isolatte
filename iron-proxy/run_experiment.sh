#!/usr/bin/env bash
# =============================================================================
# Iron-Proxy Egress ACL Experiment (bwrap + Unix-socket pipe)
# =============================================================================
#
# Reimplements smokescreen-proxy/run_dual_proxy_unix_pipe.sh using iron-proxy.
#
# Architecture:
#
#   bwrap sandbox (--unshare-net — total network block, loopback only)
#   │
#   │  socat Proxy A: TCP 127.0.0.1:18080 → UNIX /run/proxy.sock
#   │  curl  -x http://127.0.0.1:18080 <url>
#   │                                        │
#   │                   (Unix socket — bypasses net namespace isolation)
#   │                                        │
#   └────────────────────────────────────────┘
#                                            │
#   socat Proxy B (host): UNIX /tmp/iron-pipe.sock → TCP 127.0.0.1:4750
#                                            │
#   iron-proxy (host, 127.0.0.1:4750)        │
#   │  allowlist: only example.com           │
#   │  TLS termination (MITM)               │
#   │  CA: /tmp/iron-proxy-ca.{crt,key}      │
#   └────────────────────────────────────────┘
#                  │
#                Internet
#
# Key insight (identical to the smokescreen version):
#   Unix domain sockets are NOT scoped to network namespaces.
#   A process inside bwrap --unshare-net can connect to a Unix socket
#   created in the host namespace as long as the socket path is visible
#   inside the sandbox (bind-mounted in).  This is the only egress channel
#   — iron-proxy is the sole gatekeeper, enforcing the domain allowlist.
#
# iron-proxy vs smokescreen in this topology:
#   smokescreen: CONNECT tunnel, no TLS termination, no CA trust needed
#   iron-proxy:  MITM proxy, terminates TLS, re-encrypts with its own CA
#                → curl inside bwrap must trust the iron-proxy CA cert
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.yaml"
LOG_FILE="$SCRIPT_DIR/iron-proxy.log"
PROXY_B_LOG="$SCRIPT_DIR/proxy-b.log"
CA_CERT="/tmp/iron-proxy-ca.crt"
CA_KEY="/tmp/iron-proxy-ca.key"
UNIX_SOCKET="/tmp/iron-pipe.sock"
INNER_SCRIPT="/tmp/bwrap-iron-test.sh"
IRON_PROXY_BIN="$SCRIPT_DIR/.iron-proxy-bin"

IRON_PORT="4750"
PROXY_A_PORT="18080"

IRON_PROXY_PID=""
PROXY_B_PID=""

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"; }
pass() { echo -e "  ${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; }

cleanup() {
    log "Cleaning up..."
    [[ -n "$PROXY_B_PID" ]] && kill "$PROXY_B_PID" 2>/dev/null || true
    [[ -n "$IRON_PROXY_PID" ]] && kill "$IRON_PROXY_PID" 2>/dev/null || true
    rm -f "$UNIX_SOCKET" "$IRON_PROXY_BIN" "$INNER_SCRIPT"
}
trap cleanup EXIT

rm -f "$UNIX_SOCKET" "$LOG_FILE" "$PROXY_B_LOG"

# =============================================
# Phase 0: Prerequisites
# =============================================
for cmd in openssl curl socat bwrap; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Missing command: $cmd"; exit 1; }
done

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  IRON_ARCH="amd64" ;;
    aarch64) IRON_ARCH="arm64" ;;
    *)       echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

# =============================================
# Phase 1: Download iron-proxy binary
# =============================================
log "Phase 1: Fetching iron-proxy binary (linux/$IRON_ARCH)..."

RELEASES_URL="https://api.github.com/repos/ironsh/iron-proxy/releases/latest"
DOWNLOAD_URL=$(curl -sS "$RELEASES_URL" \
    | grep "browser_download_url" \
    | grep "linux" \
    | grep "$IRON_ARCH" \
    | grep -v ".sha" \
    | head -1 \
    | sed 's/.*"browser_download_url": "\(.*\)"/\1/')

if [ -z "$DOWNLOAD_URL" ]; then
    fail "Could not determine iron-proxy download URL from GitHub releases"
    exit 1
fi

log "  Downloading: $DOWNLOAD_URL"
curl -sS -L -o "$IRON_PROXY_BIN" "$DOWNLOAD_URL"
chmod +x "$IRON_PROXY_BIN"
pass "iron-proxy binary downloaded"

# =============================================
# Phase 2: Generate CA certificate
# =============================================
log "Phase 2: Generating CA certificate for iron-proxy TLS interception..."

if [ ! -f "$CA_CERT" ] || [ ! -f "$CA_KEY" ]; then
    openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
        -keyout "$CA_KEY" \
        -out "$CA_CERT" \
        -subj "/CN=iron-proxy-ca/O=iron-proxy experiment" \
        -extensions v3_ca \
        -addext "basicConstraints=critical,CA:TRUE" \
        2>/dev/null
    pass "CA cert generated: $CA_CERT"
else
    pass "Reusing existing CA cert: $CA_CERT"
fi

# Runtime config pointing at the generated CA
cat > /tmp/iron-proxy-config.yaml <<EOF
dns:
  listen: ":5353"
  proxy_ip: "127.0.0.1"
  passthrough: []

proxy:
  http_listen: ":${IRON_PORT}"
  https_listen: ":4751"

tls:
  ca_cert: "${CA_CERT}"
  ca_key: "${CA_KEY}"

transforms:
  - name: allowlist
    config:
      domains:
        - "example.com"

log:
  level: info
EOF

# =============================================
# Phase 3: Start iron-proxy
# =============================================
log "Phase 3: Starting iron-proxy on 127.0.0.1:${IRON_PORT}..."

"$IRON_PROXY_BIN" --config /tmp/iron-proxy-config.yaml >"$LOG_FILE" 2>&1 &
IRON_PROXY_PID=$!

for _ in $(seq 1 30); do
    if (echo > /dev/tcp/127.0.0.1/"$IRON_PORT") >/dev/null 2>&1; then break; fi
    sleep 0.2
done

if (echo > /dev/tcp/127.0.0.1/"$IRON_PORT") >/dev/null 2>&1; then
    pass "iron-proxy accepting connections on port $IRON_PORT"
else
    fail "iron-proxy failed to start"
    tail -20 "$LOG_FILE"
    exit 1
fi

# =============================================
# Phase 4: Start Proxy B — Unix socket → iron-proxy TCP
# =============================================
log "Phase 4: Starting Proxy B (socat UNIX-LISTEN → TCP iron-proxy)..."

socat UNIX-LISTEN:"$UNIX_SOCKET",fork,reuseaddr \
    TCP:127.0.0.1:"$IRON_PORT" >"$PROXY_B_LOG" 2>&1 &
PROXY_B_PID=$!
sleep 0.5

[[ -S "$UNIX_SOCKET" ]] \
    && pass "Proxy B Unix socket ready: $UNIX_SOCKET" \
    || { fail "Proxy B socket missing"; exit 1; }

# =============================================
# Phase 5: Write inner bwrap script
# =============================================
log "Phase 5: Writing inner sandbox test script..."

# curl inside bwrap trusts the iron-proxy CA so MITM TLS succeeds.
# socat Proxy A bridges loopback TCP to the bind-mounted Unix socket,
# which is the only egress channel out of the network-isolated sandbox.
cat > "$INNER_SCRIPT" <<'INNER'
#!/bin/sh
set -eu

PROXY_A_PORT=18080
CA_CERT=/run/iron-proxy-ca.crt
PROXY_SOCK=/run/proxy.sock

# Proxy A: loopback TCP → Unix socket (iron-proxy bridge)
socat TCP-LISTEN:${PROXY_A_PORT},fork,reuseaddr \
    UNIX-CONNECT:${PROXY_SOCK} &
PROXY_A_PID=$!
sleep 0.5

PROXY_URL="http://127.0.0.1:${PROXY_A_PORT}"

echo "--- TEST 1: example.com via iron-proxy (should SUCCEED) ---"
curl -sS \
    --cacert "$CA_CERT" \
    -x "$PROXY_URL" \
    https://example.com \
    -m 20 \
    -w "\nHTTP %{http_code}\n" 2>&1 | head -5
echo "__T1_EXIT__:$?"

echo ""
echo "--- TEST 2: google.com via iron-proxy (should be DENIED) ---"
curl -sS \
    --cacert "$CA_CERT" \
    -x "$PROXY_URL" \
    https://google.com \
    -m 15 \
    -w "\nHTTP %{http_code}\n" 2>&1 | head -5
echo "__T2_EXIT__:$?"

kill "$PROXY_A_PID" 2>/dev/null || true
INNER
chmod +x "$INNER_SCRIPT"
pass "Inner script written"

# =============================================
# Phase 6: Run bwrap sandbox
# =============================================
echo ""
echo "================================================================="
echo "  LAUNCHING bwrap SANDBOX (--unshare-net)"
echo "================================================================="
echo ""
log "Phase 6: Running tests inside bwrap (total network block + Unix socket pipe)..."

BWRAP_OUTPUT=$(bwrap \
    --unshare-net \
    --unshare-ipc \
    --unshare-pid \
    --unshare-uts \
    --ro-bind /usr          /usr          \
    --ro-bind /lib          /lib          \
    --ro-bind /lib64        /lib64        \
    --ro-bind /bin          /bin          \
    --ro-bind /etc/resolv.conf /etc/resolv.conf \
    --bind    "$UNIX_SOCKET"   /run/proxy.sock \
    --bind    "$CA_CERT"       /run/iron-proxy-ca.crt \
    --bind    "$INNER_SCRIPT"  /run/test.sh \
    --proc    /proc  \
    --dev     /dev   \
    --tmpfs   /tmp   \
    --die-with-parent \
    --clearenv \
    --setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    -- /bin/sh /run/test.sh 2>&1) || true

echo "$BWRAP_OUTPUT"

# =============================================
# Phase 7: Parse results
# =============================================
echo ""
echo "================================================================="
echo "  RESULTS"
echo "================================================================="
echo ""

T1="FAIL"; T2="FAIL"

T1_EXIT=$(echo "$BWRAP_OUTPUT" | grep "__T1_EXIT__:" | sed 's/.*__T1_EXIT__://')
T2_EXIT=$(echo "$BWRAP_OUTPUT" | grep "__T2_EXIT__:" | sed 's/.*__T2_EXIT__://')

if [[ "$T1_EXIT" == "0" ]] && echo "$BWRAP_OUTPUT" | grep -qi "example\|doctype\|html"; then
    pass "TEST 1: example.com works through bwrap → Unix → iron-proxy"
    T1="PASS"
else
    fail "TEST 1: example.com failed (curl exit=$T1_EXIT)"
fi

if [[ "$T2_EXIT" != "0" ]] && echo "$BWRAP_OUTPUT" | grep -Eqi "denied|403|407|forbidden|blocked|refused"; then
    pass "TEST 2: google.com denied by iron-proxy allowlist"
    T2="PASS"
else
    fail "TEST 2: google.com was not blocked as expected (curl exit=$T2_EXIT)"
fi

echo ""
echo "  example.com via bwrap → Unix → iron-proxy: $T1"
echo "  google.com blocked by iron-proxy allowlist: $T2"
echo ""
echo "  iron-proxy log: $LOG_FILE"
echo "================================================================="
echo ""

log "iron-proxy log (last 20 lines):"
tail -20 "$LOG_FILE"

if [[ "$T1" != "PASS" || "$T2" != "PASS" ]]; then
    exit 1
fi

pass "bwrap + Unix-socket + iron-proxy egress chain validated"
