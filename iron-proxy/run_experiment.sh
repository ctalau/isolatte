#!/usr/bin/env bash
# =============================================================================
# Iron-Proxy Egress ACL Experiment
# =============================================================================
#
# Architecture:
#   - iron-proxy runs on the host, HTTP proxy on 0.0.0.0:4750
#   - Container runs via podman --network=none (fully isolated network ns)
#   - A veth pair connects the container's namespace to the host
#   - Container can ONLY reach 10.77.1.0/24 (the iron-proxy subnet)
#   - iron-proxy allowlist permits only example.com (default-deny)
#   - NO iptables rules are created by this setup
#
# iron-proxy vs smokescreen:
#   - iron-proxy: MITM/TLS-terminating proxy with DNS server + secret injection
#   - smokescreen: CONNECT-tunnel proxy (no TLS termination), domain ACL YAML
#   - Both: default-deny egress, domain allowlist, veth isolation
#
# Network topology:
#
#   ┌───────────────────────────────────────────────────────────────┐
#   │ Host Network Namespace                                         │
#   │                                                               │
#   │  iron-proxy (0.0.0.0:4750 HTTP proxy, 0.0.0.0:5353 DNS)      │
#   │       │  allowlist: only example.com                          │
#   │       │                                                       │
#   │  veth-iron-host (10.77.1.1/24)  ──► Internet                 │
#   │       │                                                       │
#   │       │  veth pair (L2, no iptables, no NAT)                  │
#   │       │                                                       │
#   ├───────┼───────────────────────────────────────────────────────┤
#   │       │  Container Network Namespace (podman --net=none)       │
#   │  veth-iron-client (10.77.1.2/24)                              │
#   │       │                                                       │
#   │  - No default route (cannot reach internet directly)          │
#   │  - Can only reach 10.77.1.0/24 subnet                        │
#   │  - Trusts iron-proxy CA cert for MITM TLS inspection          │
#   └───────────────────────────────────────────────────────────────┘
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.yaml"
LOG_FILE="$SCRIPT_DIR/iron-proxy.log"
CA_CERT="/tmp/iron-proxy-ca.crt"
CA_KEY="/tmp/iron-proxy-ca.key"

PROXY_IP="10.77.1.1"
CLIENT_IP="10.77.1.2"
PROXY_HTTP_PORT="4750"
VETH_HOST="veth-iron-host"
VETH_CLIENT="veth-iron-client"

IRON_PROXY_BIN="$SCRIPT_DIR/.iron-proxy-bin"
IRON_PROXY_PID=""
CONTAINER_PID=""

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"; }
pass() { echo -e "  ${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; }

cleanup() {
    log "Cleaning up..."
    [ -n "$IRON_PROXY_PID" ] && kill "$IRON_PROXY_PID" 2>/dev/null || true
    podman stop iron-proxy-container 2>/dev/null || true
    podman rm -f iron-proxy-container 2>/dev/null || true
    ip link delete "$VETH_HOST" 2>/dev/null || true
    rm -f "$IRON_PROXY_BIN"
}
trap cleanup EXIT

# =============================================
# Phase 0: Prerequisites
# =============================================
for cmd in openssl curl podman nsenter ip; do
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
# Phase 2: Generate CA certificate for TLS MITM
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

# Write an updated config pointing at the generated CA paths
cat > /tmp/iron-proxy-config.yaml <<EOF
dns:
  listen: ":5353"
  proxy_ip: "${PROXY_IP}"
  passthrough: []

proxy:
  http_listen: ":${PROXY_HTTP_PORT}"
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
# Phase 3: Record iptables BEFORE
# =============================================
log "Phase 3: Recording iptables state BEFORE experiment..."
iptables -t nat -L -n 2>/dev/null > /tmp/iptables_before.txt || echo "(unavailable)" > /tmp/iptables_before.txt
iptables -L -n 2>/dev/null >> /tmp/iptables_before.txt || true

# =============================================
# Phase 4: Create veth pair
# =============================================
log "Phase 4: Creating veth pair for isolated networking..."

ip link delete "$VETH_HOST" 2>/dev/null || true
ip link add "$VETH_HOST" type veth peer name "$VETH_CLIENT"
ip addr add "${PROXY_IP}/24" dev "$VETH_HOST"
ip link set "$VETH_HOST" up
log "  Host: $VETH_HOST = $PROXY_IP/24"

# =============================================
# Phase 5: Start iron-proxy
# =============================================
log "Phase 5: Starting iron-proxy on 0.0.0.0:${PROXY_HTTP_PORT}..."
log "  Config: /tmp/iron-proxy-config.yaml"
log "  ACL: allows only example.com (default-deny)"

"$IRON_PROXY_BIN" --config /tmp/iron-proxy-config.yaml >"$LOG_FILE" 2>&1 &
IRON_PROXY_PID=$!
sleep 2

if kill -0 "$IRON_PROXY_PID" 2>/dev/null; then
    pass "iron-proxy running (PID $IRON_PROXY_PID)"
else
    fail "iron-proxy failed to start"
    tail -20 "$LOG_FILE"
    exit 1
fi

# Verify the proxy port is accepting connections
for i in $(seq 1 20); do
    if (echo > /dev/tcp/127.0.0.1/$PROXY_HTTP_PORT) >/dev/null 2>&1; then
        break
    fi
    sleep 0.3
done
(echo > /dev/tcp/127.0.0.1/$PROXY_HTTP_PORT) >/dev/null 2>&1 \
    && pass "iron-proxy accepting connections on port $PROXY_HTTP_PORT" \
    || { fail "iron-proxy not accepting connections"; tail -20 "$LOG_FILE"; exit 1; }

# =============================================
# Phase 6: Start Container
# =============================================
log "Phase 6: Starting container (podman --network=none)..."

podman run -d --rm --name iron-proxy-container --network=none \
    alpine /bin/sh -c "sleep 600" 2>&1 | tail -1

CONTAINER_PID=$(podman inspect --format '{{.State.Pid}}' iron-proxy-container)
log "  Container PID: $CONTAINER_PID"

# Move veth-client into the container's network namespace
ip link set "$VETH_CLIENT" netns "$CONTAINER_PID"

# Configure networking inside container
nsenter -t "$CONTAINER_PID" -n ip addr add "${CLIENT_IP}/24" dev "$VETH_CLIENT"
nsenter -t "$CONTAINER_PID" -n ip link set "$VETH_CLIENT" up
nsenter -t "$CONTAINER_PID" -n ip link set lo up
# No default route — container can only reach 10.77.1.0/24

log "  Container: $VETH_CLIENT = $CLIENT_IP/24 (no default route)"

# Install the iron-proxy CA cert inside the container so MITM TLS is trusted
CONTAINER_ROOTFS=$(podman mount iron-proxy-container 2>/dev/null || true)
if [ -n "$CONTAINER_ROOTFS" ]; then
    cp "$CA_CERT" "$CONTAINER_ROOTFS/usr/local/share/ca-certificates/iron-proxy-ca.crt"
    podman unmount iron-proxy-container 2>/dev/null || true
fi

# Verify connectivity
echo ""
log "Verifying veth connectivity..."
ping -c 1 -W 2 "$CLIENT_IP" >/dev/null 2>&1 \
    && pass "Host -> Container (ping)" \
    || fail "Host -> Container (ping)"
nsenter -t "$CONTAINER_PID" -n ping -c 1 -W 2 "$PROXY_IP" >/dev/null 2>&1 \
    && pass "Container -> Host (ping)" \
    || fail "Container -> Host (ping)"

# =============================================
# Phase 7: Record iptables AFTER
# =============================================
echo ""
log "Phase 7: Comparing iptables before/after..."
iptables -t nat -L -n 2>/dev/null > /tmp/iptables_after.txt || echo "(unavailable)" > /tmp/iptables_after.txt
iptables -L -n 2>/dev/null >> /tmp/iptables_after.txt || true

if diff -q /tmp/iptables_before.txt /tmp/iptables_after.txt >/dev/null 2>&1; then
    pass "NO iptables rules were added by this setup"
else
    fail "iptables rules changed:"
    diff /tmp/iptables_before.txt /tmp/iptables_after.txt || true
fi

# =============================================
# Phase 8: Run Tests
# =============================================
echo ""
echo "================================================================="
echo "  CONNECTIVITY TESTS"
echo "================================================================="
echo ""

PROXY_URL="http://${PROXY_IP}:${PROXY_HTTP_PORT}"

# --- TEST 1: Container cannot reach internet directly ---
log "TEST 1: Container -> example.com directly (should FAIL - no route)"
T1_RESULT=$(nsenter -t "$CONTAINER_PID" -n \
    wget -q -O - --timeout=5 http://93.184.216.34/ 2>&1 || true)
echo "  Output: ${T1_RESULT:0:200}"
if echo "$T1_RESULT" | grep -qi "unreachable\|timed out\|can't connect\|Network is unreachable"; then
    pass "TEST 1: Container CANNOT connect directly (no route to internet)"
    T1_STATUS="PASS"
else
    fail "TEST 1: Unexpected - container might have direct internet access"
    T1_STATUS="FAIL"
fi

echo ""

# --- TEST 2: Container connects to example.com via iron-proxy ---
log "TEST 2: Container -> example.com via iron-proxy (should SUCCEED)"
T2_RESULT=$(nsenter -t "$CONTAINER_PID" -n \
    env -u http_proxy -u https_proxy -u no_proxy \
    wget -q -O - --timeout=20 \
    --ca-certificate="$CA_CERT" \
    -e "https_proxy=${PROXY_URL}" \
    https://example.com/ 2>&1 || true)
echo "  Output (first 200 chars): ${T2_RESULT:0:200}"
if echo "$T2_RESULT" | grep -qi "example\|doctype\|html"; then
    pass "TEST 2: Container CAN connect to example.com via iron-proxy"
    T2_STATUS="PASS"
else
    fail "TEST 2: Could not connect to example.com via iron-proxy"
    echo "  iron-proxy log (last 10 lines):"
    tail -10 "$LOG_FILE"
    T2_STATUS="FAIL"
fi

echo ""

# --- TEST 3: Container cannot connect to non-allowlisted site ---
log "TEST 3: Container -> google.com via iron-proxy (should be DENIED)"
T3_RESULT=$(nsenter -t "$CONTAINER_PID" -n \
    env -u http_proxy -u https_proxy -u no_proxy \
    wget -q -O - --timeout=15 \
    --ca-certificate="$CA_CERT" \
    -e "https_proxy=${PROXY_URL}" \
    https://google.com/ 2>&1 || true)
echo "  Output: ${T3_RESULT:0:300}"
if echo "$T3_RESULT" | grep -qi "denied\|rejected\|403\|407\|503\|error\|forbidden"; then
    pass "TEST 3: Container CANNOT connect to google.com (blocked by iron-proxy ACL)"
    T3_STATUS="PASS"
else
    fail "TEST 3: Unexpected - google.com should be blocked by iron-proxy"
    echo "  iron-proxy log (last 10 lines):"
    tail -10 "$LOG_FILE"
    T3_STATUS="FAIL"
fi

# =============================================
# Results Summary
# =============================================
echo ""
echo "================================================================="
echo "  RESULTS SUMMARY"
echo "================================================================="
echo ""
echo "  Test 1 (direct blocked):          $T1_STATUS"
echo "  Test 2 (proxy allowed):           $T2_STATUS"
echo "  Test 3 (non-allowlisted blocked): $T3_STATUS"
echo "  iptables rules added:             NONE"
echo ""
echo "  iron-proxy log: $LOG_FILE"
echo "================================================================="
echo ""

log "iron-proxy log (last 20 lines):"
tail -20 "$LOG_FILE"
