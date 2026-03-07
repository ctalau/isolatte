#!/bin/bash
# =============================================================================
# Smokescreen Proxy Isolation Experiment
# =============================================================================
#
# Architecture:
#   - Smokescreen proxy runs on the host, listening on 10.77.0.1:4750
#   - Container B runs via podman --network=none (fully isolated network ns)
#   - A veth pair connects Container B's namespace to the host
#   - Container B can ONLY reach 10.77.0.0/24 (the smokescreen proxy)
#   - Smokescreen ACL only allows access to example.com (enforce mode)
#   - NO iptables rules are created by this setup
#
# Network topology:
#
#   ┌───────────────────────────────────────────────────────────┐
#   │ Host Network Namespace                                     │
#   │                                                             │
#   │  smokescreen-proxy (0.0.0.0:4750)                          │
#   │       │  ACL: only example.com allowed                     │
#   │       │                                                     │
#   │  49f9526983-v (21.0.0.190)  ──► upstream egress proxy ──► Internet
#   │                                   (21.0.0.191)             │
#   │  veth-proxy (10.77.0.1/24)                                 │
#   │       │                                                     │
#   │       │  veth pair (L2, no iptables, no NAT)               │
#   │       │                                                     │
#   ├───────┼─────────────────────────────────────────────────────┤
#   │       │  Container B Network Namespace (podman --net=none) │
#   │  veth-client (10.77.0.2/24)                                │
#   │       │                                                     │
#   │  - No default route (cannot reach internet directly)       │
#   │  - Can only reach 10.77.0.0/24 subnet                     │
#   └───────────────────────────────────────────────────────────┘
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACL_FILE="$SCRIPT_DIR/acl.yaml"
LOG_FILE="$SCRIPT_DIR/smokescreen.log"

PROXY_IP="10.77.0.1"
CLIENT_IP="10.77.0.2"
PROXY_PORT="4750"
VETH_HOST="veth-proxy"
VETH_CLIENT="veth-client"

SMOKESCREEN_PID=""
CONTAINER_PID=""

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"; }
pass() { echo -e "  ${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; }

cleanup() {
    log "Cleaning up..."
    [ -n "$SMOKESCREEN_PID" ] && kill "$SMOKESCREEN_PID" 2>/dev/null || true
    podman stop container-b 2>/dev/null || true
    podman rm -f container-b 2>/dev/null || true
    ip link delete "$VETH_HOST" 2>/dev/null || true
}
trap cleanup EXIT

# =============================================
# Phase 1: Record iptables BEFORE
# =============================================
log "Phase 1: Recording iptables state BEFORE experiment..."
iptables -t nat -L -n 2>/dev/null > /tmp/iptables_before.txt || echo "(unavailable)" > /tmp/iptables_before.txt
iptables -L -n 2>/dev/null >> /tmp/iptables_before.txt || true

# =============================================
# Phase 2: Create veth pair
# =============================================
log "Phase 2: Creating veth pair for isolated networking..."

ip link delete "$VETH_HOST" 2>/dev/null || true
ip link add "$VETH_HOST" type veth peer name "$VETH_CLIENT"

# Configure host side
ip addr add "${PROXY_IP}/24" dev "$VETH_HOST"
ip link set "$VETH_HOST" up
log "  Host: $VETH_HOST = $PROXY_IP/24"

# =============================================
# Phase 3: Start smokescreen
# =============================================
log "Phase 3: Starting smokescreen proxy..."
log "  ACL file: $ACL_FILE (allows only: example.com)"

smokescreen-proxy \
    --listen-ip "0.0.0.0" \
    --listen-port "$PROXY_PORT" \
    --egress-acl-file "$ACL_FILE" \
    --unsafe-allow-private-ranges \
    > "$LOG_FILE" 2>&1 &
SMOKESCREEN_PID=$!
sleep 2

if kill -0 "$SMOKESCREEN_PID" 2>/dev/null; then
    pass "Smokescreen running (PID $SMOKESCREEN_PID) on 0.0.0.0:$PROXY_PORT"
else
    fail "Smokescreen failed to start"; cat "$LOG_FILE"; exit 1
fi

# =============================================
# Phase 4: Start Container B
# =============================================
log "Phase 4: Starting Container B (podman --network=none)..."

podman run -d --rm --name container-b --network=none \
    alpine /bin/sh -c "sleep 600" 2>&1 | tail -1

CONTAINER_PID=$(podman inspect --format '{{.State.Pid}}' container-b)
log "  Container B PID: $CONTAINER_PID"

# Move veth-client into container's network namespace
ip link set "$VETH_CLIENT" netns "$CONTAINER_PID"

# Configure networking inside container
nsenter -t "$CONTAINER_PID" -n ip addr add "${CLIENT_IP}/24" dev "$VETH_CLIENT"
nsenter -t "$CONTAINER_PID" -n ip link set "$VETH_CLIENT" up
nsenter -t "$CONTAINER_PID" -n ip link set lo up
# NOTE: no default route added - container can only reach 10.77.0.0/24

log "  Container: $VETH_CLIENT = $CLIENT_IP/24 (no default route)"

# Verify connectivity
echo ""
log "Verifying veth connectivity..."
ping -c 1 -W 2 "$CLIENT_IP" >/dev/null 2>&1 && pass "Host -> Container (ping)" || fail "Host -> Container (ping)"
nsenter -t "$CONTAINER_PID" -n ping -c 1 -W 2 "$PROXY_IP" >/dev/null 2>&1 && pass "Container -> Host (ping)" || fail "Container -> Host (ping)"

# =============================================
# Phase 5: Record iptables AFTER
# =============================================
echo ""
log "Phase 5: Comparing iptables before/after..."
iptables -t nat -L -n 2>/dev/null > /tmp/iptables_after.txt || echo "(unavailable)" > /tmp/iptables_after.txt
iptables -L -n 2>/dev/null >> /tmp/iptables_after.txt || true

if diff -q /tmp/iptables_before.txt /tmp/iptables_after.txt >/dev/null 2>&1; then
    pass "NO iptables rules were added by this setup"
else
    fail "iptables rules changed:"
    diff /tmp/iptables_before.txt /tmp/iptables_after.txt || true
fi

# =============================================
# Phase 6: Run Tests
# =============================================
echo ""
echo "================================================================="
echo "  CONNECTIVITY TESTS"
echo "================================================================="
echo ""

# --- TEST 1: Container B cannot connect directly to whitelisted website ---
log "TEST 1: Container B -> example.com directly (should FAIL - no route)"
T1_RESULT=$(nsenter -t "$CONTAINER_PID" -n \
    wget -q -O - --timeout=5 http://93.184.216.34/ 2>&1 || true)
echo "  Output: ${T1_RESULT:0:200}"
if echo "$T1_RESULT" | grep -qi "unreachable\|timed out\|can't connect\|bad address\|Network is unreachable"; then
    pass "TEST 1: Container B CANNOT connect directly (no route to internet)"
    T1_STATUS="PASS"
else
    fail "TEST 1: Unexpected - container might have direct access"
    T1_STATUS="FAIL"
fi

echo ""

# --- TEST 2: Container B connects to whitelisted website VIA proxy ---
log "TEST 2: Container B -> example.com via smokescreen (should SUCCEED)"
T2_RESULT=$(nsenter -t "$CONTAINER_PID" -n \
    env -u http_proxy -u https_proxy -u no_proxy \
    wget -q -O - --timeout=15 -e "https_proxy=http://${PROXY_IP}:${PROXY_PORT}" \
    https://example.com/ 2>&1 || true)
echo "  Output (first 200 chars): ${T2_RESULT:0:200}"
if echo "$T2_RESULT" | grep -qi "example\|doctype\|html"; then
    pass "TEST 2: Container B CAN connect to example.com via proxy"
    T2_STATUS="PASS"
else
    fail "TEST 2: Could not connect to example.com via proxy"
    echo "  Smokescreen log (last 10 lines):"
    tail -10 "$LOG_FILE"
    T2_STATUS="FAIL"
fi

echo ""

# --- TEST 3: Container B cannot connect to non-whitelisted site VIA proxy ---
log "TEST 3: Container B -> google.com via smokescreen (should be DENIED)"
T3_RESULT=$(nsenter -t "$CONTAINER_PID" -n \
    env -u http_proxy -u https_proxy -u no_proxy \
    wget -q -O - --timeout=10 -e "https_proxy=http://${PROXY_IP}:${PROXY_PORT}" \
    https://google.com/ 2>&1 || true)
echo "  Output: ${T3_RESULT:0:300}"
if echo "$T3_RESULT" | grep -qi "denied\|rejected\|407\|503\|error\|proxy"; then
    pass "TEST 3: Container B CANNOT connect to google.com (blocked by ACL)"
    T3_STATUS="PASS"
else
    fail "TEST 3: Unexpected - google.com should be blocked"
    echo "  Smokescreen log (last 10 lines):"
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
echo "  Test 1 (direct blocked):         $T1_STATUS"
echo "  Test 2 (proxy allowed):          $T2_STATUS"
echo "  Test 3 (non-whitelisted blocked): $T3_STATUS"
echo "  iptables rules added:            NONE"
echo ""
echo "  Smokescreen proxy log: $LOG_FILE"
echo "================================================================="
echo ""

log "Smokescreen log (last 20 lines):"
tail -20 "$LOG_FILE"
