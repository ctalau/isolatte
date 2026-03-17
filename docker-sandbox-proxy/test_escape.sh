#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
# Sandbox escape & proxy-bypass test suite
# Runs INSIDE the sandboxed container (ubuntu:24.04)
# ──────────────────────────────────────────────────────────────────
set -euo pipefail

PASS=0; FAIL=0; TOTAL=0

run_test() {
  local name="$1"; shift
  TOTAL=$((TOTAL + 1))
  printf "  [TEST %02d] %-55s " "$TOTAL" "$name"
  if "$@" >/dev/null 2>&1; then
    echo "PASS"
    PASS=$((PASS + 1))
  else
    echo "FAIL"
    FAIL=$((FAIL + 1))
  fi
}

# expect_fail: the inner command SHOULD fail for the test to pass
expect_fail() {
  if "$@" >/dev/null 2>&1; then return 1; else return 0; fi
}

echo "=== Sandbox Escape & Proxy-Bypass Tests ==="
echo ""

# ── 1. Direct internet access (bypass proxy) ─────────────────────
echo "── Direct internet access (should all fail) ──"

run_test "Direct curl to google.com (no proxy)" \
  expect_fail env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
    curl --max-time 5 -s http://google.com

run_test "Direct wget to example.com (no proxy)" \
  expect_fail env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
    wget --timeout=5 -q -O /dev/null http://example.com

run_test "Direct TCP connect to 8.8.8.8:53 via /dev/tcp" \
  expect_fail bash -c 'echo >/dev/tcp/8.8.8.8/53'

run_test "Direct ping to 8.8.8.8" \
  expect_fail ping -c1 -W2 8.8.8.8

# ── 2. Proxy ACL enforcement ─────────────────────────────────────
echo ""
echo "── Proxy ACL enforcement (blocked domains) ──"

run_test "Proxy blocks google.com" \
  expect_fail curl --proxy http://proxy:4750 --max-time 5 -s https://google.com

run_test "Proxy blocks evil.com" \
  expect_fail curl --proxy http://proxy:4750 --max-time 5 -s https://evil.com

run_test "Proxy blocks raw IP 1.1.1.1" \
  expect_fail curl --proxy http://proxy:4750 --max-time 5 -s https://1.1.1.1

run_test "Proxy blocks metadata endpoint 169.254.169.254" \
  expect_fail curl --proxy http://proxy:4750 --max-time 5 -s http://169.254.169.254/latest/meta-data/

# ── 3. Allowed domains ───────────────────────────────────────────
echo ""
echo "── Allowed domains (should succeed via proxy) ──"

run_test "Proxy allows registry.npmjs.org" \
  curl --proxy http://proxy:4750 --max-time 10 -s -o /dev/null -w '%{http_code}' https://registry.npmjs.org | grep -qE '^[23]'

run_test "Proxy allows repo1.maven.org" \
  curl --proxy http://proxy:4750 --max-time 10 -s -o /dev/null -w '%{http_code}' https://repo1.maven.org/maven2/ | grep -qE '^[23]'

run_test "Proxy allows api.anthropic.com" \
  curl --proxy http://proxy:4750 --max-time 10 -s -o /dev/null https://api.anthropic.com

run_test "Proxy allows api.openai.com" \
  curl --proxy http://proxy:4750 --max-time 10 -s -o /dev/null https://api.openai.com

# ── 4. Container escape vectors ──────────────────────────────────
echo ""
echo "── Container escape attempts (should all fail) ──"

run_test "Cannot access Docker socket" \
  expect_fail ls /var/run/docker.sock

run_test "Cannot mount host filesystems via mount" \
  expect_fail mount -t proc proc /mnt

run_test "Cannot load kernel modules" \
  expect_fail modprobe dummy

run_test "Cannot write to /proc/sysrq-trigger" \
  expect_fail bash -c 'echo b > /proc/sysrq-trigger'

run_test "Cannot access host PID namespace (PID 1 is container init)" \
  bash -c '[ "$(cat /proc/1/cmdline 2>/dev/null | tr "\0" " " | head -c 5)" = "sleep" ]'

run_test "Cannot chroot escape" \
  expect_fail bash -c 'mkdir -p /tmp/esctest && chroot /tmp/esctest /bin/sh -c "echo escaped"'

run_test "No NET_RAW capability (raw sockets blocked)" \
  expect_fail python3 -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)"

# ── 5. DNS exfiltration / tunneling ──────────────────────────────
echo ""
echo "── DNS exfiltration attempts ──"

run_test "Cannot resolve arbitrary domains directly" \
  expect_fail env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
    host evil-exfil-test.example.com

# ── Summary ──────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════"
printf "  Results: %d/%d passed" "$PASS" "$TOTAL"
if [ "$FAIL" -gt 0 ]; then
  printf " (%d FAILED)" "$FAIL"
fi
echo ""
echo "════════════════════════════════════════════════"

[ "$FAIL" -eq 0 ]
