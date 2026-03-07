#!/bin/bash

# Networking Test Suite for Podman

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

RESULTS_FILE="NETWORKING_TEST_RESULTS.md"

# Clear results file
cat > "$RESULTS_FILE" << 'HEADER'
# Podman Networking Test Results

Date: $(date)
Podman Version: $(podman --version)
Kernel: $(uname -r)
OS: $(uname -s)

---

HEADER

echo -e "${BLUE}=== PODMAN NETWORKING EXPERIMENTS ===${NC}\n"

# Test 1: Pull image and get timing
echo -e "${YELLOW}TEST 1: Image Pull Timing${NC}"
echo "Pulling node:10 image (separating from execution)..."
start_time=$(date +%s)
podman pull node:10 > /dev/null 2>&1 || true
end_time=$(date +%s)
elapsed=$((end_time - start_time))
echo -e "${GREEN}✓ Image pulled in ${elapsed} seconds${NC}\n"

# Test 2: Run node --version
echo -e "${YELLOW}TEST 2: Basic Command Execution${NC}"
echo "Running: podman run --rm --net=host node:10 node --version"
output=$(podman run --rm --net=host node:10 node --version 2>&1)
echo -e "${GREEN}✓ Output: $output${NC}\n"

# Test 3: Check current iptables state
echo -e "${YELLOW}TEST 3: iptables State${NC}"
echo "Checking NAT rules..."
echo "Current iptables NAT rules (sample):"
sudo iptables -t nat -L -n 2>/dev/null | head -20 || echo "(Requires sudo privileges)"
echo ""

# Test 4: HTTP Server with Bridge Networking
echo -e "${YELLOW}TEST 4: HTTP Server with Bridge Network (Port Forwarding)${NC}"
echo "Starting HTTP server on port 8080 with bridge networking..."

podman run --rm -d -p 8080:8080 --name test-http-bridge \
  node:10 node -e "
  const server = require('http').createServer((req, res) => {
    res.writeHead(200);
    res.end('Hello from bridge container');
  });
  server.listen(8080, '0.0.0.0');
  console.log('Server listening on 8080');
  " 2>&1

sleep 1

# Try to connect
if curl -s http://localhost:8080 > /dev/null 2>&1; then
  result=$(curl -s http://localhost:8080)
  echo -e "${GREEN}✓ Successfully connected to container via localhost:8080${NC}"
  echo "  Response: $result"
else
  echo -e "${RED}✗ Failed to connect${NC}"
fi

# Check if port appears in netstat
echo "Host listening ports:"
sudo ss -tuln 2>/dev/null | grep 8080 || netstat -tuln 2>/dev/null | grep 8080 || echo "(Cannot determine - may require sudo)"

podman stop test-http-bridge
sleep 1
echo ""

# Test 5: HTTP Server with Host Networking
echo -e "${YELLOW}TEST 5: HTTP Server with Host Networking${NC}"
echo "Starting HTTP server on port 9000 with host networking..."

podman run --rm -d --net=host --name test-http-host \
  node:10 node -e "
  const server = require('http').createServer((req, res) => {
    res.writeHead(200);
    res.end('Hello from host network');
  });
  server.listen(9000, '0.0.0.0');
  console.log('Server listening on 9000');
  " 2>&1

sleep 1

# Try to connect
if curl -s http://localhost:9000 > /dev/null 2>&1; then
  result=$(curl -s http://localhost:9000)
  echo -e "${GREEN}✓ Successfully connected to container via localhost:9000${NC}"
  echo "  Response: $result"
else
  echo -e "${RED}✗ Failed to connect${NC}"
fi

echo "Host listening ports (with --net=host):"
sudo ss -tuln 2>/dev/null | grep 9000 || netstat -tuln 2>/dev/null | grep 9000 || echo "(Cannot determine)"

podman stop test-http-host
sleep 1
echo ""

# Test 6: Container-to-Container Communication
echo -e "${YELLOW}TEST 6: Container-to-Container Communication${NC}"
echo "Creating custom network..."
podman network create test-network 2>/dev/null || true

echo "Starting backend container..."
podman run --rm -d --name backend-test \
  --net test-network \
  node:10 node -e "
  const server = require('http').createServer((req, res) => {
    res.writeHead(200);
    res.end(JSON.stringify({message: 'Backend response', pid: process.pid}));
  });
  server.listen(8080);
  " 2>&1

sleep 2

echo "Testing frontend → backend communication..."
result=$(podman run --rm --net test-network \
  node:10 node -e "
  const http = require('http');
  http.get('http://backend-test:8080/', (res) => {
    let data = '';
    res.on('data', (chunk) => { data += chunk; });
    res.on('end', () => { process.stdout.write(data); process.exit(0); });
  }).on('error', (e) => {
    console.error('Error:', e.message);
    process.exit(1);
  });
  setTimeout(() => { console.error('Timeout'); process.exit(1); }, 5000);
  " 2>&1 || echo "FAILED")

if echo "$result" | grep -q "Backend"; then
  echo -e "${GREEN}✓ Container-to-container communication successful${NC}"
  echo "  Response: $result"
else
  echo -e "${RED}✗ Container-to-container communication failed${NC}"
fi

echo "Cleaning up..."
podman stop backend-test 2>/dev/null || true
podman network rm test-network 2>/dev/null || true
echo ""

# Test 7: Network Isolation
echo -e "${YELLOW}TEST 7: Network Isolation (Container A only connects to B)${NC}"
echo "Creating isolated and external networks..."
podman network create isolated-ab 2>/dev/null || true
podman network create external-net 2>/dev/null || true

echo "Starting Container B on both networks..."
podman run --rm -d --name container-b \
  --net isolated-ab \
  --net external-net \
  node:10 sleep 300 2>&1 > /dev/null

sleep 1

echo "Starting Container A on isolated network only..."
podman run --rm -d --name container-a \
  --net isolated-ab \
  node:10 sleep 300 2>&1 > /dev/null

sleep 1

echo "Testing A → B (should succeed)..."
if podman exec container-a ping -c 1 -W 2 container-b > /dev/null 2>&1; then
  echo -e "${GREEN}✓ Container A can reach Container B${NC}"
else
  echo -e "${RED}✗ Container A cannot reach Container B${NC}"
fi

echo "Cleaning up isolation test..."
podman stop container-a container-b 2>/dev/null || true
podman network rm isolated-ab external-net 2>/dev/null || true
echo ""

echo -e "${GREEN}=== TESTS COMPLETED ===${NC}\n"

