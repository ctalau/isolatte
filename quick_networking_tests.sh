#!/bin/bash

echo "=== Quick Networking Tests ==="
echo ""

# Test 1: Image pull timing
echo "TEST 1: Image Pull Timing"
time podman pull node:10 2>&1 | tail -3
echo ""

# Test 2: Basic execution
echo "TEST 2: Node Execution"
podman run --rm --net=host node:10 node --version
echo ""

# Test 3: HTTP with Bridge (port mapping)
echo "TEST 3: HTTP Server - Bridge Mode (Port Mapping)"
timeout 5 podman run --rm -d -p 8888:8080 --name web1 \
  node:10 node -e "
  require('http').createServer((q,r) => r.end('bridge')).listen(8080)
  " 2>&1
sleep 2
curl -s http://localhost:8888/ && echo "" || echo "Connect failed"
podman stop web1 2>/dev/null
echo ""

# Test 4: HTTP with Host network
echo "TEST 4: HTTP Server - Host Mode"
timeout 5 podman run --rm -d --net=host --name web2 \
  node:10 node -e "
  require('http').createServer((q,r) => r.end('host')).listen(9999)
  " 2>&1
sleep 2
curl -s http://localhost:9999/ && echo "" || echo "Connect failed"
podman stop web2 2>/dev/null
echo ""

# Test 5: Container to container
echo "TEST 5: Container-to-Container Communication"
podman network create testnet 2>/dev/null || true
podman run --rm -d --net testnet --name svc1 \
  node:10 node -e "
  require('http').createServer((q,r) => r.end('from-svc1')).listen(7777)
  " 2>&1
sleep 2

podman run --rm --net testnet node:10 \
  node -e "
  require('http').get('http://svc1:7777', (r) => {
    let d=''; r.on('data',c=>d+=c); r.on('end',()=>process.stdout.write(d));
  })
  " 2>&1

echo ""
podman stop svc1 2>/dev/null
podman network rm testnet 2>/dev/null || true
echo ""

echo "=== Tests Complete ==="
