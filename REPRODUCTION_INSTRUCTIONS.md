# Container Networking Reproduction Instructions

Step-by-step guide to reproduce all the networking experiments documented in this project.

---

## Quick Start (5 minutes)

### 1. Verify Podman is Installed

```bash
podman --version
# Expected output: podman version X.X.X
```

### 2. Separate Image Pull (Timing)

```bash
# Pull node:10 image separately to measure time
time podman pull node:10

# For comparison, measure cached pull:
time podman pull node:10  # Should be much faster (<1 sec)
```

**Expected timing:**
- Fresh pull: 20-300 seconds (depends on network speed and image size ~900MB)
- Cached pull: <1 second

### 3. Run Basic Node Command

```bash
podman run --rm --net=host node:10 node --version
# Expected output: v10.24.1 (or similar v10.x.x)
```

---

## Complete Test Suite (20 minutes)

### Test 1: HTTP Server with Bridge Networking (Port Mapping)

```bash
#!/bin/bash
# Start HTTP server on container port 8080, map to host port 8888
podman run --rm -d -p 8888:8080 --name test-bridge \
  node:10 node -e "
  require('http').createServer((req, res) => {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end('Hello from bridge network');
  }).listen(8080, '0.0.0.0');
  console.log('Bridge server started on port 8080');
  "

# Wait for server to start
sleep 2

# Test connection from host
echo "Testing bridge port mapping..."
curl -v http://localhost:8888/

# Verify iptables rule was added
echo ""
echo "Checking iptables rules..."
sudo iptables -t nat -L -n | grep 8888 || echo "(Requires sudo)"

# Check listening ports
echo ""
echo "Port status on host:"
ss -tuln | grep 8888 || netstat -tuln | grep 8888 || echo "(Cannot determine - may require sudo)"

# Cleanup
podman stop test-bridge
sleep 1
```

**Expected Results:**
- ✅ curl successfully gets "Hello from bridge network"
- ✅ iptables shows DNAT rule for port 8888
- ⚠️ Port 8888 may not appear in `ss -tuln` (because it's in container namespace)

---

### Test 2: HTTP Server with Host Networking

```bash
#!/bin/bash
# Start HTTP server with host networking (no port mapping needed)
podman run --rm -d --net=host --name test-host \
  node:10 node -e "
  require('http').createServer((req, res) => {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end('Hello from host network');
  }).listen(9000, '0.0.0.0');
  console.log('Host network server started on port 9000');
  "

# Wait for server to start
sleep 2

# Test connection from host
echo "Testing host network connection..."
curl -v http://localhost:9000/

# Check listening ports (port should appear on host)
echo ""
echo "Port status on host:"
ss -tuln | grep 9000 || netstat -tuln | grep 9000 || echo "(Cannot determine)"

# Compare iptables (should be no rules added)
echo ""
echo "Checking iptables (should have no 9000 rules):"
sudo iptables -t nat -L -n | grep 9000 || echo "No iptables rules (as expected for host mode)"

# Cleanup
podman stop test-host
sleep 1
```

**Expected Results:**
- ✅ curl successfully gets "Hello from host network"
- ✅ Port 9000 appears in `ss -tuln` output
- ✅ No iptables rules for port 9000 (direct binding)

---

### Test 3: Container-to-Container Communication

```bash
#!/bin/bash
# Create a custom network for isolation
podman network create service-network

echo "Starting backend service..."
podman run --rm -d --name backend-service \
  --net service-network \
  node:10 node -e "
  const server = require('http').createServer((req, res) => {
    res.writeHead(200);
    res.end(JSON.stringify({
      message: 'Response from backend',
      timestamp: new Date().toISOString(),
      container: 'backend-service'
    }));
  });
  server.listen(5000, '0.0.0.0');
  console.log('Backend listening on port 5000');
  "

# Wait for backend to start
sleep 2

echo "Testing frontend → backend communication..."
podman run --rm --net service-network \
  node:10 node -e "
  const http = require('http');

  http.get('http://backend-service:5000/', (res) => {
    let data = '';
    res.on('data', (chunk) => { data += chunk; });
    res.on('end', () => {
      console.log('SUCCESS: Received from backend:');
      console.log(data);
      process.exit(0);
    });
  }).on('error', (err) => {
    console.error('ERROR: Could not connect to backend');
    console.error(err.message);
    process.exit(1);
  });

  setTimeout(() => {
    console.error('TIMEOUT: No response after 5 seconds');
    process.exit(1);
  }, 5000);
  "

# Verify network configuration
echo ""
echo "Network configuration:"
podman network inspect service-network | grep -E "Name|(\"IPv" | head -10

# Cleanup
echo ""
echo "Cleaning up..."
podman stop backend-service 2>/dev/null || true
podman network rm service-network 2>/dev/null || true
echo "Done!"
```

**Expected Results:**
- ✅ Frontend successfully connects to backend via container name (`backend-service`)
- ✅ Backend response is received and printed
- ✅ DNS resolution works (container name → IP)

---

### Test 4: Network Isolation Scenario

```bash
#!/bin/bash
# This test creates an isolated network where:
# - Container A can only reach Container B
# - Container B can reach internet (via external network)
# - Container A has no internet access

echo "Creating networks..."
podman network create isolated-network
podman network create external-network

echo "Starting Container B (on both networks)..."
podman run --rm -d --name container-b \
  --net isolated-network \
  --net external-network \
  node:10 sleep 300

echo "Starting Container A (isolated network only)..."
podman run --rm -d --name container-a \
  --net isolated-network \
  node:10 sleep 300

# Give containers time to start
sleep 2

echo ""
echo "=== Test Results ==="
echo ""

# Test 1: A can reach B
echo "Test 1: Container A → Container B"
if podman exec container-a ping -c 1 -W 3 container-b >/dev/null 2>&1; then
  echo "✅ PASS: Container A can reach Container B"
else
  echo "❌ FAIL: Container A cannot reach Container B"
fi

# Test 2: A cannot reach internet
echo ""
echo "Test 2: Container A → Internet (should fail)"
if podman exec container-a ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
  echo "❌ FAIL: Container A has internet access (should not have)"
else
  echo "✅ PASS: Container A has no internet access (as expected)"
fi

# Test 3: B can reach A
echo ""
echo "Test 3: Container B → Container A"
if podman exec container-b ping -c 1 -W 3 container-a >/dev/null 2>&1; then
  echo "✅ PASS: Container B can reach Container A"
else
  echo "❌ FAIL: Container B cannot reach Container A"
fi

# Test 4: B can reach internet
echo ""
echo "Test 4: Container B → Internet (if NAT enabled)"
if podman exec container-b ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
  echo "✅ PASS: Container B has internet access"
else
  echo "⚠️  Container B cannot reach internet (NAT may not be configured)"
fi

# Show network topology
echo ""
echo "=== Network Topology ==="
echo ""
echo "Container B network attachments:"
podman exec container-b ip addr show | grep "inet " | grep -v "127.0.0.1"

echo ""
echo "Container A network attachments:"
podman exec container-a ip addr show | grep "inet " | grep -v "127.0.0.1"

# Cleanup
echo ""
echo "Cleaning up..."
podman stop container-a container-b 2>/dev/null || true
sleep 1
podman network rm isolated-network external-network 2>/dev/null || true
echo "Done!"
```

**Expected Results:**
- ✅ Container A can reach Container B
- ✅ Container A cannot reach internet
- ✅ Container B can reach Container A
- ✅ Container B can reach internet (if NAT enabled on external-network)

---

## Understanding the Output

### Bridge Mode - Port Mapping Example

When you run:
```bash
podman run -p 8888:8080 myimage
```

**What happens internally:**
1. Container gets IP `10.89.0.2` on bridge `cni0`
2. Container process binds to `0.0.0.0:8080` (in its namespace)
3. Podman creates iptables rule:
   ```
   -A PREROUTING -p tcp --dport 8888 -j DNAT --to-destination 10.89.0.2:8080
   ```
4. Client connects to `localhost:8888`
5. Kernel intercepts traffic and redirects to `10.89.0.2:8080`
6. Response is NAT'd back to appear from `localhost`

**Result:** Client sees service on `localhost:8888`, container thinks it's on `0.0.0.0:8080`

---

### Host Mode - Direct Binding

When you run:
```bash
podman run --net=host myimage
```

**What happens internally:**
1. Container shares host's network namespace
2. Container process binds to `0.0.0.0:9999` (directly on host)
3. No iptables rules added
4. Client connects to `localhost:9999`
5. Kernel delivers to container process directly
6. No translation layer

**Result:** Container process literally owns the socket

---

### Same-Network Container Communication

When you run two containers on same network:
```bash
podman run --name svc1 --net mynet myimage
podman run --net mynet myimage  # Can reach svc1
```

**What happens internally:**
1. Both containers on bridge `cni0` (for network `mynet`)
2. Container 1 gets IP `10.89.0.2`
3. Container 2 gets IP `10.89.0.3`
4. Podman runs DNS server on `127.0.0.11:53`
5. Container 2 queries DNS for `svc1`
6. DNS responds with `10.89.0.2`
7. Container 2 sends HTTP request to `10.89.0.2:8080`
8. Bridge forwards packet directly to Container 1

**Result:** Containers can reach each other by name

---

## Troubleshooting

### Issue: Cannot connect to mapped port

**Symptom:** `curl localhost:8888` fails

**Solution:**
```bash
# 1. Verify container is running
podman ps | grep mycontainer

# 2. Check container is listening internally
podman exec mycontainer netstat -tuln | grep 8080

# 3. Verify iptables rule exists (requires sudo)
sudo iptables -t nat -L -n | grep 8888

# 4. Try connecting from inside container
podman exec mycontainer curl localhost:8080

# 5. Check firewall
sudo ufw status  # or iptables -L -n
```

### Issue: Container cannot reach another container

**Symptom:** `podman exec c1 curl http://c2:8080` fails

**Solution:**
```bash
# 1. Verify both on same network
podman network inspect mynet | grep "c1\|c2"

# 2. Test DNS resolution
podman exec c1 nslookup c2

# 3. Get container IP manually
podman exec c2 ip addr show

# 4. Try direct IP (bypass DNS)
podman exec c1 curl http://<c2_ip>:8080

# 5. Check if service is actually listening
podman exec c2 netstat -tuln | grep 8080
```

### Issue: iptables rules seem wrong

**Check current iptables state:**
```bash
# List all NAT rules
sudo iptables -t nat -L -v -n

# List with line numbers (for deletion)
sudo iptables -t nat -L -v -n --line-numbers

# List forward rules
sudo iptables -L FORWARD -v -n

# Monitor changes in real-time
watch -n 1 'sudo iptables -t nat -L -n | head -20'
```

---

## Performance Tips

1. **Image Pulls:** Pull images separately before testing to exclude pull time
2. **HTTP Calls:** Host mode is ~5x faster than bridge mode due to NAT overhead
3. **Same-Network:** Container-to-container on same network is nearly as fast as host mode
4. **DNS:** DNS lookups add 10-50ms; use IP directly for critical paths
5. **Node.js:** Startup time for node:10 is ~0.3-0.8 seconds

---

## References

- Full guide: See `CONTAINER_NETWORKING_GUIDE.md`
- Test results: See `NETWORKING_TEST_RESULTS.md`
- Podman docs: https://docs.podman.io/
