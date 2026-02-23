# Podman Container Networking: Reproduction Guide

This guide documents how to reproduce container execution experiments, understand podman networking behavior, and set up network isolation scenarios.

## Prerequisites

- Podman installed and running
- Linux system (tested on Linux 4.4.0)
- Basic understanding of containerization and networking

## Part 1: Basic Container Execution

### 1.1 Running a Simple Command in Node Container

**Objective:** Execute `node --version` in a node:10 container with host networking

#### Step 1: Pull the Image (Separate from Execution)

```bash
# Pull node:10 image
podman pull node:10
```

**Time Estimate:** 2-5 minutes
- Initial pull: ~3-5 minutes (image size ~900MB)
- Subsequent pulls (cached): ~1-2 seconds
- Network dependent: varies with internet speed and registry load

#### Step 2: Execute Command with Host Networking

```bash
# Run command with host networking
podman run --rm --net=host node:10 node --version

# Run with detailed output
podman run --rm --net=host -it node:10 bash -c "echo 'Node version:' && node --version"
```

**Expected Output:**
```
v10.24.1
```

#### Step 3: Verify Container Execution

```bash
# List running containers
podman ps

# Check if process completed successfully
podman run --rm --net=host node:10 node -e "console.log(process.version)"
```

---

## Part 2: Understanding Podman Networking

### 2.1 Exploring iptables Rules

Podman can use two networking modes:
1. **host** - Uses the host's network namespace directly (no iptables rules added)
2. **bridge** (default) - Creates an isolated network with iptables rules

#### Check Podman Network Configuration

```bash
# See current network drivers
podman network ls

# Inspect default network
podman network inspect podman

# Check iptables rules (requires root)
sudo iptables -t nat -L -n
sudo iptables -L -n

# Monitor iptables changes
sudo watch -n 1 'sudo iptables -t nat -L -n | head -20'
```

**Key Findings:**
- **host mode** (`--net=host`): No iptables rules, shares host's TCP/IP stack
- **bridge mode** (default): Creates rules for port mapping and network isolation
- **slirp4netns** (rootless podman): User-mode networking without iptables

#### What Gets Added to iptables

When using bridge networking with port forwarding:
- PREROUTING rules to redirect external traffic to container ports
- POSTROUTING rules for source NAT (MASQUERADE)
- FORWARD rules to allow traffic between host and container

---

### 2.2 Port Tunneling Behavior

#### Test 1: Understanding Port Mapping

```bash
# Start an HTTP server in a container with bridge networking
podman run --rm -d -p 8080:8080 --name web-test \
  node:10 node -e "require('http').createServer((req, res) => {
    res.writeHead(200);
    res.end('Hello from container');
  }).listen(8080);"

# Check if port is accessible on host
curl http://localhost:8080
curl http://127.0.0.1:8080

# Check listening ports on host
sudo netstat -tuln | grep 8080
# or
sudo ss -tuln | grep 8080

# Stop the container
podman stop web-test
```

**How It Works:**
- Podman adds iptables PREROUTING rule: `192.168.x.x:8080 -> container_ip:8080`
- Traffic to `localhost:8080` is NAT'd to container's port
- Port is NOT actually listening on host (it's in container's namespace)

---

### 2.3 Host Networking Deep Dive

#### Test 2: HTTP Server with Host Networking

```bash
# Start HTTP server with host networking (shares host's network stack)
podman run --rm -d --net=host --name host-web \
  node:10 node -e "require('http').createServer((req, res) => {
    res.writeHead(200);
    res.end('Hello from host network');
  }).listen(9000);"

# Check listening ports (port should appear in host)
sudo ss -tuln | grep 9000

# Access from host
curl http://localhost:9000

# Stop the container
podman stop host-web
```

**Key Difference:**
- With `--net=host`, the container process literally binds to host's TCP/IP stack
- Port 9000 is directly in the host's listening sockets
- No NAT translation needed
- Less isolation, better performance

---

## Part 3: Container-to-Container Communication

### 3.1 Testing Direct Container Communication

#### Setup: Create Custom Network

```bash
# Create a custom bridge network
podman network create test-network

# Inspect the network
podman network inspect test-network
```

#### Test 3: Container-to-Container HTTP Communication

```bash
# Start a backend server
podman run --rm -d --name backend \
  --net test-network \
  node:10 node -e "
    require('http').createServer((req, res) => {
      res.writeHead(200);
      res.end('Response from backend');
    }).listen(8080);
  "

# Wait a moment for server to start
sleep 1

# Start a frontend container and make a request
podman run --rm -it --name frontend \
  --net test-network \
  node:10 node -e "
    require('http').get('http://backend:8080/', (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => { console.log('Received:', data); });
    });
  "

# Verify both containers are on the network
podman network inspect test-network

# Cleanup
podman stop backend
podman network rm test-network
```

**Expected Behavior:**
- Containers on the same network can reach each other by name
- Podman's built-in DNS resolves container names to their IPs
- No iptables rules needed for inter-container traffic (all in container network)

---

## Part 4: Network Isolation Scenarios

### 4.1 Setup: Container A → Container B Only (No Internet)

**Goal:** Container A can only reach Container B; Container B can reach internet

#### Solution: Multiple Networks + Firewall

```bash
# Create two networks:
# 1. "isolated" - for A ↔ B communication only
# 2. "external" - for B ↔ internet

podman network create isolated
podman network create external

# Start Container B on both networks
podman run --rm -d --name container-b \
  --net isolated \
  --net external \
  node:10 sleep 1000

# Start Container A on isolated network only
podman run --rm -d --name container-a \
  --net isolated \
  node:10 sleep 1000

# Test 1: A can reach B
podman exec container-a ping -c 1 container-b
# Expected: SUCCESS

# Test 2: A cannot reach internet (no internet access)
podman exec container-a ping -c 1 8.8.8.8
# Expected: FAIL (unreachable)

# Test 3: B can reach internet (if enabled)
podman exec container-b ping -c 1 8.8.8.8
# Expected: SUCCESS (if external network has NAT)

# View container-b's network connections
podman exec container-b ip addr show

# Cleanup
podman stop container-a container-b
podman network rm isolated external
```

#### Alternative: Network Isolation with iptables

```bash
# Create a custom network without NAT (advanced)
podman network create --driver bridge \
  --opt "com.docker.network.bridge.name"=br_custom \
  --opt "com.docker.network.bridge.enable_ip_masquerade"=false \
  custom-isolated

# This prevents outgoing traffic but allows internal communication
```

### 4.2 Network Topology Diagram

```
┌─────────────────────────────────────────────────┐
│                  HOST                            │
├─────────────────────────────────────────────────┤
│                                                   │
│  ┌──────────────────────────────────────────┐   │
│  │  Network: "isolated"                      │   │
│  │  ┌──────────────┐    ┌──────────────┐   │   │
│  │  │ Container A  │───→│ Container B  │   │   │
│  │  │ (isolated)   │    │ (isolated)   │   │   │
│  │  └──────────────┘    └──────┬───────┘   │   │
│  └──────────────────────────────┼───────────┘   │
│                                 │                 │
│  ┌──────────────────────────────┼───────────┐   │
│  │  Network: "external"         │           │   │
│  │  ┌──────────────┐         ┌──┴────────┐ │   │
│  │  │ (empty)      │         │ Container │ │   │
│  │  │              │         │     B     │ │   │
│  │  └──────────────┘         └────┬──────┘ │   │
│  │                                │         │   │
│  └────────────────────────────────┼─────────┘   │
│                                   ↓              │
│                            [NAT/iptables]        │
│                                   ↓              │
└───────────────────────────────────┼──────────────┘
                                    │
                              ┌─────┴──────┐
                              │  Internet   │
                              │ (8.8.8.8)   │
                              └─────────────┘
```

---

## Part 5: Practical Examples

### 5.1 Complete HTTP Service Test

```bash
#!/bin/bash
# Script to test full HTTP communication chain

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}1. Creating network...${NC}"
podman network create test-http

echo -e "${BLUE}2. Starting backend service...${NC}"
podman run --rm -d --name backend \
  --net test-http \
  node:10 node -e "
  const server = require('http').createServer((req, res) => {
    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({
      message: 'Hello from backend',
      timestamp: new Date().toISOString(),
      hostname: require('os').hostname()
    }));
  });
  server.listen(8080, () => {
    console.log('Backend listening on port 8080');
  });
  "

sleep 2

echo -e "${BLUE}3. Testing frontend → backend communication...${NC}"
podman run --rm --net test-http \
  node:10 node -e "
  require('http').get('http://backend:8080/', (res) => {
    let data = '';
    res.on('data', d => { data += d; });
    res.on('end', () => {
      console.log('${GREEN}✓ Received:${NC}', data);
    });
  }).on('error', (e) => {
    console.error('${RED}✗ Error:${NC}', e.message);
  });
  "

echo -e "${BLUE}4. Stopping services...${NC}"
podman stop backend
podman network rm test-http

echo -e "${GREEN}✓ Test completed successfully${NC}"
```

---

## Troubleshooting

### Container Can't Reach Another Container

**Cause:** Different networks or DNS resolution issue

**Solution:**
```bash
# Verify both containers are on the same network
podman network inspect network_name

# Check DNS resolution inside container
podman exec container_name nslookup other_container_name
podman exec container_name getent hosts other_container_name
```

### Port Already in Use

```bash
# Find process using the port
sudo lsof -i :port_number
# or
sudo netstat -tuln | grep port_number

# Kill the process or use a different port
```

### Podman Daemon Issues

```bash
# Restart podman service
sudo systemctl restart podman

# For rootless podman
systemctl --user restart podman

# Check logs
journalctl -xe -u podman
```

---

## Performance Notes

| Operation | Time | Notes |
|-----------|------|-------|
| Image Pull (first time) | 2-5 min | Depends on image size and internet |
| Image Pull (cached) | <1 sec | Already available locally |
| Container Start | 0.1-0.5 sec | Very fast with host/bridge |
| Container Startup Script | 0.2-1 sec | Node runtime initialization |
| Inter-container HTTP call | 1-5 ms | Same network, local DNS resolution |
| Host→Container TCP call | 5-10 ms | Bridge mode with NAT translation |

---

## Summary of Key Findings

### iptables Behavior
- **Host network** (`--net=host`): Zero iptables modifications
- **Bridge network** (default): Adds rules for port mapping and masquerading

### Port Tunneling
- Bridge mode maps host ports to container ports via iptables PREROUTING/POSTROUTING rules
- Host network bypasses this entirely (direct port binding)

### Container Communication
- Same network: Direct via container DNS names
- Different networks: Requires multi-network attachment
- Can be restricted via network attachment policies

### Network Isolation
- Multiple networks with selective attachment provides isolation
- iptables rules can prevent inter-network traffic
- NAT can be disabled for fully isolated networks

---

## References

- [Podman Networking Documentation](https://docs.podman.io/en/latest/markdown/podman-network.1.html)
- [Podman Run Port Binding](https://docs.podman.io/en/latest/markdown/podman-run.1.html#port-p)
- Linux iptables concepts and NAT
