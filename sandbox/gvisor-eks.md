# gVisor inside a privileged Kubernetes pod on EKS (staging)

Runs a Node.js script inside a gVisor sandbox, which itself runs inside a
privileged Kubernetes pod on the Content Fusion staging EKS cluster.

```
EKS node  (t3a.medium, Amazon Linux, ca-central-1)
  └── Kubernetes privileged pod  (Ubuntu 22.04)
        └── gVisor sandbox  (synthetic kernel 4.19.0-gvisor, systrap mode)
              └── Node.js process
```

## Prerequisites

- AWS CLI configured with the `dev` profile (account `033737991781`, region `ca-central-1`)
- `kubectl` installed
- EKS cluster: `content-fusion-cloud-staging`

See `content-fusion-cloud/docs/onboarding/aws-access.md` for AWS access setup.

## One-time cluster setup

### 1. Connect to the EKS cluster

```bash
aws --profile dev eks update-kubeconfig \
  --name content-fusion-cloud-staging \
  --region ca-central-1
```

### 2. Scale up the node group (if at zero)

The staging node group (`content-fusion-cloud-staging-ng-workload`) is scaled to
`desiredSize: 0` when idle to save cost. Scale it up before proceeding:

```bash
aws --profile dev eks update-nodegroup-config \
  --cluster-name content-fusion-cloud-staging \
  --nodegroup-name content-fusion-cloud-staging-ng-workload \
  --region ca-central-1 \
  --scaling-config minSize=0,maxSize=2,desiredSize=1
```

Wait for a node to become Ready:

```bash
kubectl get nodes -w
```

If the node appears as `Ready,SchedulingDisabled`, uncordon it:

```bash
kubectl uncordon <node-name>
```

### 3. Capacity note

The `t3a.medium` node (2 vCPU, 4 GB RAM) fills up quickly when all staging
workloads are scheduled. The gVisor setup requires roughly 512 MB free. If the
node is >90% memory-requested, stop the non-essential staging pods first, or
scale to 2 nodes temporarily.

### 4. Start a privileged Ubuntu pod

```bash
kubectl run gvisor-sandbox \
  --image=ubuntu:22.04 \
  --restart=Never \
  --overrides='{
    "spec": {
      "containers": [{
        "name": "gvisor-sandbox",
        "image": "ubuntu:22.04",
        "command": ["sleep", "infinity"],
        "securityContext": {
          "privileged": true
        },
        "resources": {
          "requests": {"memory": "512Mi", "cpu": "250m"},
          "limits":   {"memory": "2Gi",   "cpu": "1000m"}
        }
      }]
    }
  }'
```

Wait for it to reach Running:

```bash
kubectl get pod gvisor-sandbox -w
```

### 5. Install gVisor (runsc) and Node.js inside the pod

```bash
# Base packages
kubectl exec gvisor-sandbox -- bash -c '
  apt-get update -qq
  apt-get install -y curl gnupg ca-certificates
'

# Add gVisor apt repository and install runsc
kubectl exec gvisor-sandbox -- bash -c '
  curl -fsSL https://gvisor.dev/archive.key \
    | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg

  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] \
    https://storage.googleapis.com/gvisor/releases release main" \
    > /etc/apt/sources.list.d/gvisor.list

  apt-get update -qq
  apt-get install -y runsc
'

# Node.js
kubectl exec gvisor-sandbox -- apt-get install -y nodejs
```

## Running a Node.js script under gVisor

```bash
kubectl exec gvisor-sandbox -- \
  runsc --platform=systrap \
  do node -e "console.log('Hello from gVisor:', process.version)"
```

To run a script file:

```bash
kubectl cp my-script.js gvisor-sandbox:/tmp/my-script.js
kubectl exec gvisor-sandbox -- \
  runsc --platform=systrap \
  do node /tmp/my-script.js
```

Verify the process is running inside gVisor (should print `4.19.0-gvisor`):

```bash
kubectl exec gvisor-sandbox -- \
  runsc --platform=systrap \
  do cat /proc/version
```

## Tearing down

Delete the pod when done:

```bash
kubectl delete pod gvisor-sandbox
```

Scale the node group back to zero to stop incurring EC2 costs:

```bash
aws --profile dev eks update-nodegroup-config \
  --cluster-name content-fusion-cloud-staging \
  --nodegroup-name content-fusion-cloud-staging-ng-workload \
  --region ca-central-1 \
  --scaling-config minSize=0,maxSize=2,desiredSize=0
```

## Differences from the Docker/VirtualBox setup

See `gvisor-in-docker.md` for the equivalent setup on the local dev-box.

| Aspect | Docker on dev-box | Kubernetes on EKS |
|---|---|---|
| Outer runtime | `docker run --privileged` | `kubectl run` with `securityContext.privileged: true` |
| Node type | VirtualBox VM | EC2 `t3a.medium` |
| Image | `ubuntu:22.04` container | Same |
| gVisor flags | `--platform=ptrace --network=none --ignore-cgroups` | `--platform=systrap` (no extra flags needed) |
| Persistence | Manual `docker cp` | `kubectl cp` or a PVC |
| Cost | Free (local VM) | EC2 on-demand charges while node is running |

On EKS, `systrap` works without `--network=none` or `--ignore-cgroups` because
the pod runs on a real Linux node (not nested inside VirtualBox), so gVisor can
create cgroups and network interfaces normally. `systrap` is also faster than
`ptrace` — it uses a seccomp-based trap rather than the ptrace API, and does not
require `CAP_SYS_PTRACE`.
