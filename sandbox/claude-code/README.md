# Claude Code in Docker (dev-box)

Runs [Claude Code](https://claude.ai/code) inside a Docker container on the dev-box with the bubblewrap (`bwrap`) sandbox fully enabled.

## Quick start

SSH into the dev-box, then:

```bash
export ANTHROPIC_API_KEY=sk-ant-...

# Point at whatever repo you want Claude to work in
WORKSPACE=/workspace/my-project \
  /workspace/webreviewer-vagrant/tools/claude-code/run-claude.sh
```

The image is built automatically on first run. Subsequent runs start instantly.

## Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Image definition: Node 22 slim + bubblewrap + git + Claude Code |
| `run-claude.sh` | Launcher: builds if needed, then runs with the correct Docker flags |

## Options

```bash
# Force a rebuild of the image (e.g. after a Claude Code version bump)
/workspace/webreviewer-vagrant/tools/claude-code/run-claude.sh --build

# Default workspace is the current directory
cd /workspace/webreviewer-vagrant
/workspace/webreviewer-vagrant/tools/claude-code/run-claude.sh
```

### Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | Yes | — | Your Anthropic API key (`sk-ant-...`) |
| `WORKSPACE` | No | `$PWD` | Host path mounted as `/workspace` inside the container |

## How the bubblewrap sandbox works

Claude Code uses `bwrap` to wrap every subprocess it spawns (bash commands, tool calls, etc.) in a mount-namespace sandbox. This scrubs inherited environment variables and isolates the subprocess filesystem from the Claude Code process itself.

On a plain Docker container this fails because the default seccomp profile and AppArmor policy block the syscalls that `bwrap` needs (`clone(CLONE_NEWNS)`, `mount`, etc.). Running as a non-root user inside the container makes it worse — Linux only grants effective capabilities to uid 0.

### What was needed to make it work

Three things were required in combination:

| Docker flag | Why |
|-------------|-----|
| `--cap-add SYS_ADMIN` | Allows root to mount `/proc` inside the bwrap namespace |
| `--cap-add SETUID` `--cap-add SETGID` | Allows bwrap to set up uid/gid mappings in the new namespace |
| `--security-opt seccomp=unconfined` | Removes the default seccomp filter that blocks namespace-related syscalls |
| `--security-opt apparmor=unconfined` | Removes the AppArmor policy that also restricts `mount` and `clone` |

The container runs as **root** (uid 0). This is necessary because Docker only makes granted capabilities effective for the root user. A non-root user would hold the capabilities in the *permitted* set but not the *effective* set, so `bwrap`'s `mount /proc` call still fails with `EPERM`.

Running as root inside Docker is acceptable here because:
- The Vagrant VM itself is the outer isolation boundary.
- Docker's namespacing prevents the container root from escaping to the host.
- This is a local dev environment, not a multi-tenant system.

### Host kernel requirements

The dev-box kernel must have unprivileged user namespace creation enabled:

```
/proc/sys/kernel/unprivileged_userns_clone = 1   ✓ (confirmed on this host)
/proc/sys/user/max_user_namespaces > 0            ✓ (31585 on this host)
```

---

## Running on EKS staging

`run-claude-eks.sh` is the EKS equivalent of `run-claude.sh`. It pushes the same
Docker image to ECR and launches an interactive pod with the same privileged
security context that bwrap needs.

### Quick start

```bash
export ANTHROPIC_API_KEY=sk-ant-...

# Optional: clone a repo into /workspace before claude starts
export GIT_REPO=git@github.com:your-org/your-repo.git

/workspace/webreviewer-vagrant/tools/claude-code/run-claude-eks.sh
```

On first run, pass `--build` to push the image to ECR:

```bash
/workspace/webreviewer-vagrant/tools/claude-code/run-claude-eks.sh --build
```

The script:
1. Configures `kubectl` against `content-fusion-cloud-staging` using `AWS_PROFILE=dev-terraform`.
2. Creates a `claude-code` namespace labelled `pod-security.kubernetes.io/enforce=privileged` so the pod is not rejected by Pod Security Admission.
3. Creates an ephemeral pod with the same capabilities as the Docker run (`SYS_ADMIN`, `SETUID`, `SETGID`, seccomp `Unconfined`, root UID).
4. Attaches interactively; deletes the pod on exit.

### Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | Yes | — | Your Anthropic API key |
| `GIT_REPO` | No | — | Git URL cloned into `/workspace` via init container |
| `AWS_PROFILE` | No | `dev-terraform` | AWS CLI profile |
| `NAMESPACE` | No | `claude-code` | Kubernetes namespace |
| `ECR_REPO` | No | `033737991781.dkr.ecr.ca-central-1.amazonaws.com/claude-code-sandbox` | ECR image URI |

### Why no AppArmor flag?

EKS nodes run Amazon Linux 2023, which ships without AppArmor. The Docker
`--security-opt apparmor=unconfined` flag has no equivalent annotation here
because there is nothing to disable.

### Workspace

There is no local filesystem to mount on EKS. Set `GIT_REPO` to have the script
clone your repo into `/workspace` via an init container before claude starts.
Without it, `/workspace` starts empty — clone manually once inside the pod.

---

## Rebuilding the image

```bash
ssh cf-devbox "docker build -t claude-code-sandbox /workspace/webreviewer-vagrant/tools/claude-code/"
```

Or use the `--build` flag on `run-claude.sh` which does the same thing.

## Troubleshooting

**`bwrap: Creating new namespace failed: Operation not permitted`**
The seccomp or AppArmor flags are missing from the `docker run` command. Use `run-claude.sh` which includes them.

**`bwrap: Can't mount proc on /newroot/proc: Operation not permitted`**
The container is running as a non-root user. The image runs as root by default; don't override with `--user`.

**`ANTHROPIC_API_KEY is not set`**
Export the variable before calling the script:
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

**Image not found / `docker image inspect` fails**
Run with `--build` to force a fresh build:
```bash
/workspace/webreviewer-vagrant/tools/claude-code/run-claude.sh --build
```
