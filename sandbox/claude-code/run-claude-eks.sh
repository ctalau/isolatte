#!/usr/bin/env bash
# Run Claude Code in a privileged pod on the EKS staging cluster.
#
# Mirrors the Docker flags in run-claude.sh:
#   SYS_ADMIN + SETUID/SETGID capabilities + unconfined seccomp → bwrap works
#
# Usage:
#   ./run-claude-eks.sh [claude args...]
#   ./run-claude-eks.sh --build   # push a fresh image to ECR first
#
# Environment variables:
#   ANTHROPIC_API_KEY  (required) — your Anthropic API key
#   GIT_REPO           (optional) — git URL cloned into /workspace on startup
#   AWS_PROFILE        (optional) — AWS profile (default: dev-terraform)
#   NAMESPACE          (optional) — Kubernetes namespace (default: claude-code)
#   ECR_REPO           (optional) — ECR image URI (default: staging account)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AWS_PROFILE="${AWS_PROFILE:-dev-terraform}"
AWS_REGION="ca-central-1"
ACCOUNT_ID="033737991781"
ECR_REPO="${ECR_REPO:-${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/claude-code-sandbox}"
NAMESPACE="${NAMESPACE:-claude-code}"
POD_NAME="claude-code-${USER:-user}-$$"

if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo "Error: ANTHROPIC_API_KEY is not set." >&2
  echo "  export ANTHROPIC_API_KEY=sk-ant-..." >&2
  exit 1
fi

# ── Build & push ────────────────────────────────────────────────────────────

build_and_push() {
  echo "Building Claude Code Docker image..."
  docker build -t claude-code-sandbox "$SCRIPT_DIR"

  echo "Authenticating to ECR..."
  AWS_PROFILE="$AWS_PROFILE" aws ecr get-login-password --region "$AWS_REGION" \
    | docker login --username AWS --password-stdin \
        "${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

  # Create the ECR repo if this is the first push
  AWS_PROFILE="$AWS_PROFILE" aws ecr describe-repositories \
      --region "$AWS_REGION" --repository-names claude-code-sandbox &>/dev/null \
    || AWS_PROFILE="$AWS_PROFILE" aws ecr create-repository \
         --region "$AWS_REGION" --repository-name claude-code-sandbox \
         --image-scanning-configuration scanOnPush=true \
         --encryption-configuration encryptionType=AES256

  docker tag claude-code-sandbox "$ECR_REPO"
  docker push "$ECR_REPO"
}

if [[ "${1:-}" == "--build" ]]; then
  build_and_push
  shift
fi

# ── kubectl context ─────────────────────────────────────────────────────────

echo "Configuring kubectl for EKS staging..."
AWS_PROFILE="$AWS_PROFILE" aws eks update-kubeconfig \
  --name content-fusion-cloud-staging --region "$AWS_REGION"

# ── Namespace with privileged PSA label ─────────────────────────────────────
# The bwrap sandbox needs SYS_ADMIN; Pod Security Admission must allow it.

if ! kubectl get namespace "$NAMESPACE" &>/dev/null; then
  kubectl create namespace "$NAMESPACE"
fi
kubectl label namespace "$NAMESPACE" \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/warn=privileged \
  --overwrite

# ── Build the entrypoint args ────────────────────────────────────────────────
# Pass remaining CLI args to claude; if GIT_REPO is set, clone it first via
# an init container so the workspace is ready when claude starts.

CLAUDE_ARGS_JSON="$(printf '%s\n' "$@" | jq -R . | jq -sc .)"

# ── Pod manifest ─────────────────────────────────────────────────────────────

INIT_CONTAINERS="[]"
WORKSPACE_VOLUME='{"name":"workspace","emptyDir":{}}'

if [[ -n "${GIT_REPO:-}" ]]; then
  INIT_CONTAINERS="$(cat <<INIT
[{
  "name": "git-clone",
  "image": "alpine/git",
  "command": ["git", "clone", "${GIT_REPO}", "/workspace"],
  "volumeMounts": [{"name": "workspace", "mountPath": "/workspace"}]
}]
INIT
)"
fi

POD_MANIFEST="$(cat <<EOF
{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "${POD_NAME}",
    "namespace": "${NAMESPACE}",
    "labels": {"app": "claude-code", "user": "${USER:-user}"}
  },
  "spec": {
    "restartPolicy": "Never",
    "initContainers": ${INIT_CONTAINERS},
    "containers": [{
      "name": "claude",
      "image": "${ECR_REPO}",
      "stdin": true,
      "tty": true,
      "args": ${CLAUDE_ARGS_JSON},
      "env": [
        {"name": "ANTHROPIC_API_KEY", "value": "${ANTHROPIC_API_KEY}"}
      ],
      "volumeMounts": [
        {"name": "workspace", "mountPath": "/workspace"}
      ],
      "securityContext": {
        "runAsUser": 0,
        "allowPrivilegeEscalation": true,
        "capabilities": {
          "add": ["SYS_ADMIN", "SETUID", "SETGID"]
        },
        "seccompProfile": {"type": "Unconfined"}
      }
    }],
    "volumes": [${WORKSPACE_VOLUME}]
  }
}
EOF
)"

# ── Launch and attach ────────────────────────────────────────────────────────

cleanup() {
  echo ""
  echo "Deleting pod ${POD_NAME}..."
  kubectl delete pod "$POD_NAME" -n "$NAMESPACE" --ignore-not-found &>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "Creating pod '${POD_NAME}' in namespace '${NAMESPACE}'..."
echo "$POD_MANIFEST" | kubectl apply -f -

echo "Waiting for pod to be running..."
kubectl wait pod "$POD_NAME" -n "$NAMESPACE" \
  --for=condition=Ready --timeout=120s

echo "Attaching to pod..."
kubectl attach -it "$POD_NAME" -n "$NAMESPACE" -c claude
