#!/usr/bin/env bash
# setup-jenkins.sh — Reproduce the Jenkins udocker test environment
#
# What this does:
#   1. Creates two local git repos (/tmp/repo-alpha, /tmp/repo-beta)
#   2. Pulls the Jenkins LTS image via udocker (if not already present)
#   3. Creates and starts a Jenkins container with /tmp/jenkins_home mounted
#   4. Configures the admin user (admin / admin123)
#   5. Creates two freestyle jobs (project-alpha, project-beta)
#      pointing at the local git repos
#   6. Generates an API token for the admin user
#   7. (Optional) Triggers one build of each job
#
# Requirements: udocker, curl, git, python3
# Usage:
#   chmod +x setup-jenkins.sh
#   ./setup-jenkins.sh            # full setup
#   ./setup-jenkins.sh --no-build # skip build triggers
#
# After the script completes:
#   Jenkins UI  : http://localhost:8080
#   Credentials : admin / admin123
#   API token   : printed at the end / saved to /tmp/jenkins_api_token

set -euo pipefail

# ─── Config ────────────────────────────────────────────────────────────────────
JENKINS_IMAGE="jenkins/jenkins:lts-jdk17"
CONTAINER_NAME="jenkins"
JENKINS_HOME="/tmp/jenkins_home"
JENKINS_URL="http://localhost:8080"
ADMIN_USER="admin"
ADMIN_PASS="admin123"
# bcrypt hash of "admin123" — pre-computed so no bcrypt tool is needed
ADMIN_HASH='#jbcrypt:$2a$10$RM.16CMpXE4SMpHvj74OvuwKkk78NmlewgayvEzkb0jbiANJ0ZXsK'
REPO_ALPHA="/tmp/repo-alpha"
REPO_BETA="/tmp/repo-beta"
TRIGGER_BUILDS=true

# Parse args
for arg in "$@"; do
  case $arg in
    --no-build) TRIGGER_BUILDS=false ;;
    -h|--help)
      head -30 "$0" | grep '^#' | sed 's/^# \?//'
      exit 0
      ;;
  esac
done

# ─── Helpers ───────────────────────────────────────────────────────────────────
info()    { echo "[INFO]  $*"; }
warn()    { echo "[WARN]  $*" >&2; }
die()     { echo "[ERROR] $*" >&2; exit 1; }
require() { command -v "$1" &>/dev/null || die "'$1' is required but not found."; }

wait_for_jenkins() {
  local max=120 interval=5 elapsed=0
  info "Waiting for Jenkins to be ready (up to ${max}s)..."
  while true; do
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" "$JENKINS_URL/login" 2>/dev/null || true)
    if [[ "$code" == "200" ]]; then
      info "Jenkins is up."
      return 0
    fi
    sleep "$interval"
    elapsed=$(( elapsed + interval ))
    if (( elapsed >= max )); then
      die "Jenkins did not become ready within ${max}s. Check: udocker --allow-root ps"
    fi
    info "  Still waiting... (${elapsed}s elapsed, HTTP $code)"
  done
}

jenkins_curl() {
  # Wrapper around curl for authenticated Jenkins requests
  local method="${1:-GET}"
  local path="$2"
  shift 2
  curl -s -X "$method" \
       -u "${ADMIN_USER}:${ADMIN_PASS}" \
       "${JENKINS_URL}${path}" \
       "$@"
}

jenkins_curl_token() {
  local method="${1:-GET}"
  local path="$2"
  local token="$3"
  shift 3
  curl -s -X "$method" \
       -u "${ADMIN_USER}:${token}" \
       "${JENKINS_URL}${path}" \
       "$@"
}

get_crumb() {
  local response
  response=$(jenkins_curl GET "/crumbIssuer/api/json")
  CRUMB_FIELD=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['crumbRequestField'])" 2>/dev/null || echo "")
  CRUMB_VALUE=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['crumb'])" 2>/dev/null || echo "")
}

# ─── Step 1: Local git repos ───────────────────────────────────────────────────
setup_repos() {
  info "=== Step 1: Creating local git repos ==="

  # repo-alpha
  if [[ -d "$REPO_ALPHA" ]]; then
    warn "$REPO_ALPHA already exists — skipping."
  else
    mkdir -p "$REPO_ALPHA"
    git -C "$REPO_ALPHA" init -b master
    git -C "$REPO_ALPHA" config user.email "ci@example.com"
    git -C "$REPO_ALPHA" config user.name  "CI Bot"

    cat > "$REPO_ALPHA/Main.java" <<'EOF'
public class Main { public static void main(String[] a) { System.out.println("Alpha"); } }
EOF
    cat > "$REPO_ALPHA/README.md" <<'EOF'
# Project Alpha
EOF
    git -C "$REPO_ALPHA" add .
    git -C "$REPO_ALPHA" commit -m "Initial commit for project-alpha"

    echo "feature A" > "$REPO_ALPHA/feature.txt"
    git -C "$REPO_ALPHA" add feature.txt
    git -C "$REPO_ALPHA" commit -m "Add feature A: isolatte module"

    info "repo-alpha created at $REPO_ALPHA"
  fi

  # repo-beta
  if [[ -d "$REPO_BETA" ]]; then
    warn "$REPO_BETA already exists — skipping."
  else
    mkdir -p "$REPO_BETA"
    git -C "$REPO_BETA" init -b master
    git -C "$REPO_BETA" config user.email "ci@example.com"
    git -C "$REPO_BETA" config user.name  "CI Bot"

    cat > "$REPO_BETA/BetaTest.java" <<'EOF'
public class BetaTest { void test() { assert false; } }
EOF
    cat > "$REPO_BETA/README.md" <<'EOF'
# Project Beta
EOF
    git -C "$REPO_BETA" add .
    git -C "$REPO_BETA" commit -m "Initial commit for project-beta"

    echo "bugfix" > "$REPO_BETA/bugfix.txt"
    git -C "$REPO_BETA" add bugfix.txt
    git -C "$REPO_BETA" commit -m "Fix: resolve NullPointerException in auth module"

    info "repo-beta created at $REPO_BETA"
  fi
}

# ─── Step 2: Jenkins container ────────────────────────────────────────────────
setup_container() {
  info "=== Step 2: Setting up Jenkins container via udocker ==="

  # Pull image if missing
  if ! udocker --allow-root images 2>/dev/null | grep -q "jenkins/jenkins"; then
    info "Pulling $JENKINS_IMAGE ..."
    udocker --allow-root pull "$JENKINS_IMAGE"
  else
    info "Image $JENKINS_IMAGE already present."
  fi

  # Create container if missing
  if ! udocker --allow-root ps 2>/dev/null | grep -q "$CONTAINER_NAME"; then
    info "Creating udocker container '$CONTAINER_NAME' ..."
    udocker --allow-root create --name="$CONTAINER_NAME" "$JENKINS_IMAGE"
  else
    info "Container '$CONTAINER_NAME' already exists."
  fi

  # Set up jenkins_home
  mkdir -p "$JENKINS_HOME"

  # Skip initial setup wizard
  mkdir -p "$JENKINS_HOME/init.groovy.d"
  cat > "$JENKINS_HOME/init.groovy.d/skip-setup.groovy" <<'EOF'
import jenkins.install.InstallState
if (!Jenkins.getInstance().installState.isSetupComplete()) {
  InstallState.INITIAL_SETUP_COMPLETED.initializeState()
}
EOF

  echo "2.0" > "$JENKINS_HOME/jenkins.install.UpgradeWizard.state"
  echo "2.0" > "$JENKINS_HOME/jenkins.install.InstallUtil.lastExecVersion"

  # Start Jenkins in the background (detached-style via &)
  info "Starting Jenkins container..."
  udocker --allow-root run \
    --volume="${JENKINS_HOME}:/var/jenkins_home" \
    --volume="/tmp/repo-alpha:/tmp/repo-alpha" \
    --volume="/tmp/repo-beta:/tmp/repo-beta" \
    --publish=8080:8080 \
    "$CONTAINER_NAME" \
    > /tmp/jenkins.log 2>&1 &

  JENKINS_PID=$!
  echo "$JENKINS_PID" > /tmp/jenkins.pid
  info "Jenkins started (PID $JENKINS_PID), log: /tmp/jenkins.log"

  wait_for_jenkins
}

# ─── Step 3: Configure admin user ─────────────────────────────────────────────
configure_admin() {
  info "=== Step 3: Configuring admin user ==="

  # Find the admin user config directory
  local admin_dir
  admin_dir=$(find "$JENKINS_HOME/users" -name "config.xml" 2>/dev/null | xargs grep -l "admin" 2>/dev/null | head -1 | xargs dirname 2>/dev/null || true)

  if [[ -z "$admin_dir" ]]; then
    # Create user from scratch via Groovy script console
    info "Creating admin user via script console..."
    get_crumb
    jenkins_curl POST "/scriptText" \
      -H "${CRUMB_FIELD}:${CRUMB_VALUE}" \
      --data-urlencode 'script=
import jenkins.model.Jenkins
import hudson.security.*
def instance = Jenkins.getInstance()
def hudsonRealm = new HudsonPrivateSecurityRealm(false)
hudsonRealm.createAccount("admin", "admin123")
instance.setSecurityRealm(hudsonRealm)
def strategy = new FullControlOnceLoggedInAuthorizationStrategy()
strategy.setAllowAnonymousRead(false)
instance.setAuthorizationStrategy(strategy)
instance.save()
println "admin user created"
' > /dev/null
  else
    info "Admin user config found at $admin_dir"
    # Patch in the known password hash
    if ! grep -q 'jbcrypt' "$admin_dir/config.xml"; then
      sed -i "s|<passwordHash>.*</passwordHash>|<passwordHash>${ADMIN_HASH}</passwordHash>|" \
          "$admin_dir/config.xml"
    fi
    info "Reloading Jenkins configuration..."
    get_crumb
    jenkins_curl POST "/reload" -H "${CRUMB_FIELD}:${CRUMB_VALUE}" || true
    sleep 3
  fi

  # Verify credentials work
  local http_code
  http_code=$(curl -s -o /dev/null -w "%{http_code}" -u "${ADMIN_USER}:${ADMIN_PASS}" \
              "${JENKINS_URL}/api/json" 2>/dev/null || echo "000")
  if [[ "$http_code" == "200" ]]; then
    info "Admin credentials verified (HTTP 200)."
  else
    warn "Admin credentials check returned HTTP $http_code — continuing anyway."
  fi
}

# ─── Step 4: Create jobs ───────────────────────────────────────────────────────
job_config_xml() {
  local repo_url="$1"
  local branch="$2"
  cat <<XML
<?xml version="1.1" encoding="UTF-8"?>
<project>
  <description/>
  <keepDependencies>false</keepDependencies>
  <properties/>
  <scm class="hudson.plugins.git.GitSCM" plugin="git@latest">
    <configVersion>2</configVersion>
    <userRemoteConfigs>
      <hudson.plugins.git.UserRemoteConfig>
        <url>${repo_url}</url>
      </hudson.plugins.git.UserRemoteConfig>
    </userRemoteConfigs>
    <branches>
      <hudson.plugins.git.BranchSpec>
        <name>*/${branch}</name>
      </hudson.plugins.git.BranchSpec>
    </branches>
    <doGenerateSubmoduleConfigurations>false</doGenerateSubmoduleConfigurations>
    <submoduleCfg class="empty-list"/>
    <extensions/>
  </scm>
  <canRoam>true</canRoam>
  <disabled>false</disabled>
  <blockBuildWhenDownstreamBuilding>false</blockBuildWhenDownstreamBuilding>
  <blockBuildWhenUpstreamBuilding>false</blockBuildWhenUpstreamBuilding>
  <triggers/>
  <concurrentBuild>false</concurrentBuild>
  <builders>
    <hudson.tasks.Shell>
      <command>echo "Build started"
git log -1 --format="Last commit SHA: %H%nCommit message: %s%nAuthor: %an%nDate: %cd" \
  --date=format:'%Y-%m-%d %H:%M:%S UTC' || echo "no git"
echo "---"
echo "Simulating build failure..."
exit 1</command>
    </hudson.tasks.Shell>
  </builders>
  <publishers/>
  <buildWrappers/>
</project>
XML
}

create_jobs() {
  info "=== Step 4: Creating Jenkins jobs ==="
  get_crumb

  for job_name repo_url branch in \
      "project-alpha" "file:///tmp/repo-alpha" "master" \
      "project-beta"  "file:///tmp/repo-beta"  "master"; do
    # Parse the triplets (bash doesn't support true associative triplets,
    # so we iterate with a helper array)
    true
  done

  # Define jobs as name|url|branch
  local jobs=(
    "project-alpha|file:///tmp/repo-alpha|master"
    "project-beta|file:///tmp/repo-beta|master"
  )

  for job_def in "${jobs[@]}"; do
    local name url branch
    IFS='|' read -r name url branch <<< "$job_def"

    # Check if job already exists
    local exists_code
    exists_code=$(curl -s -o /dev/null -w "%{http_code}" \
                  -u "${ADMIN_USER}:${ADMIN_PASS}" \
                  "${JENKINS_URL}/job/${name}/api/json" 2>/dev/null || echo "000")

    if [[ "$exists_code" == "200" ]]; then
      info "Job '$name' already exists — updating config..."
      job_config_xml "$url" "$branch" | jenkins_curl POST \
        "/job/${name}/config.xml" \
        -H "${CRUMB_FIELD}:${CRUMB_VALUE}" \
        -H "Content-Type: application/xml" \
        --data-binary @- > /dev/null
    else
      info "Creating job '$name' ..."
      job_config_xml "$url" "$branch" | jenkins_curl POST \
        "/createItem?name=${name}" \
        -H "${CRUMB_FIELD}:${CRUMB_VALUE}" \
        -H "Content-Type: application/xml" \
        --data-binary @- > /dev/null
    fi

    info "  $name → $url (branch: $branch)"
  done
}

# ─── Step 5: Generate API token ───────────────────────────────────────────────
generate_token() {
  info "=== Step 5: Generating API token ==="
  get_crumb

  local response
  response=$(jenkins_curl POST \
    "/user/${ADMIN_USER}/descriptorByName/jenkins.security.ApiTokenProperty/generateNewToken" \
    -H "${CRUMB_FIELD}:${CRUMB_VALUE}" \
    --data "newTokenName=setup-token")

  API_TOKEN=$(echo "$response" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d['data']['tokenValue'])" 2>/dev/null || echo "")

  if [[ -n "$API_TOKEN" ]]; then
    echo "$API_TOKEN" > /tmp/jenkins_api_token
    info "API token generated: $API_TOKEN"
    info "Saved to /tmp/jenkins_api_token"
  else
    warn "Could not parse token from response: $response"
    warn "You can generate one manually at: ${JENKINS_URL}/user/admin/configure"
  fi
}

# ─── Step 6: Trigger builds (optional) ────────────────────────────────────────
trigger_builds() {
  info "=== Step 6: Triggering builds ==="
  get_crumb

  for job_name in project-alpha project-beta; do
    info "Triggering build for '$job_name'..."
    jenkins_curl POST "/job/${job_name}/build" \
      -H "${CRUMB_FIELD}:${CRUMB_VALUE}" > /dev/null
    info "  Build queued for $job_name"
  done

  info "Build queue is running. Check status at: ${JENKINS_URL}"
}

# ─── Main ──────────────────────────────────────────────────────────────────────
main() {
  require git
  require curl
  require python3
  require udocker

  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║         Jenkins udocker Environment Setup                   ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""

  setup_repos
  setup_container
  configure_admin
  create_jobs
  generate_token

  if [[ "$TRIGGER_BUILDS" == "true" ]]; then
    trigger_builds
  fi

  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║                  Setup Complete                             ║"
  echo "╠══════════════════════════════════════════════════════════════╣"
  printf  "║  Jenkins UI   : %-44s ║\n" "${JENKINS_URL}"
  printf  "║  Username     : %-44s ║\n" "${ADMIN_USER}"
  printf  "║  Password     : %-44s ║\n" "${ADMIN_PASS}"
  if [[ -n "${API_TOKEN:-}" ]]; then
    printf "║  API Token    : %-44s ║\n" "${API_TOKEN}"
  fi
  printf  "║  Container log: %-44s ║\n" "/tmp/jenkins.log"
  printf  "║  Stop Jenkins : %-44s ║\n" "kill \$(cat /tmp/jenkins.pid)"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  echo "Run the API report:"
  echo "  python3 jenkins_api_report.py"
  echo ""
}

main "$@"
