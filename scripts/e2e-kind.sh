#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/runeward-kind-e2e.XXXXXX")
base=http://127.0.0.1:18081
context=${RUNEWARD_KUBE_CONTEXT:-$(kubectl config current-context)}
namespace=${RUNEWARD_K8S_NAMESPACE:-runeward-e2e-kind}
binary=${RUNEWARD_E2E_BINARY:-$repo_root/bin/runeward}
server_pid=""
cohort_id=""
namespace_created=false

auth() { printf 'Authorization: Bearer %s' "$1"; }
fail() { echo "e2e-kind: $*" >&2; exit 1; }
expect_status() {
  local want=$1 token=$2 method=$3 path=$4 body=${5-}
  local got
  local args=(-sS -o "$work/response.json" -w '%{http_code}' -X "$method" -H "$(auth "$token")" -H 'Content-Type: application/json')
  if [[ -n "$body" ]]; then args+=(--data "$body"); fi
  got=$(curl "${args[@]}" "$base$path")
  [[ "$got" == "$want" ]] || fail "$method $path returned $got, expected $want: $(cat "$work/response.json")"
}
cleanup() {
  if [[ -n "$cohort_id" ]]; then
    curl -sS -X DELETE -H "$(auth tok-admin)" "$base/v1/cohorts/$cohort_id" >/dev/null 2>&1 || true
  fi
  if [[ -n "$server_pid" ]]; then kill "$server_pid" >/dev/null 2>&1 || true; fi
  if [[ "$namespace_created" == true ]]; then
    kubectl --context "$context" delete namespace "$namespace" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

command -v kubectl >/dev/null || fail "kubectl is required"
command -v jq >/dev/null || fail "jq is required"
[[ "$context" == kind-* ]] || fail "context $context is not a kind context; set RUNEWARD_KUBE_CONTEXT=kind-<name>"
kubectl --context "$context" get nodes >/dev/null || fail "cannot reach Kubernetes context $context"
if kubectl --context "$context" get namespace "$namespace" >/dev/null 2>&1; then
  fail "namespace $namespace already exists; set RUNEWARD_K8S_NAMESPACE to a fresh test namespace"
fi

mkdir -p "$work/charters" "$work/state"
cat >"$work/charters/kind-cohort.toml" <<'EOF'
[host]
type = "k8s"
image = "debian:stable-slim"
workdir = "/workspace"

[cohort]
replicas = 2
task_board = ["worker one", "worker two"]

[[policy]]
tool = "shell"
match = "*"
verdict = "allow"
EOF
cat >"$work/authz.json" <<'EOF'
{"principals":[
  {"name":"admin","tenant":"platform-admin","token":"tok-admin","admin":true},
  {"name":"developer","tenant":"team-alpha","token":"tok-dev","allowed_profiles":["kind-cohort"]},
  {"name":"operator","tenant":"team-alpha","token":"tok-ops","allowed_profiles":["kind-cohort"]},
  {"name":"outsider","tenant":"team-beta","token":"tok-locked","allowed_profiles":[]}
]}
EOF
chmod 600 "$work/authz.json"

if [[ ! -x "$binary" ]]; then
  (cd "$repo_root" && cargo build --release --locked -p runeward-cli --bin runeward \
    && cp target/release/runeward "$binary")
fi

RUNEWARD_AUTHZ_FILE="$work/authz.json" \
RUNEWARD_STATE_DIR="$work/state" \
RUNEWARD_KUBE_CONTEXT="$context" \
RUNEWARD_K8S_NAMESPACE="$namespace" \
  "$binary" --config-dir "$work/charters" serve --bind 127.0.0.1 --port 18081 --no-ui >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 40); do
  curl -fsS "$base/healthz" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "$base/healthz" >/dev/null || fail "server did not become healthy: $(cat "$work/server.log")"

expect_status 201 tok-dev POST /v1/cohorts '{"profile":"kind-cohort"}'
cohort_id=$(jq -r '.id' "$work/response.json")
[[ -n "$cohort_id" && "$cohort_id" != null ]] || fail "Cohort id missing"
namespace_created=true
[[ $(jq '.sandboxes | length' "$work/response.json") == 2 ]] || fail "expected two Kubernetes workers"
sandboxes=()
while IFS= read -r sandbox; do sandboxes+=("$sandbox"); done \
  < <(jq -r '.sandboxes[]' "$work/response.json")
[[ ${#sandboxes[@]} == 2 ]] || fail "expected two sandbox ids"

expect_status 200 tok-ops GET "/v1/cohorts/$cohort_id"
expect_status 404 tok-locked GET "/v1/cohorts/$cohort_id"

expect_status 200 tok-dev POST "/v1/citadels/${sandboxes[0]}/shell/exec" '{"command":["printf","kind-worker-one"]}'
[[ $(jq -r '.stdout' "$work/response.json") == kind-worker-one ]] || fail "first Kubernetes worker exec failed"
expect_status 200 tok-ops POST "/v1/citadels/${sandboxes[1]}/shell/exec" '{"command":["printf","kind-worker-two"]}'
[[ $(jq -r '.stdout' "$work/response.json") == kind-worker-two ]] || fail "second Kubernetes worker exec failed"

expect_status 200 tok-dev POST "/v1/cohorts/$cohort_id/claim" '{}'
task_one=$(jq -r '.task.id' "$work/response.json")
lease_one=$(jq -r '.task.lease_token' "$work/response.json")
owner_one=$(jq -r '.task.owner' "$work/response.json")
[[ "$owner_one" == developer ]] || fail "first claim owner was $owner_one, expected developer"

expect_status 200 tok-ops POST "/v1/cohorts/$cohort_id/claim" '{}'
task_two=$(jq -r '.task.id' "$work/response.json")
lease_two=$(jq -r '.task.lease_token' "$work/response.json")
owner_two=$(jq -r '.task.owner' "$work/response.json")
[[ "$owner_two" == operator ]] || fail "second claim owner was $owner_two, expected operator"

complete_one=$(jq -n --arg owner "$owner_one" --arg lease "$lease_one" '{owner:$owner,lease_token:$lease,result:"worker one done"}')
complete_two=$(jq -n --arg owner "$owner_two" --arg lease "$lease_two" '{owner:$owner,lease_token:$lease,result:"worker two done"}')
expect_status 200 tok-dev POST "/v1/cohorts/$cohort_id/tasks/$task_one/complete" "$complete_one"
expect_status 401 tok-ops POST "/v1/cohorts/$cohort_id/tasks/$task_two/complete" "$complete_one"
expect_status 200 tok-ops POST "/v1/cohorts/$cohort_id/tasks/$task_two/complete" "$complete_two"

expect_status 200 tok-dev GET "/v1/cohorts/$cohort_id/tasks"
[[ $(jq '[.tasks[] | select(.state == "done")] | length' "$work/response.json") == 2 ]] || fail "both tasks did not complete"

pod_count=$(kubectl --context "$context" -n "$namespace" get pods -l runeward.profile=kind-cohort -o json | jq '.items | length')
pvc_count=$(kubectl --context "$context" -n "$namespace" get pvc -l runeward.profile=kind-cohort -o json | jq '.items | length')
[[ "$pod_count" == 2 ]] || fail "expected two worker Pods, found $pod_count"
[[ "$pvc_count" == 2 ]] || fail "expected two worker PVCs, found $pvc_count"

expect_status 200 tok-admin DELETE "/v1/cohorts/$cohort_id"
cohort_id=""

echo "e2e-kind: two Kubernetes workers, shared-tenant identities, isolation, exec, signed leases, replay denial, and cleanup passed"
