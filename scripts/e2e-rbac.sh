#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
base=http://127.0.0.1:18080
server_pid=""
sandbox_id=""
cohort_id=""

auth() { printf 'Authorization: Bearer %s' "$1"; }
fail() { echo "e2e-rbac: $*" >&2; exit 1; }
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
  if [[ -n "$sandbox_id" ]]; then
    curl -sS -X DELETE -H "$(auth tok-admin)" "$base/v1/citadels/$sandbox_id" >/dev/null 2>&1 || true
  fi
  if [[ -n "$server_pid" ]]; then kill "$server_pid" >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

command -v docker >/dev/null || fail "docker is required"
command -v jq >/dev/null || fail "jq is required"

mkdir -p "$work/charters" "$work/state"
cat >"$work/charters/role.toml" <<'EOF'
[host]
type = "container"
image = "debian:stable-slim"
workdir = "/workspace"

[[policy]]
tool = "shell"
match = "*"
verdict = "allow"
EOF
cat >"$work/charters/missing-secret.toml" <<'EOF'
[host]
type = "container"
image = "debian:stable-slim"
workdir = "/workspace"

[[env]]
name = "REQUIRED_SECRET"
op = "env://RUNEWARD_E2E_INTENTIONALLY_MISSING"
EOF
cat >"$work/authz.json" <<'EOF'
{"principals":[
  {"name":"admin","token":"tok-admin","admin":true},
  {"name":"developer","tenant":"team-a","token":"tok-dev","allowed_profiles":["role"]},
  {"name":"operator","tenant":"team-a","token":"tok-ops","allowed_profiles":["role"]},
  {"name":"approver","tenant":"team-a","token":"tok-approver","allowed_profiles":["role"],"can_approve":true,"approval_profiles":["role"]},
  {"name":"reviewer","tenant":"team-a","token":"tok-reviewer","can_approve":true,"approval_profiles":["role"]},
  {"name":"locked","tenant":"team-b","token":"tok-locked"}
]}
EOF
chmod 600 "$work/authz.json"

binary=${RUNEWARD_E2E_BINARY:-$repo_root/runeward-e2e}
if [[ ! -x "$binary" ]]; then
  (cd "$repo_root" && cargo build --release --locked -p runeward-cli --bin runeward \
    && cp target/release/runeward "$binary")
fi

RUNEWARD_AUTHZ_FILE="$work/authz.json" RUNEWARD_STATE_DIR="$work/state" \
  "$binary" --config-dir "$work/charters" serve --bind 127.0.0.1 --port 18080 --no-ui >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 40); do
  curl -fsS "$base/healthz" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "$base/healthz" >/dev/null || fail "server did not become healthy: $(cat "$work/server.log")"

expect_status 401 invalid GET /v1/whoami
for pair in tok-admin:admin tok-dev:developer tok-ops:operator tok-approver:approver tok-reviewer:reviewer tok-locked:locked; do
  token=${pair%%:*}; name=${pair#*:}
  expect_status 200 "$token" GET /v1/whoami
  [[ $(jq -r '.principal.name' "$work/response.json") == "$name" ]] || fail "wrong identity for $name"
done

expect_status 200 tok-dev GET /v1/charters
[[ $(jq -r '[.profiles[].name] == ["role"]' "$work/response.json") == true ]] || fail "developer Charter scope leaked"
expect_status 200 tok-reviewer GET /v1/charters
[[ $(jq '.profiles | length' "$work/response.json") == 0 ]] || fail "reviewer-only role can launch"
expect_status 200 tok-admin GET '/v1/readiness?profile=missing-secret'
[[ $(jq -r '.ready == false and any(.checks[]; .name == "secrets" and .status == "fail")' "$work/response.json") == true ]] || fail "missing secret readiness false-positive"

expect_status 201 tok-dev POST /v1/citadels '{"profile":"role"}'
sandbox_id=$(jq -r '.id' "$work/response.json")
[[ -n "$sandbox_id" && "$sandbox_id" != null ]] || fail "sandbox id missing"
expect_status 200 tok-ops GET "/v1/citadels/$sandbox_id"
expect_status 404 tok-locked GET "/v1/citadels/$sandbox_id"
expect_status 403 tok-reviewer POST /v1/citadels '{"profile":"role"}'
expect_status 200 tok-dev POST "/v1/citadels/$sandbox_id/shell/exec" '{"command":["printf","role-ok"]}'
[[ $(jq -r '.stdout' "$work/response.json") == role-ok ]] || fail "governed shell failed"
expect_status 400 tok-dev POST "/v1/citadels/$sandbox_id/code/python" '{"code":"print(1)"}'
grep -q 'not declared by this Charter' "$work/response.json" || fail "missing capability error is not actionable"

expect_status 201 tok-dev POST /v1/cohorts '{"profile":"role"}'
cohort_id=$(jq -r '.id' "$work/response.json")
expect_status 201 tok-dev POST "/v1/cohorts/$cohort_id/tasks" '{"payload":"verify role automation"}'
expect_status 200 tok-ops POST "/v1/cohorts/$cohort_id/claim" '{"owner":"forged-client-name"}'
[[ $(jq -r '.task.owner' "$work/response.json") == operator ]] || fail "claim owner did not use authenticated actor"
task_id=$(jq -r '.task.id' "$work/response.json")
lease=$(jq -r '.task.lease_token' "$work/response.json")
expect_status 200 tok-ops POST "/v1/cohorts/$cohort_id/tasks/$task_id/complete" "{\"owner\":\"operator\",\"lease_token\":\"$lease\",\"result\":\"ok\"}"
expect_status 200 tok-dev GET "/v1/cohorts/$cohort_id/tasks"
[[ $(jq -r --arg id "$task_id" '.tasks[] | select(.id == $id) | .state' "$work/response.json") == done ]] || fail "cohort completion did not persist"

echo "e2e-rbac: six roles, tenant isolation, readiness, governed actions, capabilities, and cohorts passed"
