# Rune Box — end-to-end local testing

## Automated authenticated release gate

CI runs `scripts/e2e-rbac.sh` against a real Docker-backed Rune Box server. It
exercises six roles, Charter scoping, shared-tenant and cross-tenant access,
missing-secret readiness, governed execution, capability errors, authoritative
Cohort ownership, and task completion. Run the same gate locally with:

```bash
cargo build --release --locked -p runeward-cli --bin runeward
cp target/release/runeward runeward-e2e
RUNEWARD_E2E_BINARY="$PWD/runeward-e2e" ./scripts/e2e-rbac.sh
```

The script creates only temporary credentials/state and removes its Citadel and
Cohort. The manual provider/Kubernetes/browser sections below remain required
where CI does not have those external services.

A hands-on walkthrough for exercising the whole stack on your laptop: the
**Docker** and **Kubernetes** backends, deny-by-default and **strict (L3)**
egress, the governed REST API, snapshots, multi-agent Cohorts, and wiring the
**MCP server** into **Claude Desktop**, **Cursor**, and **VS Code**.

It also covers the governance/ops surface added since: the **framework
adapters** (9), offline **CLI tooling** — profile validate/lint, policy
scaffold + unit tests, profile signing, the runtime doctor, session replay
(10) — **API auth & RBAC** (11), **cost/loop guardrails** and the usage API
(12), **secrets injection** (13), **audit sinks** + offline transcript
verification (14), **anomaly detection** (15), **argv-aware policy** and the
**CEL** engine (16), and **observability**: metrics, structured logs, telemetry
(17).

It closes with the latest hardening + governance surface: **deny-by-default
policy** (18), **custom audit scrubbing** (19), **workspace-confined file
tools** (20), the **browser SSRF allowlist** (21), **isolation-preserving
snapshot restore** (22), **profile safety** — footgun lint, exempt-UID guard,
signed-at-load (23), full **RBAC tenant isolation** (24), **short-lived session
tickets** (25), **policy simulation** (26), the **egress explorer + budget
burn-down** (27), the **OTLP/SIEM audit sink** (28), the **Podman backend**
(29), the **BYO-model gateway** profile (30), **SDK transport hardening** (31),
and **build-time supply-chain hardening** (32). Sections 1–8 are the base stack;
9–32 exercise everything added since; 33 cleans up.

Everything below assumes macOS + [OrbStack](https://orbstack.dev) (which gives
you both Docker and a one-click Kubernetes cluster), but any Docker + kubectl
setup works.

---

## 0. Prerequisites


| Tool                                | Why                 | Check               |
| ----------------------------------- | ------------------- | ------------------- |
| Rust ≥ 1.95 (cargo)                 | build the binaries  | `cargo --version`   |
| Docker / OrbStack                   | Docker backend      | `docker info`       |
| Kubernetes (OrbStack/kind/minikube) | K8s backend         | `kubectl get nodes` |
| `curl`, `jq`                        | drive the REST API  | `jq --version`      |
| Node/Python (optional)              | adapter smoke tests | —                   |


Pre-pull the images the example profiles use so the first run is fast:

```bash
docker pull debian:stable-slim
docker pull rancher/mirrored-library-busybox:1.37.0   # egress-demo (has wget)
docker pull curlimages/curl:8.11.0                    # egress-strict (k8s)
```

### Build

```bash
cd /path/to/runeward
cargo build --release --locked -p runeward-cli --bin runeward
mkdir -p bin && cp target/release/runeward bin/runeward
# The k8s egress image builds runeward-egress itself: docker build -f deploy/Dockerfile.egress .

./bin/runeward version
```

### Handy environment variables


| Var                      | Purpose                                           | Default                     |
| ------------------------ | ------------------------------------------------- | --------------------------- |
| `RUNEWARD_CONFIG_DIR`    | pin the profile search dir                        | (unset; use `--config-dir`) |
| `RUNEWARD_STATE_DIR`     | where the audit ledger is written                 | OS cache dir                |
| `RUNEWARD_KUBE_CONTEXT`  | kube-context for the k8s backend                  | current context             |
| `RUNEWARD_K8S_NAMESPACE` | namespace for sandbox pods                        | `runeward`                  |
| `RUNEWARD_EGRESS_IMAGE`  | egress sidecar/init image ref                     | `runeward-egress:latest`    |
| `RUNEWARD_API_TOKEN`     | bearer token for `serve --token` and REST clients | (unset; open local serve)   |
| `GITHUB_TOKEN`           | optional GitHub credential explicitly imported by a Charter | unset |
| `OPENAI_BASE_URL`        | optional OpenAI-compatible gateway explicitly imported by a Charter | provider default |


`gh auth login` authenticates the host CLI but does not automatically expose a
GitHub token to a Citadel. Use `op = "env://GITHUB_TOKEN"` only in Charters that
need GitHub operations. An `OPENAI_BASE_URL` override is also opt-in and its
hostname must be allowed by the Charter's egress policy.

> The **backend is chosen per profile** by `[host].type` (`container` →
> Docker, `kubernetes` → K8s). There is no global backend switch — you pick by
> which profile you run.

Use a scratch state dir so test runs are isolated and easy to wipe:

```bash
export RUNEWARD_STATE_DIR="$(mktemp -d)/runeward-state"
```

The example profiles live in `[examples/](https://github.com/Runeeward/runeward/tree/main/examples)`:


| Profile         | Backend | Demonstrates                                      |
| --------------- | ------- | ------------------------------------------------- |
| `dev`           | Docker  | open profile, interactive shell                   |
| `governed`      | Docker  | policy `deny` + human-in-the-loop approval        |
| `rego`          | Docker  | OPA/Rego policy engine (`policy_engine = "rego"`) |
| `policy-bundle` | Docker  | signed OCI policy bundle (`[policy_bundle]`)      |
| `egress-demo`   | Docker  | deny-by-default egress (cooperative proxy)        |
| `egress-strict` | K8s     | strict L3 egress (iptables + transparent proxy)   |
| `fleet-demo`    | Docker  | multi-agent Cohort + atomic Command Board         |
| `ns-auto`       | Docker  | fully worked autonomous-agent contract            |
| `k8s`           | K8s     | minimal Kubernetes-backed Citadel                 |


---

## 1. CLI smoke test (Docker)

```bash
# Inspect a profile's resolved, secret-redacted contract
./bin/runeward --config-dir examples print ns-auto

# List discoverable profiles
./bin/runeward --config-dir examples list

# Run a one-off command in a throwaway sandbox, then tear it down
./bin/runeward --config-dir examples dev -- uname -a

# Drop into an interactive shell (Ctrl-D to exit + clean up)
./bin/runeward --config-dir examples dev
```

Expected: `uname -a` prints a Linux kernel string (the container's), and the
interactive shell gives you a prompt inside `/workspace`.

---

## 2. Control plane + dashboard (Docker)

Start the governed control plane (REST API + web dashboard on `:8080`). Pick
**one** of the auth modes below — the rest of this guide assumes `$BASE` and
`$AUTH` from 2a.

**Without auth** (default local dev; `serve` logs a warning, no dashboard login):

```bash
./bin/runeward --config-dir examples serve
# => auth=false in the startup log
```

**With auth** (dashboard login + protected API; required for `--bind 0.0.0.0`):

```bash
export RUNEWARD_API_TOKEN=dev-local   # pick any secret; reuse it in the dashboard
./bin/runeward --config-dir examples serve --token "$RUNEWARD_API_TOKEN"
# => auth=true — paste the same token into the dashboard sign-in form
```

Open [http://localhost:8080/](http://localhost:8080/) — you get the dashboard (create a sandbox, live
terminal, files, shell/code, Chronicle timeline, Conclave inbox, and the **Cohorts**
view). Leave `serve` running and drive it from a second terminal.

### 2a. Citadel lifecycle over REST

In a **second terminal**, set the API base URL and auth header (match how you
started `serve` above):

```bash
BASE=http://localhost:8080

# Without auth:
AUTH=()

# With auth (same value as --token / RUNEWARD_API_TOKEN):
# export RUNEWARD_API_TOKEN=dev-local
# AUTH=(-H "Authorization: Bearer $RUNEWARD_API_TOKEN")
```

All `curl` examples use `"${AUTH[@]}"` — leave `AUTH` empty (`AUTH=()`) when
serving without a token. `/healthz` is always open; everything under `/v1`,
`/mcp`, and `/metrics` requires auth when a token is configured.

```bash
# Create a sandbox from the dev profile
SID=$(curl -s "${AUTH[@]}" $BASE/v1/citadels -d '{"profile":"dev"}' | jq -r .id)
echo "sandbox=$SID"

# Run a shell command
curl -s "${AUTH[@]}" $BASE/v1/citadels/$SID/shell/exec \
  -d '{"command":["echo","hello from runeward"]}' | jq

# Run Python (NB: the sandbox image must ship python3 — the `dev` profile's
# debian:stable-slim does not. See the note below to test the code runner.)
curl -s "${AUTH[@]}" $BASE/v1/citadels/$SID/code/python \
  -d '{"code":"print(6*7)"}' | jq '.stdout'

# Write + read a file (read returns content under .content)
curl -s "${AUTH[@]}" $BASE/v1/citadels/$SID/file/write \
  -d '{"path":"note.txt","content":"remember me"}' | jq '.verdict'
curl -s "${AUTH[@]}" $BASE/v1/citadels/$SID/file/read \
  -d '{"path":"note.txt"}' | jq -r '.content'

# List sandboxes (array is under .sandboxes)
curl -s "${AUTH[@]}" $BASE/v1/citadels | jq '.sandboxes[].id'

# Tear down
curl -s "${AUTH[@]}" -X DELETE $BASE/v1/citadels/$SID | jq
```

Every response carries a `verdict` (`allow`/`deny`/`require-approval`),
`exit_code`, `stdout`/`stderr`, and `duration_ms` — when a call fails, pipe
through `| jq` (not `| jq '.stdout'`) so you see the real error body.

> **Sandbox ids are in-memory** — restarting `serve` drops every session, so
> re-create the sandbox and re-capture `$SID` if a call reports `sandbox not found`.

> The Python/code runner shells out to `python3` **inside the sandbox**, so it
> needs a Python image (the `dev` profile's `debian:stable-slim` has none) — point
> a profile at e.g. `python:3.12-slim` and restart `serve` to see it return `42`.

### 2b. Chronicle + tamper-evidence

```bash
# This sandbox's events (events are under .events)
curl -s "${AUTH[@]}" $BASE/v1/citadels/$SID/chronicle | jq '.events[].tool'

# Verify the hash chain across the whole ledger
curl -s "${AUTH[@]}" $BASE/v1/chronicle/verify | jq
# => {"ok":true,"signed":true}
```

You can also confirm the on-disk ledger grows and is append-only (requires
`RUNEWARD_STATE_DIR` from 0 — if unset, `ls` errors with "No such file"):

```bash
ls -la "$RUNEWARD_STATE_DIR"
```

---

## 3. Policy + human-in-the-loop approvals (Docker)

Use the `governed` profile, which **denies** `rm `* and **requires approval**
for writes under `config/`. File tools are workspace-confined (20), so use a
path **relative to the workspace** like `config/app.conf` (an absolute path is
rejected before policy runs and never creates an approval).

```bash
# NB: don't name the variable GID/UID/EUID — those are read-only in zsh.
SB=$(curl -s "${AUTH[@]}" $BASE/v1/citadels -d '{"profile":"governed"}' | jq -r .id)
echo "sandbox=$SB"

# Denied outright by policy -> HTTP 403 + verdict "deny"
curl -s "${AUTH[@]}" -o /dev/null -w "%{http_code}\n" \
  $BASE/v1/citadels/$SB/shell/exec -d '{"command":["rm","-rf","/tmp/x"]}'
# => 403

# Requires approval: blocks up to 5 min, then returns 202 + approval_id.
# Run in the background (&) so you can approve from another command while it waits.
curl -s "${AUTH[@]}" $BASE/v1/citadels/$SB/file/write \
  -d '{"path":"config/app.conf","content":"reviewed"}' &

# See the pending approval (list is under .approvals)
sleep 1
curl -s "${AUTH[@]}" $BASE/v1/conclave | jq
# => {"approvals":[{"id":"…","sandbox_id":"…","tool":"file.write",…}]}
AID=$(curl -s "${AUTH[@]}" $BASE/v1/conclave | jq -r '.approvals[0].id')
echo "approval=$AID"

# Approve it (or /deny) — the blocked background call now proceeds
curl -s "${AUTH[@]}" -X POST $BASE/v1/conclave/$AID/approve | jq
# => {"ok":true}
# The background file/write job prints {"bytes":…,"verdict":"allow"} when done
```

In the dashboard, the same flow shows up in the **Approvals** drawer (the count
badge in the header increments); approve/deny there and watch the call resolve.

### 3b. Alternative policy engines (CEL / Rego)

The same verdicts can be expressed in CEL or OPA/Rego by setting `policy_engine`
in the profile. `examples/rego.toml` mirrors `governed`'s rules in Rego:

```bash
RID=$(curl -s "${AUTH[@]}" $BASE/v1/citadels -d '{"profile":"rego"}' | jq -r .id)

# Denied by the Rego module (data.runeward.decision)
curl -s "${AUTH[@]}" $BASE/v1/citadels/$RID/shell/exec \
  -d '{"command":["rm","-rf","/tmp/x"]}' | jq '{verdict,reason}'
# => {"verdict":"deny","reason":"destructive command blocked by policy"}

# Allowed (default decision)
curl -s "${AUTH[@]}" $BASE/v1/citadels/$RID/shell/exec \
  -d '{"command":["echo","hi"]}' | jq '{verdict,exit_code}'
# => {"verdict":"allow","exit_code":0}
```

The Rego query (default `data.runeward.decision`) returns either a bare verdict
string or `{"verdict":..., "reason":...}` over the input `{tool, arg}`. Modules
use Rego v1 syntax (`if`/`contains`).

### 3c. Governed browser tool

The browser runs headless Chromium *inside* the sandbox, so it obeys the same
policy verdicts and egress allowlist. **The profile's image must ship Chromium
and the `runeward-browser` driver**, and it must not carry an `ENTRYPOINT` that
fights Rune Box's `sleep infinity` keep-alive. Use the **`browser-stateful`**
profile (`examples/browser-stateful.toml`, image `runeward-sandbox:dev` built
from `[deploy/Dockerfile.sandbox](https://github.com/Runeeward/runeward/blob/main/deploy/Dockerfile.sandbox)`),
which ships both binaries and keeps the container alive.

> On a deny-by-default profile, `runeward-browser` transparently injects the
> egress proxy's credentials for Chromium (whose `--proxy-server` can't carry
> them). Use an image built for this (`runeward-sandbox:dev`); ad-hoc images with
> their own `ENTRYPOINT` (e.g. `zenika/alpine-chrome`) fight Rune Box's keep-alive
> and exit immediately. If a call returns `{"verdict":null,…}`, drop the
> `| jq '{…}'` filter to see the real error body.

Build the sandbox image once, then create a `browser-stateful` sandbox:

```bash
docker build -f deploy/Dockerfile.sandbox -t runeward-sandbox:dev .   # one-time
BID=$(curl -s "${AUTH[@]}" $BASE/v1/citadels -d '{"profile":"browser-stateful"}' | jq -r .id)
echo "browser sandbox=$BID"
# Sanity check the container stayed up (Status should be "Up …", not "Exited"):
docker ps --filter "label=runeward.profile=browser-stateful" --format '{{.Status}}'
```

**One-shot render** — fetch a single URL (the profile allows `example.com`):

```bash
# mode "text" returns rendered DOM in .stdout
curl -s "${AUTH[@]}" $BASE/v1/citadels/$BID/browser \
  -d '{"url":"https://example.com/","mode":"text"}' | jq -r '.stdout' | head
# => <!doctype html> … <title>Example Domain</title> … <h1>Example Domain</h1> …

# mode "screenshot" returns a base64 PNG in .stdout — decode it to a file:
curl -s "${AUTH[@]}" $BASE/v1/citadels/$BID/browser \
  -d '{"url":"https://example.com/","mode":"screenshot"}' \
  | jq -r '.stdout' | base64 -d > shot.png
file shot.png     # => shot.png: PNG image data, … (a real PNG, not 0 bytes)
open shot.png     # macOS   (Linux: xdg-open shot.png)
```

**Stateful, CDP-driven session** — a persistent Chromium page the control plane
drives across calls (cookies/DOM/storage persist between actions). Each action
is individually governed and audited:

```bash
# open -> returns a session id
SESS=$(curl -s "${AUTH[@]}" -X POST $BASE/v1/citadels/$BID/browser/sessions | jq -r .session_id)

# act: navigate, then evaluate JS / extract text / screenshot on the SAME page
curl -s "${AUTH[@]}" $BASE/v1/citadels/$BID/browser/sessions/$SESS/act \
  -d '{"action":"navigate","url":"https://example.com/"}' | jq '{verdict,exit_code}'
curl -s "${AUTH[@]}" $BASE/v1/citadels/$BID/browser/sessions/$SESS/act \
  -d '{"action":"title"}' | jq -r .stdout        # => Example Domain
curl -s "${AUTH[@]}" $BASE/v1/citadels/$BID/browser/sessions/$SESS/act \
  -d '{"action":"eval","expr":"document.querySelectorAll(\"a\").length"}' | jq -r .stdout   # => 1

# screenshot returns a base64 PNG in .stdout — decode the same page to a file:
curl -s "${AUTH[@]}" $BASE/v1/citadels/$BID/browser/sessions/$SESS/act \
  -d '{"action":"screenshot"}' | jq -r .stdout | base64 -d > session-shot.png
file session-shot.png    # => PNG image data …

# close -> shuts down the in-sandbox Chromium
curl -s "${AUTH[@]}" -X DELETE $BASE/v1/citadels/$BID/browser/sessions/$SESS | jq
```

Over MCP the session is `runeward_browser_open` → `runeward_browser_act`
(`action` one of navigate|eval|text|html|screenshot|click|type|wait|title|url)
→ `runeward_browser_close`; the one-shot render is `runeward_browser`. A
deny-by-default profile constrains what the browser can reach — the session's
HTTP(S) egress proxy is threaded into Chromium via `--proxy-server` (through the
credential-injecting loopback forwarder described above), so browser traffic is
subject to the same allowlist and audit as shell/file egress.

### 3d. Signed OCI policy bundles

Ship a policy as a signed, versioned OCI artifact and have a profile pull +
verify it. This uses a throwaway local registry, so add `plain_http = true` to
the profile's `[policy_bundle]` block for the test.

> On macOS the registry is mapped to host port `5001` because AirPlay Receiver
> holds `:5000` (and answers with a `403` that looks like a registry error).

```bash
# 1. Local registry + signing key (host 5001 -> registry 5000; avoids AirPlay)
docker run -d --rm -p 5001:5000 --name rw-registry registry:2
./bin/runeward archive keygen --out /tmp/rw-keys      # writes bundle.key + bundle.pub

# 2. Author a policy and push it (rego here; --engine cel also works)
cat > /tmp/prod.rego <<'EOF'
package runeward
import rego.v1
default decision := "allow"
decision := {"verdict": "deny", "reason": "destructive command blocked by bundle"} if {
  input.tool == "shell"
  contains(input.arg, "rm ")
}
EOF
./bin/runeward archive push oci://localhost:5001/policies:v1 \
  --policy /tmp/prod.rego --engine rego --key /tmp/rw-keys/bundle.key --plain-http

# 3. Verify the pull independently (tamper the tag or key to see it fail closed)
./bin/runeward archive pull oci://localhost:5001/policies:v1 \
  --verify-key /tmp/rw-keys/bundle.pub --plain-http

# 4. A profile that consumes it (examples/policy-bundle.toml as a template):
#    [policy_bundle]
#    ref        = "oci://localhost:5001/policies:v1"
#    verify_key = "<contents of /tmp/rw-keys/bundle.pub>"
#    plain_http = true
# Creating a sandbox from it pulls+verifies the bundle before the first action;
# an invalid signature or wrong key fails sandbox creation (fail-closed).

docker rm -f rw-registry
```

---

## 4. Deny-by-default egress (Docker, cooperative proxy)

The `egress-demo` profile denies all egress except `example.com`. Rune Box
starts an in-process host proxy and points the container at it via
`HTTP(S)_PROXY`.

```bash
EID=$(curl -s "${AUTH[@]}" $BASE/v1/citadels -d '{"profile":"egress-demo"}' | jq -r .id)

# Allowed host -> succeeds
curl -s "${AUTH[@]}" $BASE/v1/citadels/$EID/shell/exec \
  -d '{"command":["wget","-qO-","http://example.com/"]}' | jq '.exit_code'
# => 0

# Disallowed host -> blocked by the proxy (non-zero exit)
curl -s "${AUTH[@]}" $BASE/v1/citadels/$EID/shell/exec \
  -d '{"command":["wget","-qO-","http://api.github.com/"]}' | jq '.exit_code'
# => non-zero
```

> Docker enforcement is **cooperative**: an app that ignores `HTTP(S)_PROXY`
> could bypass it. For bypass-resistant enforcement, use strict mode on
> Kubernetes (6).

---

## 5. Snapshots (Docker)

```bash
SID=$(curl -s "${AUTH[@]}" $BASE/v1/citadels -d '{"profile":"dev"}' | jq -r .id)
curl -s "${AUTH[@]}" $BASE/v1/citadels/$SID/file/write -d '{"path":"state.txt","content":"v1"}' >/dev/null

# Capture a snapshot of the workspace
SNAP=$(curl -s "${AUTH[@]}" $BASE/v1/citadels/$SID/snapshot -d '{"name":"v1"}' | jq -r .id)
curl -s "${AUTH[@]}" $BASE/v1/snapshots | jq

# Restore into a brand-new governed sandbox
RID=$(curl -s "${AUTH[@]}" -X POST $BASE/v1/snapshots/$SNAP/restore | jq -r .id)
curl -s "${AUTH[@]}" $BASE/v1/citadels/$RID/file/read -d '{"path":"state.txt"}' | jq -r .stdout
# => v1
```

---

## 6. Kubernetes backend

Point Rune Box at your cluster (OrbStack exposes it as context
`orbstack`). Create the namespace and, for **strict egress**, allow the
privileged capabilities the iptables init container needs:

For a disposable kind release gate covering two workers, shared-tenant actors,
cross-tenant isolation, governed exec, signed task leases, replay rejection,
and cleanup, run:

```bash
RUNEWARD_KUBE_CONTEXT=kind-logjedi ./scripts/e2e-kind.sh
```

The dashboard exercises the same backend. Start `runeward serve` with
`RUNEWARD_KUBE_CONTEXT` set, open **Agent groups**, and select `fleet-k8s`.
The selected Charter's readiness result appears beside the picker and disables
**New** when the cluster is unavailable, so a Docker readiness result cannot be
mistaken for Kubernetes readiness.

```bash
export RUNEWARD_KUBE_CONTEXT=orbstack        # or: kind-kind, minikube, ...
kubectl create namespace runeward

# Only needed for strict L3 egress (NET_ADMIN in an init container):
kubectl label namespace runeward \
  pod-security.kubernetes.io/enforce=privileged --overwrite
```

### 6a. Basic k8s sandbox

Add a k8s profile (or reuse `egress-strict` without the network block). Quick
inline test using the CLI against a k8s profile — create `examples/k8s.toml`:

```toml
[host]
type    = "k8s"
image   = "debian:stable-slim"
workdir = "/workspace"
[rationing]
max_execs = 100
```

Then:

```bash
./bin/runeward --config-dir examples serve      # same control plane, now k8s-capable
KID=$(curl -s "${AUTH[@]}" $BASE/v1/citadels -d '{"profile":"k8s"}' | jq -r .id)

# Watch the pod come up
kubectl -n runeward get pods

# Exec through the governed API (goes via client-go remotecommand)
curl -s "${AUTH[@]}" $BASE/v1/citadels/$KID/shell/exec -d '{"command":["hostname"]}' | jq -r .stdout
# => runeward-<id>   (the pod name; matches `kubectl -n runeward get pods`)

curl -s "${AUTH[@]}" -X DELETE $BASE/v1/citadels/$KID    # deletes the Pod + PVC
```

### 6b. Strict L3 egress (iptables + transparent SNI proxy)

Build the egress image **with iptables** and make it available to the cluster
(on OrbStack/Docker Desktop the local Docker images are shared with the built-in
Kubernetes, so no push is needed):

```bash
docker build -f deploy/Dockerfile.egress -t runeward-egress:latest .
```

Run a sandbox from the `egress-strict` profile (allowlist: `example.com`,
`*.githubusercontent.com`):

```bash
SID=$(curl -s "${AUTH[@]}" $BASE/v1/citadels -d '{"profile":"egress-strict"}' | jq -r .id)

# Inspect the pod — you should see an init container (egress-init) and the
# egress sidecar alongside the sandbox container:
kubectl -n runeward get pod -l runeward.profile=egress-strict -o jsonpath='{.items[0].spec.initContainers[*].name}{"\n"}{.items[0].spec.containers[*].name}{"\n"}'

# Allowed host succeeds (traffic is transparently redirected through the proxy,
# which reads the TLS SNI / HTTP Host and matches the allowlist):
curl -s "${AUTH[@]}" $BASE/v1/citadels/$SID/shell/exec \
  -d '{"command":["curl","-sS","-o","/dev/null","-w","%{http_code}","https://example.com/"]}' | jq -r .stdout

# Disallowed host is dropped even though nothing set HTTP_PROXY inside the app:
curl -s "${AUTH[@]}" $BASE/v1/citadels/$SID/shell/exec \
  -d '{"command":["curl","-sS","--max-time","8","https://api.github.com/"]}' | jq '.exit_code'
# => non-zero (connection refused/reset by the proxy)

# See the proxy's allow/deny decisions:
kubectl -n runeward logs -l runeward.profile=egress-strict -c egress
```

> Strict mode is Linux/Kubernetes-only. The init container needs `NET_ADMIN`;
> the transparent proxy runs as uid `1337` and iptables exempts it, so the
> sandbox container must run as any other uid (the stock images do).

### 6c. Declarative CRDs + controller (`runeward up`)

Instead of the imperative REST API, you can manage sandboxes and fleets as
Kubernetes custom resources reconciled by the Rune Box controller.

Install the CRDs and controller in one command (idempotent, server-side apply):

```bash
# Build the image so the controller Deployment can start (shared with OrbStack k8s)
docker build -f deploy/Dockerfile -t runeward:latest .

# Install CRDs + namespace + RBAC + controller Deployment
./bin/runeward up

# Give the controller profiles to resolve
kubectl -n runeward create configmap runeward-profiles --from-file=examples/
kubectl -n runeward rollout restart deploy/runeward-controller
```

Or install just the CRDs and run the controller locally (handy for iterating):

```bash
./bin/runeward up --crds-only
RUNEWARD_K8S_NAMESPACE=runeward ./bin/runeward --config-dir examples controller
```

Then drive it declaratively (create `examples/k8s.toml` per 6a first):

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: runeward.dev/v1alpha1
kind: Citadel
metadata: { name: demo, namespace: runeward }
spec: { profile: k8s }
EOF

# The controller provisions the pod and fills in .status
kubectl -n runeward get citadels
kubectl -n runeward get citadel demo -o jsonpath='{.status}' ; echo
# => {"phase":"Running","citadelId":"...","backend":"k8s","image":"debian:stable-slim"}
kubectl -n runeward get pods

# A Cohort works the same way
cat <<'EOF' | kubectl apply -f -
apiVersion: runeward.dev/v1alpha1
kind: Cohort
metadata: { name: crew, namespace: runeward }
spec: { profile: fleet-demo }
EOF
kubectl -n runeward get cohorts

# Deleting a CR tears down the backing pods/Cohort via a finalizer
kubectl -n runeward delete citadel demo
```

Via Helm instead of `runeward up` (use **one** installer — they manage the same
objects, so `helm install` into a namespace that already ran `runeward up` fails
on ownership; tear the other down first):

```bash
helm install runeward deploy/helm/runeward -n runeward --create-namespace \
  --set image.tag=latest
helm lint deploy/helm/runeward   # what CI runs

# The chart mounts profiles from a Secret named "runeward-profiles" (the
# `runeward up` path uses a ConfigMap); without it the controller reports
# `profile not found`. Create it and restart:
kubectl -n runeward create secret generic runeward-profiles --from-file=examples/
kubectl -n runeward rollout restart deploy/runeward-controller
```

Uninstall: `helm uninstall runeward -n runeward` (Helm), or for `runeward up`:

```bash
kubectl delete namespace runeward
kubectl delete clusterrole,clusterrolebinding runeward-controller --ignore-not-found
kubectl delete crd citadels.runeward.dev cohorts.runeward.dev clusterpolicies.runeward.dev clustercitadels.runeward.dev clustercohorts.runeward.dev
```

### 6d. Org-wide policy defaults (`ClusterPolicy` + admission webhook)

Install the third CRD and enable the webhook via Helm (it self-registers its
validating/mutating configs and mints its own serving cert on startup):

```bash
./bin/runeward up --crds-only        # installs clusterpolicies.runeward.dev too
helm upgrade --install runeward deploy/helm/runeward -n runeward --create-namespace \
  --set image.tag=latest --set webhook.enabled=true
kubectl -n runeward rollout status deploy/runeward-webhook
```

Apply an org policy, then watch it default and gate Citadel/Cohort creation:

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: runeward.dev/v1alpha1
kind: ClusterPolicy
metadata: { name: org-defaults }
spec:
  allowedProfiles: ["k8s", "fleet-*"]
  deniedProfiles: ["*-admin"]
  defaultProfile: "k8s"
  requiredLabels: ["owner"]
EOF

# Missing spec.profile -> mutating webhook fills in defaultProfile ("k8s")
cat <<'EOF' | kubectl apply -f -
apiVersion: runeward.dev/v1alpha1
kind: Citadel
metadata: { name: defaulted, namespace: runeward, labels: { owner: alice } }
spec: {}
EOF
kubectl -n runeward get citadel defaulted -o jsonpath='{.spec.profile}'; echo   # => k8s

# A denied profile is rejected by the validating webhook
cat <<'EOF' | kubectl apply -f -
apiVersion: runeward.dev/v1alpha1
kind: Citadel
metadata: { name: blocked, namespace: runeward, labels: { owner: alice } }
spec: { profile: super-admin }
EOF
# => admission webhook "...": profile "super-admin" is denied by ClusterPolicy ...
```

> The validating webhook fails closed (`failurePolicy: Fail`): if it is
> unreachable, admission is blocked rather than silently allowed. Only the
> mutating defaulting path is best-effort (`failurePolicy: Ignore`), so a
> defaulting outage never blocks legitimate work. The decision logic
> (defaulting, allow/deny globs, namespace + required-label checks) is
> unit-tested in `crates/runeward-k8s/src/webhook`.

### 6e. Cluster-scoped environments (`ClusterCitadel` / `ClusterCohort`)

For org-shared environments that shouldn't belong to any single team namespace, the
controller also reconciles the cluster-scoped `ClusterCitadel` / `ClusterCohort`.
`runeward up` installs all five CRDs; the controller watches the cluster-scoped
ones cluster-wide (via a `ClusterRole`) regardless of `--all-namespaces`:

> The examples carry an `owner` label to satisfy the `requiredLabels: ["owner"]`
> from the 6d `ClusterPolicy` (if you enabled the webhook); omit it and admission
> denies the request.

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: runeward.dev/v1alpha1
kind: ClusterCitadel
metadata: { name: shared-cell, labels: { owner: alice } }
spec: { profile: k8s }
EOF

kubectl get clustercitadels            # short name: cctd
kubectl get clustercitadel shared-cell -o jsonpath='{.status.phase} {.status.citadelId}'; echo

# A ClusterCohort fans out the profile's [cohort] replicas onto a shared board.
# Use a k8s-backed fleet profile (fleet-k8s) — the in-cluster controller has no
# Docker daemon, so container-backed fleet-demo would fail with "docker CLI not
# found in PATH".
cat <<'EOF' | kubectl apply -f -
apiVersion: runeward.dev/v1alpha1
kind: ClusterCohort
metadata: { name: shared-crew, labels: { owner: alice } }
spec: { profile: fleet-k8s }
EOF
kubectl get clustercohorts               # short name: ccoh

# Deleting the CR tears down the backing Citadel/Cohort via its finalizer.
kubectl delete clustercitadel shared-cell
kubectl delete clustercohort shared-crew
```

Cluster-scoped environments carry no `namespace`; the controller provisions their
backing Pods/PVCs in its own namespace. When the admission webhook is enabled,
`ClusterPolicy` governs them too (profile allow/deny + required labels; the
`allowedNamespaces` constraint is skipped for cluster-scoped resources).

---

## 7. Multi-agent Cohorts

A Cohort is N Citadels sharing one atomic Command Board.

```bash
# Create the Cohort (fleet-demo => 2 Citadels seeded with 3 tasks)
FID=$(curl -s "${AUTH[@]}" $BASE/v1/cohorts -d '{"profile":"fleet-demo"}' | jq -r .id)
curl -s "${AUTH[@]}" $BASE/v1/cohorts/$FID | jq '{sandboxes, stats}'

# A worker atomically claims the next task
TASK=$(curl -s "${AUTH[@]}" $BASE/v1/cohorts/$FID/claim -d '{"owner":"worker-1"}')
echo "$TASK" | jq
TID=$(echo "$TASK" | jq -r '.task.id')

# Complete it (or /fail with {"error":"...","requeue":true})
curl -s "${AUTH[@]}" -X POST $BASE/v1/cohorts/$FID/tasks/$TID/complete -d '{"result":"done"}' | jq

# Add a new task and list the board
curl -s "${AUTH[@]}" $BASE/v1/cohorts/$FID/tasks -d '{"payload":"extra work"}' | jq
curl -s "${AUTH[@]}" $BASE/v1/cohorts/$FID/tasks | jq '.tasks[] | {id, state, owner}'

# Tear the whole Cohort down
curl -s "${AUTH[@]}" -X DELETE $BASE/v1/cohorts/$FID | jq
```

The dashboard's **Cohorts** view shows the same board live, with per-task
claim/complete/fail controls.

---

## 8. MCP integration (Claude Desktop, Cursor, VS Code)

Rune Box speaks the Model Context Protocol over **stdio** (for editor/desktop
clients) or **streamable HTTP** (mounted at `/mcp` on `serve`, or standalone via
`runeward mcp --http`). Tools exposed:

- Citadels: `runeward_create_citadel`, `runeward_shell`, `runeward_python`,
`runeward_node`, `runeward_browser`, `runeward_read_file`, `runeward_write_file`,
`runeward_list_files`, `runeward_search_files`, `runeward_list_conclave`,
`runeward_publish_conversation`, `runeward_list_conversation`,
`runeward_kill_citadel`.
- Cohorts: `runeward_create_cohort`, `runeward_list_cohorts`, `runeward_list_tasks`,
`runeward_add_task`, `runeward_claim_task`, `runeward_complete_task`,
`runeward_fail_task`, `runeward_kill_cohort`.

Use an **absolute path** to the binary and profiles in client configs. Get them:

```bash
echo "$(pwd)/bin/runeward"
echo "$(pwd)/examples"
```

> Rune Box allows only **one writer per audit ledger**, so give each concurrent
> instance its own `RUNEWARD_STATE_DIR` (as the configs below do). A second
> instance on the default dir fails with `ledger: ... already in use`.

### 8a. Quick HTTP sanity check (no client needed)

The streamable-HTTP transport requires the MCP `initialize` handshake before any
other call, and replies as Server-Sent Events. The handshake returns an
`Mcp-Session-Id` header you must echo on subsequent requests:

```bash
./bin/runeward --config-dir examples mcp --http --port 8081 &
# runeward: MCP (streamable HTTP) at http://localhost:8081/mcp

H=(-H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream')

# 1) initialize — grab the session id from the response headers
SID=$(curl -s -D - -o /dev/null http://localhost:8081/mcp "${H[@]}" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}' \
  | tr -d '\r' | awk -F': ' 'tolower($1)=="mcp-session-id"{print $2}')

# 2) tell the server we're initialized
curl -s -o /dev/null http://localhost:8081/mcp "${H[@]}" -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

# 3) list tools — expect all sandbox + fleet tools
curl -s http://localhost:8081/mcp "${H[@]}" -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | sed -n 's/^data: //p' | grep -o '"name":"runeward_[a-z_]*"' | sort -u
```

(Real MCP clients — Claude, Cursor, VS Code — do this handshake for you; the
manual steps above are just for a dependency-free smoke test.)

### 8b. Claude Desktop (stdio)

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "runeward": {
      "command": "/ABSOLUTE/PATH/sandbox/bin/runeward",
      "args": ["--config-dir", "/ABSOLUTE/PATH/sandbox/examples", "mcp"],
      "env": { "RUNEWARD_STATE_DIR": "/ABSOLUTE/PATH/runeward-state" }
    }
  }
}
```

Restart Claude Desktop → the Rune Box tools appear under the tools (plug) icon.
Try: *"Create a Rune Box environment from the `dev` profile and run `uname -a`."*

### 8c. Cursor (stdio)

Create `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (per-project):

```json
{
  "mcpServers": {
    "runeward": {
      "command": "/ABSOLUTE/PATH/sandbox/bin/runeward",
      "args": ["--config-dir", "/ABSOLUTE/PATH/sandbox/examples", "mcp"],
      "env": { "RUNEWARD_STATE_DIR": "/ABSOLUTE/PATH/runeward-state" }
    }
  }
}
```

Open **Cursor → Settings → MCP** and confirm `runeward` is connected (green),
then ask the agent to use a Rune Box tool.

### 8d. VS Code (Copilot agent mode, stdio)

Create `.vscode/mcp.json` in the workspace:

```json
{
  "servers": {
    "runeward": {
      "type": "stdio",
      "command": "/ABSOLUTE/PATH/sandbox/bin/runeward",
      "args": ["--config-dir", "/ABSOLUTE/PATH/sandbox/examples", "mcp"],
      "env": { "RUNEWARD_STATE_DIR": "/ABSOLUTE/PATH/runeward-state" }
    }
  }
}
```

Open the **Chat** view, switch to **Agent** mode, press the tools icon and
enable `runeward`. (Requires VS Code ≥ 1.102 with MCP support.) You can also
point any HTTP-capable client at `serve`'s `/mcp` endpoint instead of stdio.

---

## 9. Framework adapters

The `[adapters/](https://github.com/Runeeward/runeward/tree/main/adapters)`
directory has thin, typed clients over the REST API plus lazy-loaded
agent-framework tool factories. Neither package ships its own test suite (TS has
`build`/`typecheck` only), so we smoke-test them against a **running `serve`**.
Start one first (from 2) on `http://localhost:8080` with `$BASE` / `$AUTH` set,
then verify:

```bash
curl -s $BASE/healthz                  # {"status":"ok"} — always open
curl -s "${AUTH[@]}" $BASE/v1/charters        # array of profile names (needs $AUTH when auth is on)
```

### 9a. Python (`runeward`)

```bash
cd adapters/python
pip install -e .                       # core client — pure stdlib, no runtime deps

# Importing the top-level package must NOT need any framework installed:
python -c "from runeward import RunewardClient; print('ok:', RunewardClient)"
```

Smoke-test the governed surface (the client defaults to
`http://localhost:8080`; pass `token=os.environ.get("RUNEWARD_API_TOKEN")` when
`serve` uses `--token`):

```bash
python - <<'PY'
import os
from runeward import RunewardClient
tok = os.environ.get("RUNEWARD_API_TOKEN")  # None when serving without a token
rw = RunewardClient("http://localhost:8080", token=tok)
sbx = rw.create_sandbox("dev")
sid = sbx["id"]
r = rw.shell(sid, ["echo", "hello from python adapter"])
print("verdict:", r["verdict"], "exit:", r["exit_code"], "out:", r["stdout"].strip())
print("audit verifies:", rw.verify_audit())
rw.kill_sandbox(sid)
PY
```

Expected: `verdict: allow exit: 0 out: hello from python adapter` and
`audit verifies: True`. A denied action raises `RunewardDenied`; a gated one
raises `RunewardApprovalRequired` (carrying `approval_id`) — governance is
surfaced as exceptions, not swallowed. Methods mirror the MCP tools:
`create_sandbox`, `shell`, `python`, `node`, `read_file`, `write_file`,
`list_files`, `search_files`, `list_approvals`, `approve`, `deny`,
`kill_sandbox`, `audit`, `verify_audit`.

Framework tool factories are lazy-loaded — install only the extra you need, then
each submodule exposes `make_runeward_tools(client)`:

```bash
pip install -e ".[langchain]"   # or: crewai | llamaindex | openai-agents | strands
python -c "
from runeward import RunewardClient
from runeward.langchain_tools import make_runeward_tools
print(len(make_runeward_tools(RunewardClient('http://localhost:8080'))), 'tools')
"
```

Import paths: `runeward.langchain_tools`, `runeward.crewai_tools`,
`runeward.llamaindex_tools`, `runeward.openai_agents_tools`,
`runeward.strands_tools`.

### 9b. TypeScript (`@runeward/sdk`)

```bash
cd adapters/typescript
npm install          # installs only `typescript`; the framework peers are optional
npm run build        # tsc -> ./dist  (builds cleanly with no optional peers installed)
npm run typecheck    # tsc --noEmit
```

> The framework adapters import their optional peers dynamically, so
> `build`/`typecheck` succeed with none of them installed — you only need a
> framework package at runtime if you call its `makeRunewardTools`.

Smoke-test against the running control plane (methods are camelCase):

```bash
node --input-type=module -e "
import { RunewardClient } from './dist/index.js';
const token = process.env.RUNEWARD_API_TOKEN;  // omit when serving without a token
const rw = new RunewardClient({ baseUrl: 'http://localhost:8080', token });
const sbx = await rw.createSandbox('dev');
const r = await rw.shell(sbx.id, ['echo', 'hello from ts adapter']);
console.log(r.verdict, r.exit_code, r.stdout.trim());
console.log('audit verifies:', await rw.verifyAudit());
await rw.killSandbox(sbx.id);
"
```

Framework factories live at subpath exports and are `async` (dynamic
`import()`), so peer deps are only needed if you use them:

```bash
npm install ai zod          # Vercel AI SDK; or @langchain/core zod, or @strands-agents/sdk zod
node --input-type=module -e "
import { RunewardClient, makeRunewardTools } from './dist/index.js';   // ai-tools re-exported from root
const tools = await makeRunewardTools(new RunewardClient({ baseUrl: 'http://localhost:8080' }));
console.log(Object.keys(tools));
"
```

Subpaths: `@runeward/sdk/ai-tools` (re-exported at root), `@runeward/sdk/langchain-tools`,
`@runeward/sdk/strands-tools`. See [Adapters](adapters.md) and `adapters/README.md`.

---

## 10. CLI governance tooling (no server required)

These commands are static/offline — they never launch a sandbox, so they run
anywhere and are ideal in CI.

### 10a. Validate & lint profiles

```bash
# Lint every resolvable profile; exits non-zero on any error-severity finding.
./bin/runeward --config-dir examples validate

# Lint specific profiles; --strict also fails on warnings.
./bin/runeward --config-dir examples validate dev governed --strict
```

Each profile prints `ok` or a table of `[error]`/`[warn]` findings (missing
image, unresolved secret refs, dead egress/policy rules).

### 10b. Scaffold & unit-test policy

```bash
# List ready-made policy templates, then print one (paste into a profile).
./bin/runeward policy scaffold --list
./bin/runeward policy scaffold package-approval

# Assert a profile's policy against a table of cases (great for CI).
cat > /tmp/cases.toml <<'EOF'
[[case]]
name   = "block rm -rf"
tool   = "shell"
action = "rm -rf /"
expect = "deny"

[[case]]
name   = "allow echo"
tool   = "shell"
action = "echo hi"
expect = "allow"
EOF
./bin/runeward --config-dir examples policy test governed --cases /tmp/cases.toml
# => PASS lines + "2 passed, 0 failed"; exit non-zero if any case fails.

# Inline cases also work (repeatable --case):
./bin/runeward --config-dir examples policy test governed \
  --case 'tool=shell,action=rm -rf /,expect=deny'
```

> Bundle-backed profiles (`[policy_bundle]`) can't be simulated offline — the
> policy is remote — and `policy test` says so explicitly.

### 10c. Sign & verify a profile (provenance)

```bash
./bin/runeward archive keygen --out /tmp/rw-keys           # ed25519 keypair
./bin/runeward charter sign examples/governed.toml --key /tmp/rw-keys/bundle.key
# writes examples/governed.toml.sig

./bin/runeward charter verify examples/governed.toml --verify-key /tmp/rw-keys/bundle.pub
# => verified: <key-id>

# Tamper check: edit the profile, re-verify -> non-zero "signature mismatch".
```

### 10d. Hardened-runtime doctor (gVisor / Kata)

```bash
./bin/runeward runtime check          # reports what's registered with Docker/k8s
./bin/runeward runtime guide          # full gVisor/Kata setup walkthrough
./bin/runeward runtime install gvisor # DRY-RUN by default — prints the plan, mutates nothing
```

`runtime check` is a read-only diagnostic (exit 0 unless `--strict` and nothing
is available). Then wire it in via `runtime_class = "gvisor"` under `[host]`.

### 10e. Replay a recorded terminal session

Governed interactive terminals are captured as asciinema v2 `.cast` files, but
recording is opt-in — enable it on `serve`, then drive a terminal to produce one:

```bash
# 1) (Re)start serve with recording on (only one serve can hold the ledger/:8080).
pkill -f 'runeward.*serve'
RUNEWARD_RECORD_TERMINALS=1 ./bin/runeward --config-dir examples serve &

# 2) Open a terminal so a session is recorded: dashboard → pick a sandbox →
#    Terminal, run a few commands, close the drawer.

# 3) Grab the newest cast under the state dir (default ~/Library/Caches/runeward
#    on macOS, ~/.cache/runeward on Linux):
RECDIR="${RUNEWARD_STATE_DIR:-$HOME/Library/Caches/runeward}/recordings"
CAST="$RECDIR/$(ls -t "$RECDIR" 2>/dev/null | head -1)"

# 4) Replay it instantly or with the original timing:
./bin/runeward replay "$CAST" --no-timing
./bin/runeward replay "$CAST"
```

> Recording is best-effort and **output-only** (keystrokes are not captured), and
> never blocks the live session.

---

## 11. API authentication & RBAC

2 shows the day-to-day **with/without token** flow (`$AUTH` on every `curl`).
This section goes deeper: what is protected, how tokens are presented, and
multi-principal RBAC.

By default `serve` binds `127.0.0.1` and is unauthenticated (it logs a warning).
Binding a non-loopback interface **requires** a credential or `serve` refuses to
start.

### 11a. Single API token

```bash
export RUNEWARD_API_TOKEN=s3cret
./bin/runeward --config-dir examples serve --token "$RUNEWARD_API_TOKEN" --no-ui &
BASE=http://localhost:8080
AUTH=(-H "Authorization: Bearer $RUNEWARD_API_TOKEN")

curl -s -o /dev/null -w '%{http_code}\n' $BASE/v1/citadels                       # 401 without $AUTH
curl -s "${AUTH[@]}" $BASE/v1/charters | jq .                                              # 200
curl -s $BASE/healthz                                                             # 200 (always open)
curl -s -o /dev/null -w '%{http_code}\n' "${AUTH[@]}" $BASE/metrics                        # 200 with auth; 401 without
```

Tokens may be presented as `Authorization: Bearer <t>`, `X-Runeward-Token: <t>`,
or `?token=<t>` (the last is for the WebSocket terminal). The dashboard stores
the token in-browser only and sends it as a bearer header on API calls.

### 11b. Multi-principal RBAC

```bash
cat > /tmp/authz.json <<'EOF'
{"principals":[
  {"name":"root","token":"tok-admin","admin":true},
  {"name":"dev","token":"tok-dev","allowed_profiles":["dev"]}
]}
EOF
RUNEWARD_AUTHZ_FILE=/tmp/authz.json ./bin/runeward --config-dir examples serve --no-ui &

curl -s -H "Authorization: Bearer tok-dev" $BASE/v1/whoami | jq .
# => {"authenticated":true,"rbac":true,"principal":{"name":"dev","can_launch":true,"allowed_profiles":["dev"],...}}

# Charters are scoped to launchable profiles for non-admins:
curl -s -H "Authorization: Bearer tok-dev" $BASE/v1/charters | jq '[.profiles[].name]'
# => ["dev"]   (not the full catalog)

# dev may launch "dev"...
curl -s -H "Authorization: Bearer tok-dev" -d '{"profile":"dev"}' $BASE/v1/citadels | jq .id
# ...but not "governed" -> 403
curl -s -H "Authorization: Bearer tok-dev" -d '{"profile":"governed"}' $BASE/v1/citadels | jq .
# => {"error":"not authorized to launch profile governed"}
```

Principal fields: `token`, `admin`, `can_approve`, `allowed_profiles` (globs).
`/v1/whoami` reports honest `can_launch` (false when `allowed_profiles` is empty).
When an RBAC file is loaded it supersedes `--token` and startup logs `auth=true`.
A non-loopback bind is satisfied by `--token`, `RUNEWARD_API_TOKEN`, **or**
`RUNEWARD_AUTHZ_FILE`.

---

## 12. Cost & loop guardrails + usage API

Guardrails live in `[rationing]` and are enforced **after** policy passes; a breach
returns HTTP **403** with `verdict:"deny"` and a `reason`, and is recorded in the
ledger. Create a scratch profile:

```bash
cat > examples/limits-demo.toml <<'EOF'
[host]
type  = "container"
image = "debian:stable-slim"
[rationing]
max_execs      = 1     # 12a
loop_window    = "60s" # 12b (max_execs stays high enough not to fire first)
loop_threshold = 3
max_cost_usd   = 0.01  # 12c
EOF
# restart serve so it re-reads examples/
```

Each subsection uses its **own fresh sandbox** so one guardrail doesn't mask the
next. `max_execs = 1` is intentionally tiny for 12a; 12b/12c create sandboxes
where the loop/budget limit is the one that fires (the exec count stays under 1
call for the budget test and the loop trips on failures, not the exec cap — bump
`max_execs` to e.g. `50` in a copy if you want to hammer the loop harder).

### 12a. max_execs

```bash
SB=$(curl -s "${AUTH[@]}" $BASE/v1/citadels -d '{"profile":"limits-demo"}' | jq -r .id)
curl -s "${AUTH[@]}" $BASE/v1/citadels/$SB/shell/exec -d '{"command":["echo","1"]}' | jq .verdict   # allow
curl -s "${AUTH[@]}" $BASE/v1/citadels/$SB/shell/exec -d '{"command":["echo","2"]}' | jq '{verdict,reason}'
# => {"verdict":"deny","reason":"policy: max execs exceeded"}
```

### 12b. Runaway-loop detection

Use a profile where the loop limit fires before `max_execs`. Add one:

```bash
cat > examples/loop-demo.toml <<'EOF'
[host]
type  = "container"
image = "debian:stable-slim"
[rationing]
max_execs      = 50
loop_window    = "60s"
loop_threshold = 3
EOF
# restart serve, then repeat a *failing* command (non-zero exit = a failure) on
# the same key tool|arg (here shell|false):
LB=$(curl -s "${AUTH[@]}" $BASE/v1/citadels -d '{"profile":"loop-demo"}' | jq -r .id)
for i in 1 2 3; do curl -s "${AUTH[@]}" $BASE/v1/citadels/$LB/shell/exec -d '{"command":["false"]}' | jq -r .verdict; done
curl -s "${AUTH[@]}" $BASE/v1/citadels/$LB/shell/exec -d '{"command":["false"]}' | jq '{verdict,reason}'
# => {"verdict":"deny","reason":"policy: runaway loop detected"}
```

### 12c. Budget via the usage API

Agents report token/cost usage; the next governed call is blocked once a budget
is exhausted (reporting itself is never blocked). Use a fresh sandbox from a
budget-only profile so `max_execs` doesn't fire first:

```bash
cat > examples/budget-demo.toml <<'EOF'
[host]
type  = "container"
image = "debian:stable-slim"
[rationing]
max_cost_usd = 0.01
EOF
# restart serve
BB=$(curl -s "${AUTH[@]}" $BASE/v1/citadels -d '{"profile":"budget-demo"}' | jq -r .id)
curl -s "${AUTH[@]}" $BASE/v1/citadels/$BB/usage -d '{"tokens":0,"cost_usd":0.02}' | jq .   # 200, cumulative
curl -s "${AUTH[@]}" $BASE/v1/citadels/$BB/shell/exec -d '{"command":["echo","blocked"]}' | jq '{verdict,reason}'
# => {"verdict":"deny","reason":"cost budget exhausted: $0.0200/$0.0100 spent"}

# Usage also feeds Prometheus:
curl -s "${AUTH[@]}" $BASE/metrics | grep runeward_usage
```

Other keys: `wall_clock` (duration), `egress_requests` (browser/net only),
`max_tokens`, plus backend caps `memory`/`cpus`. An invalid duration string fails
sandbox creation (400).

---

## 13. Secrets injection (fail-closed)

Profile `[[env]]` entries inject secrets resolved fresh per session. Sources are
selected by the `op` scheme; `env://` needs zero external deps and is perfect for
a local test. `value` (literal) and `file` (host file) are the non-`op` forms.

```bash
export MY_SECRET=hello-local
cat > examples/secret-env.toml <<'EOF'
[host]
type  = "container"
image = "debian:stable-slim"
[[env]]
name = "MY_SECRET"
op   = "env://MY_SECRET"
EOF
# restart serve (so it inherits MY_SECRET and re-reads examples/)

SB=$(curl -s "${AUTH[@]}" $BASE/v1/citadels -d '{"profile":"secret-env"}' | jq -r .id)
curl -s "${AUTH[@]}" $BASE/v1/citadels/$SB/shell/exec -d '{"command":["printenv","MY_SECRET"]}' | jq -r .stdout
# => [REDACTED]  — the value is live inside the sandbox but scrubbed from output.

# Prove it's actually set without leaking it (length only, never the value):
curl -s "${AUTH[@]}" $BASE/v1/citadels/$SB/shell/exec \
  -d '{"command":["sh","-lc","test -n \"$MY_SECRET\" && echo present len=${#MY_SECRET}"]}' | jq -r .stdout
# => present len=11
```

> Secrets from `op`/`file` sources (or literals flagged `secret = true`) are
> scrubbed from **both** returned stdout/stderr and the audit ledger, so an
> injected credential never leaks back in cleartext. A plain `value = "..."`
> literal is not scrubbed and prints as-is.

**Fail-closed:** point `op` at an unset var and creation aborts with **400**:

```bash
# op = "env://DOES_NOT_EXIST"  ->  POST /v1/citadels returns
# {"error":"env \"...\": resolve \"env://DOES_NOT_EXIST\": ... unset or empty"}
```

Other schemes (need their backend): `vault://kv/path#field`
(`VAULT_ADDR`/`VAULT_TOKEN`), `aws://name/key#field`, `gcp://secret#version`.
`op://vault/item/field` (1Password) needs the `op` CLI on the control-plane
host, authenticated by `OP_SERVICE_ACCOUNT_TOKEN` or the desktop app
integration; see [profiles](profiles.md#1password-op).

---

## 14. Chronicle sinks + offline transcript verification

### 14a. Stream every event to a file / webhook

Sinks are configured by env vars (a bad URL/file fails `serve` at startup):

```bash
# File sink (JSON Lines, mode 0600):
RUNEWARD_AUDIT_FILE=/tmp/rw-audit.jsonl ./bin/runeward --config-dir examples serve --no-ui &
# ...run any governed action...
tail -1 /tmp/rw-audit.jsonl | jq '{seq,tool,verdict,hash}'

# Webhook sink — capture with a throwaway listener:
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get('Content-Length',0)); print(self.rfile.read(n).decode())
        self.send_response(200); self.end_headers()
HTTPServer(('127.0.0.1',9999),H).serve_forever()" &
RUNEWARD_AUDIT_WEBHOOK_URL=http://127.0.0.1:9999/hook \
RUNEWARD_AUDIT_WEBHOOK_HEADER="Authorization: Bearer hook-secret" \
  ./bin/runeward --config-dir examples serve --no-ui
```

Each event is POSTed as JSON (`Content-Type: application/json`, retried 3x).
Both sinks can run at once.

### 14b. Export a signed bundle and verify it offline

```bash
# Export the whole signed transcript (embeds the public key) from a live serve:
curl -s "${AUTH[@]}" $BASE/v1/chronicle/export -o /tmp/bundle.json

# Verify with no server running — checks the hash chain AND signatures:
./bin/runeward chronicle verify /tmp/bundle.json
# => ok: N events verified (hash chain + signatures intact)
```

`GET /v1/chronicle/verify` (live) and `GET /v1/chronicle/pubkey` complement this.

---

## 15. Anomaly detection

The detector is always on; detections are emitted as **structured WARN logs** on
the `serve` logger (not audit events or API fields), rate-limited to one per
(session, kind) per minute. Lower a threshold to trip it fast:

```bash
RUNEWARD_ANOMALY_EXEC_BURST=3 RUNEWARD_ANOMALY_WINDOW=1m \
  ./bin/runeward --config-dir examples serve --no-ui 2>&1 | tee /tmp/serve.log &

SB=$(curl -s "${AUTH[@]}" $BASE/v1/citadels -d '{"profile":"dev"}' | jq -r .id)
for i in 1 2 3 4 5; do curl -s "${AUTH[@]}" $BASE/v1/citadels/$SB/shell/exec -d '{"command":["echo","'$i'"]}' >/dev/null; done
grep 'anomaly=exec_burst' /tmp/serve.log
```

Kinds/knobs: `exec_burst` (`RUNEWARD_ANOMALY_EXEC_BURST`, window
`RUNEWARD_ANOMALY_WINDOW`), `novel_host` (`RUNEWARD_ANOMALY_MAX_HOSTS`),
`denial_spike` (`RUNEWARD_ANOMALY_MAX_DENIES`).

---

## 16. argv-aware policy & the CEL engine

### 16a. argv matching (evasion-resistant)

`match` globs the joined command; `match_argv` globs the real executable
(`argv[0]`, its basename, and the `-c` payload of `sh`/`bash`/… wrappers), so it
catches `sh -c "rm ..."` evasion:

```bash
cat > examples/argv-guard.toml <<'EOF'
[host]
type  = "container"
image = "debian:stable-slim"
[[policy]]
tool       = "shell"
match_argv = "rm"
verdict    = "deny"
reason     = "no rm via argv"
EOF
# restart serve

SB=$(curl -s "${AUTH[@]}" $BASE/v1/citadels -d '{"profile":"argv-guard"}' | jq -r .id)
curl -s "${AUTH[@]}" $BASE/v1/citadels/$SB/shell/exec -d '{"command":["sh","-c","rm -rf /tmp/x"]}' | jq '{verdict,reason}'
# => {"verdict":"deny","reason":"no rm via argv"}
curl -s "${AUTH[@]}" $BASE/v1/citadels/$SB/shell/exec -d '{"command":["ls","-la"]}' | jq -r .verdict   # allow
```

### 16b. CEL policy engine

`examples/cel-policy.toml` mirrors `governed`'s rules with `policy_engine = "cel"`
and `[[cel]]` rules over the `tool`/`arg` variables:

```bash
CID=$(curl -s "${AUTH[@]}" $BASE/v1/citadels -d '{"profile":"cel-policy"}' | jq -r .id)
curl -s "${AUTH[@]}" $BASE/v1/citadels/$CID/shell/exec -d '{"command":["rm","-rf","/tmp/x"]}' | jq '{verdict,reason}'
# => deny (destructive command blocked by CEL policy)
curl -s "${AUTH[@]}" $BASE/v1/citadels/$CID/shell/exec -d '{"command":["echo","hi"]}' | jq -r .verdict   # allow
```

You can also unit-test CEL/Rego/argv rules offline with `policy test` (10b).

---

## 17. Observability: metrics, logs, telemetry

```bash
# Prometheus metrics (same listener as the API; protected when auth is on):
curl -s "${AUTH[@]}" $BASE/metrics | grep -E '^runeward_(actions_total|sandboxes_created_total|build_info)'

# Structured JSON logs to a shipper:
RUNEWARD_LOG_FORMAT=json RUNEWARD_LOG_LEVEL=debug ./bin/runeward --config-dir examples serve --no-ui
# => {"time":"...","level":"INFO","msg":"request","method":"POST","path":"/v1/citadels","status":200,...}

# Telemetry is OFF by default; startup logs its state. It only sends when BOTH
# are set (and DO_NOT_TRACK always wins):
#   RUNEWARD_TELEMETRY=1 RUNEWARD_TELEMETRY_ENDPOINT=https://collector.example/ingest
```

`/metrics` and `/healthz` are excluded from the access log. A ready-made Grafana
dashboard (`deploy/grafana/`) and Prometheus alerts (`deploy/prometheus/`) ship
in-repo — see [Observability](observability.md).

---

## 18. Deny-by-default policy mode

Turn the biggest authz footgun (unmatched action ⇒ *allow*) into a fail-closed
default, per-profile or operator-wide.

```bash
# Per-profile: policy_default is a top-level profile key.
cat > examples/deny-default.toml <<'EOF'
policy_default = "deny"

[host]
type    = "container"
image   = "debian:stable-slim"
workdir = "/workspace"
EOF
# restart serve, then an unmatched action is denied (no explicit [[policy]] needed):
CID=$(curl -s "${AUTH[@]}" $BASE/v1/citadels -d '{"profile":"deny-default"}' | jq -r .id)
curl -s "${AUTH[@]}" $BASE/v1/citadels/$CID/shell/exec -d '{"command":["echo","hi"]}' | jq -r .verdict
# => deny

# Operator-wide switch (no profile edit) — flips the fallback for every profile;
# an explicit profile policy_default still overrides it:
RUNEWARD_POLICY_DEFAULT=deny ./bin/runeward --config-dir examples serve --no-ui

# validate warns when a builtin-policy profile relies on the implicit allow:
./bin/runeward --config-dir examples validate dev --strict   # => [warn] implicit allow-by-default …
```

---

## 19. Custom Chronicle scrub patterns

Operators can add their own secret shapes on top of the built-in scrubber; a bad
regex fails closed at creation.

```bash
cat > examples/scrub-demo.toml <<'EOF'
[host]
type    = "container"
image   = "debian:stable-slim"
workdir = "/workspace"

[chronicle]
scrub_patterns = ["ACME-[A-Z0-9]{6}"]
EOF
# Invalid regex is rejected at sandbox creation (fail-closed):
#   scrub_patterns = ["("]  ->  POST /v1/citadels => 400  "chronicle.scrub_patterns \"(\": …"

# restart serve; the pattern is masked in returned output AND in the ledger:
CID=$(curl -s "${AUTH[@]}" $BASE/v1/citadels -d '{"profile":"scrub-demo"}' | jq -r .id)
curl -s "${AUTH[@]}" $BASE/v1/citadels/$CID/shell/exec -d '{"command":["echo","key ACME-AB12CD done"]}' | jq -r .stdout
# => the ACME-AB12CD token is replaced with a mask (raw value never returned)
curl -s "${AUTH[@]}" $BASE/v1/citadels/$CID/chronicle | jq '.events[-1].args'   # masked here too
```

Built-in coverage now also masks `sk-ant-`/`sk-proj-`/`sk-…` (OpenAI/Anthropic),
AWS secret keys, `ghp_`/`github_pat_…`, Google `AIza…`, Slack `xox…`, and generic
high-entropy blobs — even when the secret was never declared.

---

## 20. Workspace-confined file tools

The control-plane `file.*` tools are confined to the sandbox workdir, so policy
is no longer the only thing standing between an agent and `/etc/passwd`.

```bash
CID=$(curl -s "${AUTH[@]}" $BASE/v1/citadels -d '{"profile":"dev"}' | jq -r .id)   # dev sets workdir=/workspace
# Absolute path -> refused
curl -s "${AUTH[@]}" $BASE/v1/citadels/$CID/file/read -d '{"path":"/etc/passwd"}' | jq -r .error
# => path "/etc/passwd" must be relative to workspace
# `..` escape -> refused
curl -s "${AUTH[@]}" $BASE/v1/citadels/$CID/file/read -d '{"path":"../../etc/passwd"}' | jq -r .error
# => path "../../etc/passwd" escapes workspace root
# In-workspace relative path -> works
curl -s "${AUTH[@]}" $BASE/v1/citadels/$CID/file/write -d '{"path":"note.txt","content":"hi"}' >/dev/null
curl -s "${AUTH[@]}" $BASE/v1/citadels/$CID/file/read  -d '{"path":"note.txt"}' | jq -r .content   # => hi
```

---

## 21. Browser URL-scheme / SSRF allowlist

The browser `navigate` path only accepts `http`/`https` (and `about:blank`) and
blocks loopback, link-local (cloud metadata `169.254.169.254`), and private
targets by default.

```bash
# (Uses a browser-capable sandbox image; the guard rejects before navigating.)
curl -s "${AUTH[@]}" $BASE/v1/citadels/$CID/browser -d '{"url":"file:///etc/passwd","mode":"text"}' | jq -r .error
# => scheme "file" not allowed
curl -s "${AUTH[@]}" $BASE/v1/citadels/$CID/browser -d '{"url":"http://169.254.169.254/","mode":"text"}' | jq -r .error
# => blocked host (link-local / private)
# Allow a trusted internal target only when you must:
#   RUNEWARD_BROWSER_ALLOW_PRIVATE_ADDRS=1
```

The in-container browser control socket also requires a shared secret
(`RUNEWARD_BROWSER_CONTROL_TOKEN`). Chromium launches with `--no-sandbox` by
default (both the one-shot render and the stateful driver) because a container
usually lacks the user namespaces Chromium's own sandbox needs; on a host that
provides them (userns) or stronger isolation (gVisor/Kata) keep Chromium's
sandbox with `RUNEWARD_BROWSER_NO_SANDBOX=0`.

---

## 22. Snapshot restore re-derives isolation

A restore now runs the full profile→spec path, so egress/hardening/limits come
back on the restored environment (it is not an open container).

```bash
SID=$(curl -s "${AUTH[@]}" $BASE/v1/citadels/$CID/snapshot -d '{"name":"v1"}' | jq -r .id)
NID=$(curl -s "${AUTH[@]}" $BASE/v1/snapshots/$SID/restore | jq -r .id)
# The restored sandbox re-applies the profile's egress allowlist:
curl -s "${AUTH[@]}" $BASE/v1/citadels/$NID/shell/exec \
  -d '{"command":["sh","-c","curl -sS https://disallowed.example >/dev/null; echo $?"]}' | jq -r .stdout
# => non-zero (egress enforced, not open)
# If the snapshot's source profile is gone, restore fails closed instead of
# running with no governance:
# => {"error":"load snapshot profile \"…\": …"}
```

---

## 23. Profile safety: footgun lint, exempt-UID guard, signed-at-load

```bash
# host.user = "1337" collides with the strict-egress exempt uid (a full egress
# bypass). It is now a lint error AND rejected at sandbox creation:
cat > examples/footgun.toml <<'EOF'
[host]
type  = "container"
image = "debian:stable-slim"
user  = "1337"

[network]
default = "deny"
enforce = "strict"

[[network.rule]]
verdict  = "allow"
hostname = "*.debian.org"
EOF
./bin/runeward --config-dir examples validate footgun          # => [error] host.user 1337 …
./bin/runeward --config-dir examples validate footgun --strict # also shows isolation-footgun warnings

# Signed-profile enforcement at load — tampered on-disk profiles fail closed.
# (Reuses the keypair + sign flow from 10c.)
./bin/runeward archive keygen --out /tmp/rw-keys
./bin/runeward charter sign examples/governed.toml --key /tmp/rw-keys/bundle.key
RUNEWARD_REQUIRE_SIGNED_PROFILES=1 RUNEWARD_PROFILE_VERIFY_KEY=/tmp/rw-keys/bundle.pub \
  ./bin/runeward --config-dir examples print governed          # loads only if the .sig verifies
# now edit examples/governed.toml and re-run -> load fails closed (signature mismatch)
```

---

## 24. RBAC tenant isolation across every resource

With multi-principal RBAC (11b) a non-admin token is now scoped on fleets,
snapshots, Conclave, and the Chronicle — not just `/v1/citadels/{id}` — and Cohort
create enforces `CanLaunch` like sandbox create.

```bash
# (DEV_TOKEN is a non-admin principal from 11b; ADMIN is an admin token.)
curl -s -H "Authorization: Bearer $DEV_TOKEN" $BASE/v1/cohorts    | jq   # only dev's fleets
curl -s -H "Authorization: Bearer $DEV_TOKEN" $BASE/v1/snapshots | jq   # only dev's snapshots
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $DEV_TOKEN" $BASE/v1/chronicle/export
# => 403 unless the principal is permitted

# Fleet create honors the allowed-profile list:
curl -s -H "Authorization: Bearer $DEV_TOKEN" $BASE/v1/cohorts -d '{"profile":"governed"}' | jq -r .error
# => not authorized to launch profile governed

# Fleet complete/fail reject an empty owner (no more hijack with {}):
curl -s -o /dev/null -w '%{http_code}\n' "${AUTH[@]}" $BASE/v1/cohorts/$FID/tasks/$TID/complete -d '{}'
# => 400 (owner required)
```

---

## 25. Short-lived session tickets

Long-lived bearer tokens no longer need to ride in URLs or `localStorage`.

```bash
# Mint a single-use, short-TTL ticket for the terminal WebSocket:
curl -s "${AUTH[@]}" $BASE/v1/tickets -d '{"kind":"terminal","sandbox_id":"'$CID'"}' | jq
# => {"ticket":"…","expires_at":"…","scope":{"kind":"terminal","sandbox_id":"…"}}
# The socket accepts GET /v1/citadels/$CID/terminal?ticket=<one-time>; a second
# use of the same ticket is rejected. Downloads work too:
curl -s "${AUTH[@]}" $BASE/v1/tickets -d '{"kind":"download","path":"/v1/chronicle/export"}' | jq -r .ticket
# (POST /v1/citadels/{id}/terminal-ticket still works and delegates to this store.)
```

### Optional browser IDE (experimental)

Full documentation (additions + limitations): [Browser IDE](browser-ide.md).

Contrast with **host IDE → MCP** (setup 1) and **in-environment CLI agents** (setup 2): this path
embeds code-server inside the Citadel and reverse-proxies it from `serve`. Keystrokes are
**not** per-command policy (same caveat as the interactive terminal).

Cursor Desktop / Claude Desktop / Codex do **not** ship a self-hosted browser GUI. To test
those CLIs through the same Open-IDE spin-off, build the `ide-agents` target from `deploy/Dockerfile.ide` and use
`ide-claude` / `ide-codex` / `ide-cursor` Charters; run `claude`, `codex`, or `agent` in the
IDE terminal. GitHub Copilot is not first-class on code-server (Open VSX marketplace).

```bash
# Build the IDE image and enable the feature flag:
docker build --target ide -f deploy/Dockerfile.ide -t runeward-ide:latest .
export RUNEWARD_ENABLE_EXPERIMENTAL_IDE=1
# Charter: examples/ide-demo.toml ([ide] enabled = true)

# Or IDE + coding CLIs:
docker build --target ide-agents -f deploy/Dockerfile.ide -t runeward-ide-agents:latest .
# Charters: ide-claude / ide-codex / ide-cursor (API key files under ~ as documented in each;
# write CODEX_API_KEY to ~/.runeward-openai.key for ide-codex)

CID=$(curl -s "${AUTH[@]}" $BASE/v1/citadels -d '{"profile":"ide-demo"}' | jq -r .id)
TICKET=$(curl -s "${AUTH[@]}" $BASE/v1/tickets -d '{"kind":"ide","sandbox_id":"'$CID'"}' | jq -r .ticket)
# Open in a browser (ticket is single-use; a cookie covers subsequent asset loads):
open "$BASE/v1/citadels/$CID/ide?ticket=$TICKET"
# Or: dashboard → select Citadel → Open IDE
# Chronicle: ide.open on create, ide.close on kill.
```

---

## 26. Policy simulation (dry-run) over the API

"What would happen?" without touching a sandbox — it runs the real engine
(builtin/CEL/Rego) and returns a first-match trace. The dashboard "Policy" panel
calls the same endpoint.

```bash
curl -s "${AUTH[@]}" $BASE/v1/policy/simulate -d '{
  "profile_name":"governed",
  "actions":[
    {"tool":"shell","command":["rm","-rf","/"]},
    {"tool":"shell","command":["echo","hi"]}
  ]}' | jq '.results[] | {tool, verdict, matched_rule}'
# => rm -rf … -> deny (with matched rule); echo hi -> allow
# Inline profile bodies are accepted too (use "profile" instead of "profile_name").
```

---

## 27. Egress explorer + budget burn-down

```bash
# Per-sandbox egress decisions (host, ip, allow/deny, reason) for the dashboard
# "Egress" panel — sourced from the in-process/cooperative proxy decision log:
curl -s "${AUTH[@]}" $BASE/v1/citadels/$CID/perimeter | jq '.decisions[] | {host, ip, allow, reason}'
# (Strict out-of-process sidecar traffic is not represented by this buffer.)

# Configured limits are now returned on the sandbox object, feeding a read-only
# budget burn-down panel (usage vs caps):
curl -s "${AUTH[@]}" $BASE/v1/citadels/$CID | jq '.limits'
# => {"max_tokens":…, "max_cost_usd":…, "max_execs":…, "egress_requests":…, "wall_clock":…}
```

---

## 28. OTLP / SIEM Chronicle sink

Fan the ledger out to an OpenTelemetry collector alongside the webhook/file sinks
(14), so events land in Datadog/Splunk/Elastic with trace context.

```bash
RUNEWARD_AUDIT_OTLP_ENDPOINT=http://localhost:4318 \
RUNEWARD_AUDIT_OTLP_HEADERS="authorization=Bearer XYZ" \
RUNEWARD_AUDIT_OTLP_SERVICE_NAME=runeward \
  ./bin/runeward --config-dir examples serve --no-ui
# Each governed action is exported as an OTLP log record with attributes:
# session/sandbox, profile, tool, action, verdict, exit_code, duration, reason
# (+ trace context when the event carries one). Emit is non-blocking; on overflow
# the oldest event is dropped and counted, never stalling the action path.
# Other knobs: RUNEWARD_AUDIT_OTLP_INSECURE, RUNEWARD_AUDIT_OTLP_RESOURCE_ATTRS.
```

Signature verification also tightened: when a signing key is configured,
`GET /v1/chronicle/verify` (and `runeward chronicle verify`) require **every** record to
be signed — an unsigned record now fails verification instead of passing.

---

## 29. Podman / rootless backend

```bash
# Force Podman (auto-detected when the docker CLI is absent but podman is present):
RUNEWARD_CONTAINER_RUNTIME=podman ./bin/runeward --config-dir examples serve --no-ui
# Everything in 1–5 works the same; rootless Podman uses host.containers.internal
# for the cooperative proxy host mapping.
podman ps -a --filter "label=runeward.profile"   # sandboxes show up under podman
# An invalid value is rejected at startup:
#   RUNEWARD_CONTAINER_RUNTIME=nope  ->  error: unsupported container runtime "nope"
```

---

## 30. Local / self-hosted model profile

A ready template that pins an agent's model traffic to a **local** runtime
(Ollama / vLLM / llama.cpp / LM Studio / LiteLLM — anything exposing an
OpenAI-compatible `/v1`) with deny-by-default egress. "OpenAI" here is the wire
protocol, not the vendor; nothing leaves for a hosted API.

```bash
./bin/runeward --config-dir examples validate byo-model-gateway   # => passes (env:// refs warn)
# Point at your local runtime (Ollama's default port shown); the key is a
# placeholder for servers that ignore auth. Injected under OPENAI_BASE_URL,
# OPENAI_API_BASE, and OPENAI_API_KEY so OpenAI SDK / LangChain / LiteLLM agents
# all pick it up:
export OPENAI_BASE_URL=http://host.docker.internal:11434/v1 OPENAI_API_KEY=local
CID=$(curl -s "${AUTH[@]}" $BASE/v1/citadels -d '{"profile":"byo-model-gateway"}' | jq -r .id)
# Only the runtime host is reachable; everything else is denied egress.
```

Full walkthrough (air-gapped, still-audited fleets): [Bring your own model](byo-model.md).

---

## 31. SDK adapter transport hardening

```bash
# Python: cleartext http:// to a non-loopback host is refused unless opted in.
python3 - <<'PY'
from runeward import RunewardClient
try:
    RunewardClient(base_url="http://10.0.0.5:8080")            # refused
except Exception as e:
    print("refused:", e)
RunewardClient(base_url="http://10.0.0.5:8080", allow_insecure=True)  # explicit opt-in
RunewardClient(base_url="http://localhost:8080")               # loopback is fine
PY
# TypeScript: new RunewardClient({ baseUrl, allowInsecure: true }); env
# RUNEWARD_ALLOW_INSECURE_HTTP=1 opts in for both. Sandbox/approval IDs are now
# percent-encoded in request paths.
```

---

## 32. Supply-chain hardening (build-time)

```bash
# Base images are pinned by digest and agent tool versions are fixed:
grep -n '@sha256:' deploy/Dockerfile deploy/Dockerfile.egress deploy/Dockerfile.sandbox deploy/Dockerfile.agent

# Helm ships governance-on by default, with split ServiceAccounts + scoped RBAC:
helm template runeward deploy/helm/runeward | grep -E 'kind: (ServiceAccount|ClusterRole|Role)$'
helm template runeward deploy/helm/runeward | grep -c 'ValidatingWebhookConfiguration'   # => 1 (enabled by default)

# install.sh verifies the cosign signature over checksums.txt (bypass only via an
# explicit RUNEWARD_INSECURE_SKIP_* env); CI uploads complete scanner reports,
# while gosec gates HIGH and Trivy gates HIGH/CRITICAL release findings.
grep -n 'cosign verify-blob' install.sh
```

---

## 33. Cleanup

```bash
# Stop `serve` / `mcp` with Ctrl-C.

# Docker: remove leftover sandbox containers (labeled by runeward)
docker ps -a --filter "label=runeward.profile" -q | xargs -r docker rm -f

# Kubernetes: drop the namespace (Pods, PVCs, ConfigMaps go with it)
kubectl delete namespace runeward

# Remove the scratch profiles created above (6a, 12, 13, 16, 18-23, py.toml)
rm -f examples/{limits-demo,loop-demo,budget-demo,secret-env,argv-guard,k8s,py}.toml \
      examples/{deny-default,scrub-demo,footgun}.toml examples/governed.toml.sig

# Wipe the audit ledger / snapshots and any scratch files for this run
rm -rf "$RUNEWARD_STATE_DIR" /tmp/rw-keys /tmp/cases.toml /tmp/authz.json \
       /tmp/rw-audit.jsonl /tmp/bundle.json /tmp/serve.log
```

---

## Troubleshooting


| Symptom                                                                     | Likely cause / fix                                                                                                                                                                  |
| --------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `serve` errors creating a sandbox                                           | Docker/OrbStack not running (`docker info`), the profile's image isn't pulled, or `docker`/`podman` isn't on `PATH` in the shell that started `serve`.                              |
| K8s sandbox stuck `Pending`                                                 | No default StorageClass for the workspace PVC, or the image can't be pulled by the cluster. `kubectl -n runeward describe pod ...`.                                                 |
| Strict egress: init container `CreateContainerError`/denied                 | Namespace PodSecurity blocks `NET_ADMIN` — label it `privileged` (6).                                                                                                              |
| Strict egress: `runeward-egress` ImagePullBackOff                           | Build the image (`deploy/Dockerfile.egress`) or set `RUNEWARD_EGRESS_IMAGE` to a pushed ref.                                                                                        |
| Strict egress: allowed host still blocked                                   | The app connected by raw IP with no SNI/Host — add a `cidr` rule, or use a hostname. Check the `egress` sidecar logs.                                                               |
| MCP client shows no tools                                                   | Use absolute paths in the config; check the client's MCP logs; verify `bin/runeward mcp` runs standalone.                                                                           |
| Approval call never returns                                                 | Approve/deny it via `GET /v1/conclave` + `POST /v1/conclave/{id}/approve`, or the dashboard drawer.                                                                               |
| Everything returns `401`                                                    | Auth is on. Use `AUTH=(-H "Authorization: Bearer $RUNEWARD_API_TOKEN")` and `"${AUTH[@]}"` on every `curl` (2a); a bare `$AUTH="-H Authorization:Bearer …"` word-splits the token. |
| `curl ... \| jq` prints **nothing** (no error)                               | `curl -s` swallows connection errors — usually `$BASE` is unset (2a) or `serve` isn't up. Re-run with `-sS` to see the real error.                                                 |
| `serve` refuses to start on `--bind 0.0.0.0`                                | Non-loopback binds require a credential — add `--token`, `RUNEWARD_API_TOKEN`, or `RUNEWARD_AUTHZ_FILE`.                                                                            |
| A tool call denies with `policy: … exceeded` / `budget exhausted`           | Not a bug — a `[rationing]` guardrail fired (12). Raise the limit or start a fresh sandbox.                                                                                           |
| `POST /v1/citadels` returns `400` mentioning `resolve "…"`                 | A `[[env]]` secret couldn't be resolved (fail-closed, 13). Set the source var/creds, or fix the `op` scheme.                                                                       |
| New profile not picked up                                                   | `serve` reads profiles at startup — restart it after editing `examples/`. Or run `runeward validate` first (10a).                                                                  |
| `policy test` says it can't simulate                                        | The profile sources policy from an OCI bundle; bundle-backed policy is remote and can't be tested offline (10b).                                                                   |
| `file.*` returns `must be relative to workspace` / `escapes workspace root` | Not a bug — file tools are confined to the sandbox workdir (20). Use a path relative to the workspace.                                                                             |
| Browser `navigate` returns `scheme … not allowed` / `blocked host`          | The URL-scheme/SSRF allowlist fired (21). Only `http`/`https` public hosts are allowed; set `RUNEWARD_BROWSER_ALLOW_PRIVATE_ADDRS=1` for a trusted internal target.                |
| Unmatched action denied unexpectedly                                        | Deny-by-default is on via the profile `policy_default` or `RUNEWARD_POLICY_DEFAULT=deny` (18). Add an explicit `[[policy]]` allow rule.                                            |
| OTLP sink: no records arrive                                                | Check `RUNEWARD_AUDIT_OTLP_ENDPOINT`/`_HEADERS` and collector reachability; the sink is non-blocking and drops (and counts) on overflow (28).                                      |
| `unsupported container runtime "…"` at startup                              | `RUNEWARD_CONTAINER_RUNTIME` must be `docker` or `podman` (29).                                                                                                                    |
| `ledger: "…/ledger.jsonl" is already in use by another runeward process`    | One writer per audit ledger. Another `serve`/`mcp` holds the default state dir — give this instance its own `RUNEWARD_STATE_DIR` (8), or stop the other process.                    |
| `runeward mcp --http` → `bind: address already in use`                      | A previous `mcp`/`serve` still owns the port. `pkill -f 'runeward.*mcp'` (or stop `serve`), or start with a different `--port`.                                                     |
