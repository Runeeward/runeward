# Policies (Charters)

A policy file—called a Charter in existing Rune Box APIs—is the declarative
security contract for a sandbox (Citadel). Rune Box resolves policies from a
config directory (`--config-dir` or `$RUNEWARD_CONFIG_DIR`) and
supports **TOML, YAML, and JSON** — pick per file by extension (`.toml`,
`.yaml`/`.yml`, `.json`). TOML is the default in the examples.

Inspect the resolved, secret-redacted result before use:

```bash
runeward --config-dir examples print <charter>
```

## Anatomy

```toml
capabilities = ["python", "node"] # optional tools actually present in the image

[host]
type      = "container"          # or "k8s"
image     = "ghcr.io/runewardd/runeward-agent:latest"
workdir   = "/workspace"
copy_from = "~/Documents/my-project"   # optional: seed /workspace at create
# runtime_class = "gvisor"       # hardened runtime (Docker --runtime / k8s runtimeClassName)
# read_only  = true              # read-only rootfs (writable /tmp + workspace)
# seccomp    = "/etc/seccomp/strict.json"   # Docker --security-opt seccomp / k8s Localhost profile
# apparmor   = "runtime/default"            # AppArmor profile
# command    = ["/bin/sh", "-c", "sleep infinity"] # override image entrypoint/keepalive

[network]
default = "deny"                 # deny-by-default egress

[[network.rule]]                 # one rule per allow/deny entry
verdict  = "allow"
hostname = "api.openai.com"      # supports *.wildcards

[[network.rule]]
verdict  = "allow"
hostname = "*.githubusercontent.com"

[[env]]
name  = "OPENAI_API_KEY"
value = "sk-..."                 # or file = "~/.secrets/openai"; or op = "env://OPENAI_API_KEY" / "vault://kv/openai#key"

[[file]]
path    = "/workspace/README.md"
content = "seeded at create"

[[policy]]
tool    = "shell"
match   = "rm -rf *"
verdict = "require-approval"

[rationing]
wall_clock      = "15m"          # duration string; empty/zero means unlimited
max_execs       = 200
egress_requests = 100            # cap outbound requests through the proxy
max_tokens      = 2000000        # cap reported model tokens (0 = unlimited)
max_cost_usd    = 25.0           # cap reported spend in USD (0 = unlimited)
```

## Sections

| Section | Purpose |
| --- | --- |
| `capabilities` | Optional top-level list of tools actually present in the image: `python`, `node`, and/or `browser`. Creation verifies declared tools, the API rejects unavailable code/browser actions, and the dashboard hides unavailable controls. Official Rune Box and obvious language images are inferred; older custom Charters are probed once after creation for backward compatibility. |
| `[host]` | Backend (`container` or `k8s`), image, workdir, optional `copy_from` to seed the workspace, optional `command` to override an image entrypoint and keep the Citadel alive, optional `runtime_class` to select a hardened runtime like `gvisor`/`kata` for VM-grade isolation (maps to `--runtime` on Docker and `runtimeClassName` on Kubernetes), optional `read_only = true` to mount the root filesystem read-only (writable `/tmp` + workspace), and optional `seccomp` / `apparmor` to pin a seccomp/AppArmor profile (Docker `--security-opt`; k8s Localhost profiles — k8s pods default to the runtime's seccomp profile). |
| `[network]` + `[[network.rule]]` | Egress policy. `default = "deny"` plus one `[[network.rule]]` per `verdict`/`hostname` (or `cidr`) entry; hostnames support `*.wildcard`. Use a separate rule for each hostname. |
| `[[env]]` | Environment/secret injection: literal `value`, from a `file`, or an `op` scheme reference — `env://NAME` (host env var), `vault://<mount>/<path>#<field>` (Vault KV v2 via `VAULT_ADDR`/`VAULT_TOKEN`), `aws://<secret-id>[#json-key]` (AWS Secrets Manager), `gcp://<name>[#version]` (GCP Secret Manager), or `op://…` (1Password, not built in). Resolution is fail-closed; known secrets are redacted from the ledger. |
| `[[file]]` | Files written into the Citadel at create. |
| `[[policy]]` / `[[cel]]` / `[rego]` | Per-action verdicts. Choose the engine with top-level `policy_engine`. |
| `[policy_bundle]` | Pull signed, versioned policy from an OCI artifact instead of inline rules. |
| `[rationing]` | Rationing (guardrails): `wall_clock` (duration string), `max_execs`, `egress_requests`, loop detection via `loop_window`/`loop_threshold`, and budget caps `max_tokens`/`max_cost_usd` (enforced once usage is reported to `POST /v1/citadels/{id}/usage`). |
| `[ide]` | Optional experimental browser IDE (code-server). Fields: `enabled`, `port` (default 8080), optional `path`, optional `agents = ["claude","codex","cursor"]` (UI hints). Requires `RUNEWARD_ENABLE_EXPERIMENTAL_IDE=1` and the `ide` or `ide-agents` target from `deploy/Dockerfile.ide`. See [Browser IDE](browser-ide.md) for setup and limitations (no desktop GUI embed, no first-class Copilot). |
| `[workspace]` | Optional persistent workspace: `persist = true` keeps the disk across sleep/wake and control-plane restarts; `idle_timeout = "15m"` (at least `1m`) puts an idle Citadel to sleep. See [Workspaces and context](workspaces-and-context.md). |
| `[schedule]` | `self_service = true` lets agents create and delete their own scheduled runs over MCP (default false). See [Workspaces and context](workspaces-and-context.md#scheduled-runs). |

## Secret injection

```toml
[[env]]
name  = "OPENAI_API_KEY"
value = "sk-..."            # literal (redacted in the ledger)

[[env]]
name = "ANTHROPIC_API_KEY"
file = "~/.secrets/anthropic"   # read from a host file at create

[[env]]
name = "GITHUB_TOKEN"
op   = "env://GITHUB_TOKEN"          # host env var

[[env]]
name = "DB_PASSWORD"
op   = "vault://kv/database/prod#password"   # HashiCorp Vault KV v2 (VAULT_ADDR/VAULT_TOKEN)

[[env]]
name = "STRIPE_KEY"
op   = "aws://prod/stripe#secret_key"        # AWS Secrets Manager (AWS_REGION + creds); #key extracts a JSON field

[[env]]
name = "SIGNING_KEY"
op   = "gcp://signing-key"                   # GCP Secret Manager (GOOGLE_CLOUD_PROJECT + access token / metadata); version defaults to latest
```

The `op` key takes a scheme reference resolved fresh at Citadel creation:
`env://NAME`, `vault://<mount>/<path>#<field>`, `aws://<secret-id>[#json-key]`
(AWS Secrets Manager — `AWS_REGION`/`AWS_DEFAULT_REGION` plus standard
`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN`),
`gcp://<name>[#version]` or `gcp://projects/<p>/secrets/<n>/versions/<v>` (GCP
Secret Manager — `GOOGLE_CLOUD_PROJECT` plus `GOOGLE_OAUTH_ACCESS_TOKEN` or the
GCE metadata server), or `op://…` (1Password, not built in — always fails
closed). Resolution is fail-closed: an unresolvable reference aborts Citadel
creation rather than starting without the secret. `runeward doctor` and
`GET /v1/readiness?profile=...` perform the same prerequisite check without
returning secret values.

## Image entrypoints and startup liveness

Rune Box normally overrides the image entrypoint with `sleep infinity`. For an
application image whose own entrypoint interprets those words (for example a
headless-Chrome image), declare the executable and arguments explicitly:

```toml
[host]
image = "zenika/alpine-chrome:124"
command = ["/bin/sh", "-c", "sleep infinity"]
```

Docker/Podman Citadels must stay running across post-start liveness checks; an
image that exits during startup now fails creation instead of appearing as
`running`. Kubernetes uses the same Charter command in the Pod spec.

## Seeding and exporting workspaces

Rune Box never mounts your host directory. `copy_from` takes a one-time copy into
`/workspace` at create; later host edits do not sync in, and the agent's changes
stay in the Citadel. Pull results back out with:

```bash
runeward export <citadel-id> ./out
```

## Policy engines

Set `policy_engine` at the top level:

- `builtin` (default) — first-match tool + glob rules via `[[policy]]`.
- `cel` — CEL expressions over `{tool, arg}` via `[[cel]]`.
- `rego` — an OPA/Rego module returning `data.runeward.decision` via `[rego]`.

Instead of inline rules, a Charter can consume a signed OCI policy Archive so a
security team ships one artifact many Charters reuse:

```toml
[policy_bundle]
ref        = "oci://ghcr.io/acme/runeward-policies:v3"
verify_key = "<base64 ed25519 public key>"   # when set, a valid signature is REQUIRED
```

See the [`examples/`](https://github.com/Runewardd/runeward/tree/main/examples)
directory for complete, runnable Charters.
