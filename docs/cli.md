# CLI reference

The `runeward` binary is the primary entrypoint. A bare Charter name is shorthand
for `enter <charter>`.

## Global flags

| Flag | Description |
| --- | --- |
| `-c`, `--config-dir` | Pin Charter resolution to a directory (or `$RUNEWARD_CONFIG_DIR`). |
| `--help` | Help for any command. |
| `--version` | Print the version. |

## Environment

| Variable | Purpose |
| --- | --- |
| `RUNEWARD_CONFIG_DIR` | Default Charter directory. |
| `RUNEWARD_STATE_DIR` | Where the ledger, keys, terminal recordings, and Cohort state live. **Use a distinct value per running instance.** |
| `RUNEWARD_API_TOKEN` | Bearer token required on every control-plane request (see `--token`). |
| `RUNEWARD_AUTHZ_FILE` | JSON file of named RBAC principals (per-token profile/approval scopes); upgrades the single shared token to multi-principal auth. |
| `RUNEWARD_OIDC_ISSUER` / `RUNEWARD_OIDC_AUDIENCE` | Verify OIDC bearer JWTs and map signed Rune Box tenant/role claims. |
| `RUNEWARD_OIDC_JWKS_URL` | Optional explicit JWKS endpoint; normally discovered from the issuer. HTTPS required except on loopback. |
| `RUNEWARD_CREDENTIALS_FILE` | Optional path for the private client credential written by `runeward auth login`. |
| `RUNEWARD_RATE_LIMIT` | Requests/sec per client IP; defaults to `50`. Set `0`/`off` only for trusted benchmarks. |
| `RUNEWARD_RECORD_TERMINALS` | `1` records governed terminal sessions as asciinema casts under the state dir. |
| `RUNEWARD_AUDIT_WEBHOOK_URL` / `RUNEWARD_AUDIT_FILE` | Stream Chronicle events to a webhook and/or file sink in real time. |
| `RUNEWARD_COPY_FROM_ROOTS` | Colon-separated allowlist restricting `copy_from`/seed source directories. |
| `RUNEWARD_MCP_DEFAULT_TOKEN` | Selects the principal for a stdio MCP process; falls back to `runeward auth login`. |
| `RUNEWARD_K8S_NAMESPACE` | Namespace for k8s Citadel pods (default `runeward`). |
| `RUNEWARD_K8S_PSA_ENFORCE` | Pod Security Admission enforce level for the managed namespace (`privileged`\|`baseline`\|`restricted`; default `privileged`). |
| `RUNEWARD_K8S_NETWORK_POLICY` | Truthy creates a default-deny (DNS-only egress) NetworkPolicy in the managed namespace. |
| `RUNEWARD_DNS_RESOLVERS` | Comma-separated resolver IPs to confine DNS to under strict egress. |
| `RUNEWARD_ENABLE_EXPERIMENTAL_BROWSER` | Set to `1` to enable the experimental browser surface in a trusted deployment; disabled by default. |
| `RUNEWARD_ENABLE_EXPERIMENTAL_IDE` | Set to `1` to enable the optional in-Citadel browser IDE (code-server) + ticketed reverse proxy; disabled by default. See [Browser IDE](browser-ide.md). |
| `GITHUB_TOKEN` | Optional GitHub credential for an agent running inside a Citadel. Rune Box injects it only when the Charter explicitly references `op = "env://GITHUB_TOKEN"`; use a least-privilege token and never place it in an MCP config or committed file. Host `gh` authentication is not passed into a Citadel automatically. |
| `OPENAI_BASE_URL` | Optional OpenAI-compatible API endpoint for agents or SDKs. It is used only when a Charter explicitly injects it; leave it unset for the provider's default endpoint. For Docker-hosted gateways use a container-reachable address such as `http://host.docker.internal:11434/v1` and allow the hostname in the Charter's network policy. |

Provider and source-control variables are not ambient Citadel credentials. They
remain on the host unless a Charter deliberately imports them with an `env://`
secret source, where they become subject to readiness validation, redaction,
and the Charter's egress policy.

## Commands

| Command | Description |
| --- | --- |
| `runeward auth login\|status\|logout` | Save or remove a client credential using OIDC device flow or `--token-stdin`. |
| `runeward init [project-dir]` | Create `.runeward/quickstart.toml` without overwriting an existing policy. |
| `runeward quickstart [project-dir]` | Prove allow, pre-execution denial, and signed audit. |
| `runeward doctor [charter] [--json]` | Check policy, runtime, required secret sources, image, and state readiness. |
| `runeward enter <charter> [-- cmd...]` | Create a Citadel and open a shell, or run a one-shot command. |
| `runeward serve [--token ... --tls-cert ... --tls-key ...]` | Start the control plane: REST API + web dashboard (default `127.0.0.1:8080`). |
| `runeward mcp [--http --tls-cert ... --tls-key ...]` | Run stdio or streamable-HTTP MCP exposing governed tools to an IDE/agent. |
| `runeward list` | List reachable Charters. |
| `runeward print <charter>` | Print a Charter's resolved, secret-redacted policy. |
| `runeward validate <charter> [--strict]` | Statically lint a Charter (missing images, unresolved secrets, unreachable rules, duplicate env). |
| `runeward policy test <charter> --cases <file>` | Simulate a Charter's policy against sample actions, exiting non-zero on mismatch. |
| `runeward policy scaffold [template] [--list]` | Print a ready-made policy template for a common control. |
| `runeward policy learn <evidence-or-chronicle.json>` | Print exact, reviewable proposals from a verified audit trail. |
| `runeward evidence export <charter> [-o file]` | Package the resolved policy and signed Chronicle events. |
| `runeward evidence verify <file>` | Verify the policy digest, event chain, and every signature. |
| `runeward charter sign\|verify <file>` | Produce/verify a detached ed25519 signature over a Charter. |
| `runeward runtime check\|guide\|install <gvisor\|kata>` | Inspect, explain, or install hardened runtimes (gVisor/Kata). |
| `runeward replay <cast>` | Replay a recorded terminal session (asciinema v2 cast). |
| `runeward export <citadel-id> <dest-dir>` | Copy a Citadel workspace back to the host (Docker and k8s). |
| `runeward cohort ...` | Drive multi-agent Cohorts — see [Cohorts](fleets.md). |
| `runeward chronicle verify <bundle.json>` | Verify an exported, signed Chronicle transcript offline. |
| `runeward archive ...` | Manage signed OCI policy Archives (`keygen`, `push`, `pull`). |
| `runeward controller` | Run the Kubernetes controller (watches CRDs). |
| `runeward webhook` | Run the admission webhook. |
| `runeward up` | One-command install of the in-cluster control plane. |
| `runeward version` | Print version information. |

## Examples

```bash
# First-run proof
runeward quickstart

# Interactive Citadel
runeward --config-dir examples enter ns-auto

# One-shot command
runeward --config-dir examples enter ns-auto -- python --version

# Control plane with an isolated state dir
RUNEWARD_STATE_DIR=/tmp/rw runeward --config-dir examples serve

# Verify an exported Chronicle bundle
runeward chronicle verify ./transcript.json

# Sign and publish a policy Archive
runeward archive keygen --out ./keys
runeward archive push oci://ghcr.io/acme/runeward-policies:v3 \
  --policy prod.rego --engine rego --key ./keys/bundle.key

# Authenticated control plane on a non-loopback bind
RUNEWARD_API_TOKEN=$(openssl rand -hex 32) \
  runeward --config-dir examples serve --bind 0.0.0.0 --port 8443 \
  --tls-cert ./tls/server.crt --tls-key ./tls/server.key

# OIDC device login for Cohort CLI and stdio MCP clients
runeward auth login --issuer https://id.example.com \
  --client-id runeward-cli --audience runeward

# Lint a Charter and unit-test its policy
runeward --config-dir examples/safe validate --strict
runeward --config-dir examples policy test ns-auto \
  --case "tool=shell,action=rm -rf /,expect=deny"

# Scaffold a common policy and append it to a Charter
runeward policy scaffold package-approval >> mycharter.toml

# Export portable evidence, verify it, and draft reviewed policy additions
runeward --config-dir examples evidence export ns-auto -o evidence.json
runeward evidence verify evidence.json
runeward policy learn evidence.json > proposed-policy.toml

# Install and verify a hardened runtime (dry-run by default; --apply to execute)
runeward runtime install gvisor            # prints the plan
runeward runtime install gvisor --apply    # downloads + registers runsc
runeward runtime check                     # confirm it's registered
```
