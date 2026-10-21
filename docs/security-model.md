# Security model

!!! warning "Interactive sessions are not per-command policy gates"
    Per-action policy and approval decisions apply to calls routed through the
    control plane's governed tool APIs (REST, MCP, dashboard shell/file/code
    controls, and SDK adapters). The interactive terminal, optional browser IDE
    (code-server), and commands started directly inside a sandbox receive
    sandbox, network, and resource controls plus terminal recording / Chronicle
    open-close for IDE sessions, but Rune Box does not intercept each shell
    command or IDE keystroke for a policy verdict. Use governed tool calls when
    individual command approval and signed verdict evidence are required.

Rune Box's job is to reduce the blast radius of an autonomous agent. Knowing what
it does — and does not — protect against is essential to using it safely.

For **reporting vulnerabilities**, see
[SECURITY.md](https://github.com/Runeeward/runeward/blob/main/SECURITY.md).
Please disclose privately; do not open a public issue.

## What Rune Box provides

- **Isolation.** Each environment runs in a container (Docker/Podman), a Pod
  (Kubernetes) or its own microVM (`host.type = "microvm"`: Firecracker or
  libkrun) with its own workspace. Docker environments are hardened by default: all Linux
  capabilities dropped, `no-new-privileges`, a `--pids-limit`, and default
  memory/CPU ceilings (overridable via `RUNEWARD_SANDBOX_MEMORY`,
  `RUNEWARD_SANDBOX_CPUS`, `RUNEWARD_SANDBOX_PIDS`; set to `0` to disable).
  Setting `host.read_only = true` mounts the root filesystem read-only (with a
  writable `/tmp` and the writable workspace) on both Docker and Kubernetes.
  `host.seccomp` / `host.apparmor` pin a seccomp/AppArmor profile (Docker
  `--security-opt`; Kubernetes Localhost profiles), and Kubernetes pods default
  to the runtime's seccomp profile rather than Unconfined.
  A Charter can explicitly override an application image's entrypoint with
  `host.command`; Docker/Podman creation requires the process to remain alive
  across post-start checks before the Citadel is reported as running.
- **Control-plane authentication.** `runeward serve` binds `127.0.0.1` by
  default and refuses any non-loopback `--bind` unless authentication is set (an
  API token via `--token` / `RUNEWARD_API_TOKEN`, or an RBAC store). When set it
  is required on every request — REST, `/mcp`, the terminal WebSocket, and the
  dashboard. A non-loopback listener also refuses plaintext HTTP unless TLS is
  configured with `--tls-cert`/`--tls-key` or the operator explicitly passes
  `--allow-insecure-http` behind a trusted TLS-terminating proxy. Request bodies
  are size-capped to bound memory use.
- **RBAC / multi-principal auth.** Setting `RUNEWARD_AUTHZ_FILE` to a JSON store
  of principals (each with its own token, an allowed-profile glob list, and
  launch, approval-profile, and admin scopes) upgrades the single shared token to per-principal
  access: the server enforces which profiles a caller may launch and whether it
  may resolve approvals, and records the principal name as the audit actor.
  `/v1/whoami` reports honest `can_launch` / `can_approve` flags;
  `/v1/charters` and policy simulation are scoped to launchable Charters for
  non-admins. A principal has a resource-owning `tenant` and an independently
  attributed actor `name`; several agents can therefore collaborate without
  sharing one identity. Each Citadel records its owning tenant; a non-admin can see
  and act on only its tenant's Citadels (an ownership guard enforces this on every
  `/v1/citadels/{id}` route), while admins see all. The dashboard has an
  interactive token login (backed by `/v1/whoami`) that gates create/approve
  controls to what the caller is permitted; the static dashboard shell loads
  without a token so the login screen can render, but the API always requires
  one. Recovery snapshots are tenant-scoped and persisted. HTTP MCP uses the
  same per-request principal and ownership rules as REST; stdio MCP binds one
  process to the principal selected by `RUNEWARD_MCP_DEFAULT_TOKEN` or the
  credential saved by `runeward auth login`.
- **HTTP hardening.** Responses set `nosniff`, frame denial, no-referrer, and a
  restrictive Permissions Policy. API/MCP responses are no-store and use a
  deny-all content policy; dashboard assets use the explicit dashboard CSP.
- **OIDC authentication.** `RUNEWARD_OIDC_ISSUER` plus
  `RUNEWARD_OIDC_AUDIENCE` enables RS256 JWT verification from the provider's
  JWKS. Rune Box maps only signed claims: `runeward_tenant`,
  `runeward_profiles`, `runeward_approval_profiles`,
  `runeward_can_approve`, and `runeward_admin`. Issuer, audience, expiry,
  not-before, algorithm, key id, and signature are checked. Non-loopback issuer
  and JWKS endpoints must use HTTPS.
- **Signed Cohort leases.** Claim returns a short-lived HMAC-signed
  `lease_token` bound to Cohort, task, actor, and expiry. Heartbeat returns a
  refreshed token; complete/fail require the current token. Listing a task never
  exposes its lease capability.
- **Durable state.** Cohort boards, snapshots, and provider-neutral Run records
  use private atomic state-file replacement. A run still marked active after a
  control-plane restart is closed as `interrupted` rather than appearing live.
- **Cost / token budgets.** Agents or Cohort workers report model usage to
  `POST /v1/citadels/{id}/usage`; usage accrues per Citadel and per Charter
  (surfaced in Prometheus and the Citadel view). A Charter's `rationing.max_tokens`
  / `rationing.max_cost_usd` caps are enforced fail-closed — once exceeded, further
  governed tool calls are denied.
- **Attributed approvals.** Resolving an approval records *who* decided it (the
  RBAC principal name, else `X-Runeward-Actor`, else the peer address) in the
  audit ledger.
- **Deny-by-default egress, enforced at L3 on both backends.** Network access is
  denied unless explicitly allowlisted. Cooperative mode points the sandbox at
  the proxy via `HTTP(S)_PROXY` (the host proxy requires a per-cell credential);
  strict mode (`network.enforce = "strict"`) enforces transparently at the
  kernel: on Kubernetes via an iptables init container + sidecar sharing the pod
  netns, and on Docker via a `NET_ADMIN` egress sidecar that owns the netns
  (the sandbox joins it with `--network container:…`). In strict mode all TCP is
  redirected through the proxy regardless of proxy env, so code that ignores it
  can't bypass the allowlist. The strict path also drops non-DNS UDP (blocking
  QUIC/HTTP3 bypass) and IPv6 egress; setting `RUNEWARD_DNS_RESOLVERS`
  (comma-separated IPs) additionally confines DNS (UDP+TCP :53) to those
  resolvers, closing DNS as a covert exfil channel.
- **Credential broker.** A Charter's `[[credential]]`s are resolved by the
  control plane (from `env://`, `vault://`, `aws://`, `gcp://` or 1Password
  `op://` references) and never enter the Citadel: the agent gets an opaque
  `rwph_…` placeholder in `placeholder_env`, and the egress proxy swaps it for
  the real secret only on requests to the `[[endpoint]]` that owns it (and
  refuses it, as `placeholder-misuse`, anywhere else). Inspected endpoints are
  TLS-terminated with a per-Citadel CA the sandbox trusts (installed at
  `/etc/runeward/ca/`, with `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`,
  `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `GIT_SSL_CAINFO` pointing at a
  bundle of the image's roots plus that CA) and checked per request.
  `require-approval` requests wait in Conclave like governed tool calls, and
  every broker decision is Chronicled as tool `egress` and listed on the
  Citadel's perimeter log. `RUNEWARD_BROKER_UPSTREAM_CA` adds private
  upstream roots.
- **Endpoint binaries.** An `[[endpoint]]` with `binaries` is usable only by
  those executables: before forwarding a byte or attaching a credential, the
  broker asks the in-sandbox supervisor which executable holds the connection
  and refuses anything else (reason code `binary`). It is enforced, not
  advisory, and fails closed; see [Endpoint binaries](#endpoint-binaries)
  below.
- **In-sandbox confinement.** A Charter with `[filesystem]` or `[process]`
  runs the agent under `runeward-supervisor` as PID 1: Landlock limits the
  agent to the listed paths, a seccomp filter blocks ptrace, namespace
  creation and similar escapes, and the agent runs as the Charter's non-root
  identity with every capability cleared. Governed execs go through
  `runeward-supervisor exec` with the same confinement. The supervisor's
  enforcement report is Chronicled and raised on the Citadel;
  `landlock = "required"` or `[process]` refuse to start on a kernel that
  cannot enforce it (the guest kernel under Kata, gVisor's own kernel under
  runsc), and a required Landlock that is not enforced fails the create.
  The sandbox's root holds only `SETUID`, `SETGID` and `CHOWN`, with no
  privilege escalation, until the supervisor drops them.
  - *Docker/Podman* run the binary the sandbox image carries
    (`deploy/Dockerfile.sandbox`); a best-effort `[filesystem]` on an image
    without it runs unconfined, and that is recorded.
  - *Kubernetes* never takes the binary from the sandbox image: an init
    container from the egress image (`deploy/Dockerfile.egress`), running as
    root with every capability dropped, copies it into a memory-backed
    emptyDir mounted read-only at `/run/runeward/bin` and writes the config
    documents into the root-only `/run/runeward`; under strict egress the
    iptables init container does this instead (see
    [isolation](isolation.md) for the Firecracker drive budget). Pod exec
    cannot pick a user, so the backend's own operations (workspace tar
    streams, file projection, the isolation probe) also go through the
    supervisor, as the agent identity without Landlock or seccomp, as
    Docker's `exec -u` does. Kubernetes cannot read an image's `USER`, so
    the agent identity must come from the Charter (`[process] run_as_user`
    or `host.user`). The control plane runs the image's own `sh`, `chown`
    and `cat` as the container's root (to set an exec's working directory,
    hand the workspace to the agent and read the report), as Docker runs
    its `chown`: the agent cannot change root-owned image files.
- **Per-action policy and approvals.** `allow` / `deny` / `require-approval`
  verdicts, with human-in-the-loop gates for risky operations.
- **Guardrails.** Hard caps on wall-clock, exec count, egress requests, and
  token/spend budgets, plus retry-loop detection.
- **Tamper-evident audit.** An append-only, hash-chained, ed25519-signed ledger,
  independently verifiable offline. Events can also stream in real time to a
  webhook or file sink (`RUNEWARD_AUDIT_WEBHOOK_URL` / `RUNEWARD_AUDIT_FILE`)
  for SIEM ingestion, over a non-blocking queue that never stalls the ledger. A
  built-in anomaly detector flags novel egress targets, exec bursts, and denial
  spikes (`RUNEWARD_ANOMALY_*`).
- **Terminal session recording.** With `RUNEWARD_RECORD_TERMINALS=1`, governed
  terminal sessions are captured as asciinema v2 casts under the state dir and
  can be replayed with `runeward replay` as part of the audit trail.
- **Read-only Live chat.** Conversation turns are opt-in messages published by
  an agent harness, not automatic capture of private agent UI text. Rune Box
  bounds each Citadel's in-memory history, applies declared-secret and
  credential-pattern redaction, strips terminal controls, and streams through
  an ownership-checked, same-origin WebSocket using a short-lived scoped ticket.
  The observer socket accepts no application input. Live chat is operational
  visibility; the signed Chronicle remains the authoritative action evidence.
- **No host mounts.** `copy_from` copies into the sandbox; the host tree is never
  mounted. Request-time overrides are administrator-only. Set
  `RUNEWARD_COPY_FROM_ROOTS` (a colon-separated allowlist) to confine which host
  directories `copy_from` may read; sources outside the roots fail creation.
- **Kubernetes multi-tenancy.** The managed namespace carries Pod Security
  Admission labels (`RUNEWARD_K8S_PSA_ENFORCE`, or the chart's
  `podSecurityStandard`), Citadel containers always drop `ALL` capabilities and
  disable privilege escalation (a supervised one adds back `SETUID`, `SETGID`
  and `CHOWN` for the supervisor, which the `baseline` standard allows, and
  runs as root until the supervisor drops to the agent, which `restricted`
  does not), and an optional default-deny NetworkPolicy
  (DNS-only egress) isolates Citadel pods (`RUNEWARD_K8S_NETWORK_POLICY`, or the
  chart's `networkPolicy.enabled`) so environments can't reach each other or the control
  plane laterally.
- **Admission enforcement defaults.** The validating ClusterPolicy webhook is
  fail-closed (`failurePolicy: Fail`) so webhook outages block admission for
  governed resources. The mutating default-profile webhook is best-effort
  (`failurePolicy: Ignore`) and only fills missing `spec.profile`.
- **Supply-chain assurance.** Releases are cosign-signed (keyless) with SBOMs,
  and CI runs SAST (gosec, CodeQL), dependency/vuln scanning (govulncheck, Trivy),
  per-image CVE scans, and a DAST baseline, with Dependabot keeping dependencies
  current. Gosec uploads the complete SARIF report for triage and blocks releases
  on every unsuppressed HIGH-severity result; accepted architecture findings use
  narrow, source-local `#nosec` comments with justification.

## In scope (please report)

- Citadel escape from an environment to the host or another environment.
- Bypass of the egress allowlist, policy engine, or approval gates.
- Audit-ledger forgery or silent tampering that verification would miss.
- Path traversal / writes outside the intended workspace (e.g. tar-slip).
- Auth/authorization flaws in the REST API, WebSocket terminal, browser IDE
  proxy, or admission webhook.
- Secret leakage in logs, the ledger, or the dashboard.

## Operator responsibility (out of scope)

- Security of the container runtime, host kernel, and Kubernetes cluster — keep
  them patched.
- Trustworthiness of images referenced by Charters and of the agents/CLIs you run
  inside an environment.
- Secrets you place in Charters; Rune Box redacts *declared* secret values from
  the ledger and additionally masks common credential shapes (API keys, bearer
  tokens, PEM keys, `password=`/`token=` pairs) wherever they appear, but
  pattern matching is best-effort and can't catch every custom format.
- Network exposure of `runeward serve`. It binds `127.0.0.1` and requires an API
  token before any non-loopback bind, but you still choose the token strength,
  terminate TLS appropriately, and configure static RBAC or OIDC rather than a
  shared token for team deployments.
- Denial of service from workloads you explicitly grant large resource limits.

## Operational notes

!!! warning "One writer per ledger"
    The audit ledger is single-writer, protected by a file lock. Give each running
    instance its own `RUNEWARD_STATE_DIR`. Two processes sharing one ledger produce
    out-of-order/duplicate records, permanently breaking the hash chain so
    verification reports tampering.

!!! note "Same-origin WebSocket"
    The dashboard terminal WebSocket enforces a same-origin check to prevent
    cross-site hijacking, and state-changing REST requests reject mismatched
    browser `Origin`s. Per-IP rate limiting defaults to 50 requests/sec; tune
    `RUNEWARD_RATE_LIMIT` or explicitly set it to `off` for trusted benchmarks.
    Front the control plane with TLS in production.

!!! note "Experimental browser IDE"
    With `RUNEWARD_ENABLE_EXPERIMENTAL_IDE=1` and Charter `[ide] enabled`, serve
    reverse-proxies code-server inside the environment. That session is workspace-equivalent
    interactive access (not per-keystroke policy). Cursor/Claude Desktop/Codex
    GUIs are not embedded; GitHub Copilot is not first-class on code-server
    (Open VSX). Details and limits: [Browser IDE](browser-ide.md).

Rune Box is defense-in-depth, not a hard isolation boundary. Its default
container backend shares the host kernel, so a determined escape via a kernel or
runtime vulnerability is possible. For untrusted or adversarial workloads, add
VM-grade isolation by setting `host.runtime_class` in the profile to a
sandboxed runtime. On Kubernetes this maps to `runtimeClassName` (e.g. `gvisor`
or `kata`); on Docker it maps to `docker run --runtime` (e.g. `runsc` for
gVisor; for Kata, the name it is registered under in `daemon.json`, such as
`kata` pointing at the `containerd-shim-kata-v2` or `kata-runtime` binary, or
the containerd runtime handler `io.containerd.kata-qemu.v2`). The runtime must
first be installed and registered with your engine. `runeward runtime install
gvisor --apply` downloads and registers gVisor for Docker; Kata itself is not
installed by Rune Box (`runtime install kata --apply` only registers an
existing Kata install with Docker, or applies a RuntimeClass on Kubernetes). A
name the engine doesn't recognize fails environment creation rather than silently falling back to the
shared-kernel runtime. `runeward runtime check` probes Docker and Kubernetes for
registered `runsc`/`kata` runtimes and `runeward runtime guide` prints the setup
steps. microVM runtimes (Kata Containers with QEMU or Cloud Hypervisor, and
Firecracker on Kubernetes; `krun` is refused because it cannot exec into a
running guest) are supported the same way, and the reported tier is derived from
evidence collected inside the sandbox, not from the runtime's name: see
[Isolation and runtimes](isolation.md). `host.type = "microvm"` boots a
Firecracker or libkrun microVM per Citadel directly, with no container engine:
see [Native microVMs](#native-microvms) below. For the strictest cases, also
use a disposable host.
Rune Box's sweet spot is governing a cooperative-but-fallible agent, not caging
code whose goal is to break out.

### Endpoint binaries

```toml
[network]
default = "deny"
enforce = "strict"

[[endpoint]]
name = "github"
host = "api.github.com"
protocol = "rest"
credential = "github"
binaries = ["/usr/bin/gh", "/usr/bin/git"]
```

**What a binary is.** The executable file the kernel runs for a process, the
target of `/proc/<pid>/exe`, matched by file identity (device and inode)
against the listed paths as they were when the Citadel started. A listed
symlink matches the file it points to (`/usr/bin/python3` matches a process
running `/usr/bin/python3.11`), a hard link matches, a copy of an allowed
binary at another path does not, and a file put at a listed path after start
does not. For an interpreter the binary is the interpreter: `python3
script.py` and a `#!/usr/bin/env python3` script are both `python3.11`, so
listing an interpreter (or a shell, `env`, `busybox`) allows every program it
runs; `runeward validate` warns about that. Scripts are never identified by
name, since argv is chosen by the caller and proves nothing.

**How it is enforced.** For every connection to such an endpoint the broker
sends the in-sandbox attribution helper the connection's sandbox-side address
and destination with a fresh nonce. The helper finds the socket in
`/proc/net/tcp{,6}`, every process in the Citadel holding it (each thread's
descriptor table), and each holder's executable, and answers with an
HMAC-SHA256 tag under a per-Citadel key. The broker forwards only if the
answer verifies and every holder is a listed binary; in `mode = "audit"` it
records `audit-would-deny` and forwards. Each decision records the attributed
`binary` and `binary_enforced` (true when enforced, false in audit mode), on
the perimeter list and in the Chronicle.

The helper is started by `runeward-supervisor` (PID 1) before the agent, as a
separate process: it pins the listed binaries, binds an abstract Unix socket
in the Citadel's network namespace (`@runeward-attribution`, which the
strict-egress sidecar shares), drops to the agent's uid (needed to read the
agent's `/proc/<pid>/fd` without `CAP_SYS_PTRACE`), sets `no_new_privs`,
installs the supervisor's seccomp filter and turns non-dumpable. It has no
Landlock domain on purpose: Landlock only lets a process inspect processes in
its own domain, so a Landlocked helper could not see the agent at all (and the
same rule keeps a Landlocked agent from inspecting the helper). The key
reaches the helper on its stdin from the root-only supervisor config and the
sidecar in its root-only broker document; it is never in an environment
variable, on a command line, in the report or in a log line.

**Threat model.** The agent is untrusted and shares the helper's uid. It
cannot forge or replay an answer: it never holds the key, cannot read the
helper's memory or descriptors (non-dumpable; `ptrace`, `process_vm_readv`
and `pidfd_getfd` are denied by its seccomp filter), and every answer is
bound to the broker's nonce and the connection's addresses. It can connect to
the helper's socket, or take its name if the helper dies, but answers it
produces fail verification. Everything that goes wrong fails closed: no
answer, a bad tag, a socket nobody in the Citadel holds, a holder the helper
cannot inspect (another uid such as an operator's root `docker exec`, or a
non-dumpable process), and any holder that is not listed all refuse the
connection.

**Where it is enforced, and where it is refused.** Attribution needs the
broker to share the Citadel's network namespace and kernel, and the
supervisor to run, so:

- **Docker and Podman** with strict egress and a container runtime (runc,
  crun): enforced. Cooperative egress cannot attribute (the broker runs in
  the control plane and sees only NATed connections), so a Charter with
  `binaries` and without strict egress is an error in `runeward validate`
  and refused at create, the same way `landlock = "required"` is refused on a
  kernel without Landlock. gVisor and VM runtimes keep the Citadel's sockets
  out of the sidecar's sight and are refused at create.
- **Kubernetes:** the sidecar shares the Pod's network namespace (inside the
  guest for Kata, which runs the whole Pod in one VM), and the broker document
  carries the attribution socket and key. Until the supervisor runs in the
  Pod, a Charter with `binaries` requires it and is refused.
- **Native microVMs** (`host.type = "microvm"`): not supported. The broker
  runs on the host, outside the VM, so it cannot reach the helper inside the
  guest; `runeward validate` reports an error and the create is refused.

`binaries` requires the supervisor even without `[filesystem]` or
`[process]`, so the agent needs a non-root identity (`[process] run_as_user`,
`host.user`, or an image `USER`).

**Residual risks.**

- Binary identity is not code identity. An allowed interpreter runs any
  script, and an allowed dynamically linked binary can be made to load other
  code (`LD_PRELOAD`, plugins, extensions, `git` hooks and helpers). Prefer
  static, single-purpose binaries, and pair `binaries` with request rules.
- Attribution happens when the connection is accepted. A holder that later
  hands the socket to another process (`SCM_RIGHTS`, an inherited descriptor)
  is not re-checked; that needs the allowed binary's cooperation.
- The agent can kill the helper (same uid). That only makes every
  binary-restricted endpoint refuse until the Citadel is restarted.
- A process the helper cannot inspect anywhere in the Citadel, while it holds
  the socket, makes the connection refuse; an operator running a root shell
  that holds such a socket will see refusals.

### Native microVMs

With `host.type = "microvm"` each Citadel is its own VM (Firecracker or
libkrun on KVM), so a guest kernel or runtime exploit lands in that VM, not
on the host kernel. What crosses the boundary, and why:

- **Disks.** The image disk is attached read-only and shared by the VMs of
  that image; the guest writes into memory. The workspace is a per-Citadel
  disk image. The host never mounts either: workspace export, snapshots and
  file reads go through the guest agent, so the host does not interpret a
  filesystem the guest could have corrupted. Image layers are untrusted
  input: they are verified against their digests and unpacked into a staging
  directory without ever following a link out of it, as an unprivileged user.
- **No network device.** The guest has none (libkrun's socket-impersonation
  networking is disabled). Its only way out is a vsock port the host maps to
  a per-Citadel Unix socket served by the Charter's egress proxy, so
  `default = "deny"` and the request broker cannot be bypassed from inside
  the guest, even by its root; non-HTTP traffic has no path at all. The
  in-cell IDE is therefore unavailable.
- **The guest agent** (`runeward-vmagent`, PID 1) is inside the boundary: a
  root process in the guest can replace or impersonate it. That only affects
  that Citadel's own exec, files and isolation evidence; the verdict is
  still capped by the monitor (it can never claim more than `vm`), the host
  side confirms the monitor process it launched, and egress enforcement is
  on the host. Commands and file operations run as the Citadel's user after
  an identity switch, not as the agent's root.
- **The monitor** runs as the Rune Box user with access to `/dev/kvm`.
  Firecracker applies its built-in seccomp filters; it is not run under its
  jailer. libkrun runs in the `runeward-krun` helper process. Neither gets a
  network device or a shared host directory.
- **Secrets.** Environment values (including broker placeholders) reach the
  guest over the agent's vsock stream, never on the kernel command line or
  in a file on the host; broker credentials stay in the control plane.

### Broker secrets in the egress sidecar

In cooperative mode on Docker/Podman the broker runs inside the control plane,
so resolved credentials never leave it. Strict mode and Kubernetes run the
proxy in a sidecar, which needs the secrets to inject them. The control plane
hands the sidecar a `runeward.egress.broker.v1` document (endpoints, resolved
credential values, the placeholders already set in the Citadel, and the
per-Citadel CA certificate and private key) through `runeward-egress
--broker-config <file>`:

- **Docker/Podman strict mode:** a `0600` root-owned file copied into the
  stopped sidecar container before it starts; the sidecar reads it while still
  root, removes it, then drops to the proxy uid. The Citadel shares only the
  sidecar's network namespace, not its filesystem or processes.
- **Kubernetes:** a per-Citadel Secret mounted into the egress container only
  (world-readable inside that one mount, because kubelet makes Secret files
  root-owned while the proxy runs unprivileged); the sandbox container mounts
  only the CA certificate key of it.
- The document is never put on a command line or in an environment variable.

Anyone who can read the sidecar's filesystem or memory, or read Secrets in the
Citadel namespace, can read those credentials: the container engine, node
root, and Kubernetes principals with Secret read or `pods/exec` on the egress
container. Grant that access accordingly, or use cooperative mode on
Docker/Podman when credentials must stay on the control-plane host. Approval
routing is not available in the sidecar yet: a `require-approval` request
there is refused. Docker strict-mode decisions are read back from the
sidecar's log stream into the ledger; Kubernetes sidecar decisions are logged
by the sidecar but not yet Chronicled.
