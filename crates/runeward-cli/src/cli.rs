//! The command tree (clap) and its dispatch.

use std::ffi::OsString;
use std::io::Write;

use anyhow::{Result, anyhow};
use clap::{Args, CommandFactory, Parser, Subcommand};

use crate::cohort::{CohortOptions, FleetClient};
use crate::common::{expand_home, go_abs, go_io_error};
use crate::remote::Out;

const ROOT_LONG: &str =
    "Rune Box applies policy, human approvals, resource limits, and signed audit
to AI-agent sandboxes running on Docker, Podman, or Kubernetes. Rune Box calls
its policy files Charters and its sandboxes Citadels, but common terms come first.

Exit codes:
  0  success
  1  error (including malformed or unknown requests)
  3  refused by policy, a human approval gate, missing permission, or an
     unmet isolation floor; nothing ran
  4  refused for a spent budget, capacity or load shedding; nothing ran and
     retrying later may succeed
A refusal prints `refused (<reason>, retryable=<bool>, request_id=<id>): <message>`.";

/// `runeward`: policy, approvals, and signed audit for AI agents.
#[derive(Debug, Parser)]
#[command(
    name = "runeward",
    about = "Policy, approvals, and signed audit for AI agents",
    long_about = ROOT_LONG,
    disable_version_flag = true
)]
pub struct Cli {
    /// pin policy-file (Charter) resolution to a directory (or $RUNEWARD_CONFIG_DIR)
    #[arg(
        short = 'c',
        long,
        global = true,
        value_name = "DIR",
        default_value = ""
    )]
    pub config_dir: String,
    /// version for runeward
    #[arg(short = 'v', long = "version")]
    pub show_version: bool,
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Every subcommand.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Sign, publish, and fetch signed OCI policy Archives (bundles)
    #[command(subcommand)]
    Archive(ArchiveCmd),
    /// Log in with OIDC or manage a local client credential
    #[command(subcommand)]
    Auth(AuthCmd),
    /// Sign and verify Charter (profile) TOML files (provenance)
    #[command(subcommand)]
    Charter(CharterCmd),
    /// Offline Chronicle tools (verify exported audit transcript bundles)
    #[command(subcommand)]
    Chronicle(ChronicleCmd),
    /// Drive a governed Cohort by prompt (create, push prompts, run an agent on each)
    #[command(
        long_about = "Talks to a running `runeward serve`. `up` creates a Cohort and remembers its id;
`exec` runs a prompt on one Citadel (workspace accumulates); `add`+`run` fan
prompts out across all workers in parallel. Pick the agent with --agent and
the model with --model."
    )]
    Cohort(CohortArgs),
    /// Manage a running Citadel's workspace: fork, sleep, wake, status, perimeter
    #[command(
        long_about = "Talks to a running `runeward serve`. `fork` copies a Citadel's workspace into a
new, independent Citadel; `sleep` and `wake` stop and resume a persistent
workspace (Charter [workspace] persist = true) under the same id; `status`
shows the isolation tier the backend delivered, usage and the workspace
state; `perimeter` lists egress and request-broker decisions."
    )]
    Citadel(CitadelArgs),
    /// Start, follow and cancel agent-session turns
    #[command(
        long_about = "Talks to a running `runeward serve`. `turn` starts the next turn of an agent
session (its agent CLI with your prompt) and streams the output; `attach`
replays the transcript after a sequence number and then follows live
output, so a dropped client loses nothing; `cancel` stops the active turn
(it does not rewind)."
    )]
    Session(SessionArgs),
    /// Create and manage scheduled agent runs (cron or interval)
    #[command(
        long_about = "Talks to a running `runeward serve`. A schedule targets one Citadel or one
Cohort and fires on a 5-field UTC cron expression or a fixed interval
(at least 1m). Each firing asks policy, runs the optional precheck (the
agent starts only if it exits 0) and starts a fresh agent session."
    )]
    Schedule(ScheduleArgs),
    /// Generate the autocompletion script for the specified shell
    Completion {
        /// bash, zsh, fish, powershell or elvish
        shell: clap_complete::Shell,
    },
    /// Reconcile Rune Box Citadel/Cohort custom resources (Kubernetes)
    #[command(
        long_about = "Watch runeward.dev/v1alpha1 Citadel and Cohort resources and reconcile
them onto the governed Kubernetes backend. Apply the CRDs from deploy/crds
first (or use `runeward up`). Profiles are resolved from --config-dir /
$RUNEWARD_CONFIG_DIR, typically a mounted ConfigMap in-cluster."
    )]
    Controller {
        /// number of reconcile workers
        #[arg(long, default_value_t = 2)]
        workers: usize,
        /// watch all namespaces instead of $RUNEWARD_K8S_NAMESPACE
        #[arg(long)]
        all_namespaces: bool,
    },
    /// Check policy, runtime, image, and state readiness
    Doctor {
        /// Charter to check (default: quickstart, dev, ns-auto, else the first container Charter)
        charter: Option<String>,
        /// print a machine-readable readiness report
        #[arg(long)]
        json: bool,
    },
    /// Provision a sandbox from a policy and step into it
    #[command(
        long_about = "Provision a sandbox (Citadel) for the named policy (Charter/profile) and attach an interactive
shell, or run an explicit command after `--`."
    )]
    Enter {
        /// The Charter to provision
        charter: String,
        /// Command to run instead of an interactive shell (after `--`)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
        /// do not tear down the sandbox on exit
        #[arg(long)]
        keep: bool,
    },
    /// Export or verify a portable policy and signed-audit package
    #[command(subcommand)]
    Evidence(EvidenceCmd),
    /// Copy a sandbox workspace back out to a host directory
    #[command(
        long_about = "Export copies the /workspace of a running sandbox (Citadel; Docker or Kubernetes)
into a local directory. The Citadel is only read; the destination receives
a point-in-time copy of the agent's results, so later host edits never flow
back into the Citadel. This is the inverse of a Charter's host.copy_from."
    )]
    Export {
        /// The Citadel id
        citadel_id: String,
        /// The host directory to copy into
        dest_dir: String,
    },
    /// Create a runnable starter policy in .runeward/
    Init {
        /// Project directory (default: the current directory)
        project_dir: Option<String>,
        /// replace an existing starter policy
        #[arg(long)]
        force: bool,
        /// starter policy name
        #[arg(long, default_value = "quickstart")]
        name: String,
    },
    /// List policy files (Charters) reachable from here
    List,
    /// Run the MCP server wrapping Rune Box's governed tools (stdio or --http)
    #[command(
        long_about = "Expose Rune Box's governed sandbox (Citadel) tools over the Model Context Protocol.
By default it speaks stdio (for Claude Desktop / Cursor); with --http it
serves the streamable-HTTP transport at /mcp on 127.0.0.1 (a non-loopback
--bind requires --token or RUNEWARD_API_TOKEN)."
    )]
    Mcp(runeward_mcp::McpArgs),
    /// Author, inspect, learn, and test authority policies
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Render a policy file's resolved controls (redacted)
    #[command(
        long_about = "Resolve a policy file (Charter) and print its controls and projected env with secrets
redacted, so you can inspect the sandbox before starting it."
    )]
    Print {
        /// The Charter to render
        charter: String,
    },
    /// Create a starter policy and prove allow, deny, and signed audit
    Quickstart {
        /// Project directory (default: the current directory)
        project_dir: Option<String>,
        /// create the starter policy without launching a sandbox
        #[arg(long)]
        no_run: bool,
        /// replace an existing starter policy
        #[arg(long)]
        force: bool,
    },
    /// Replay a recorded terminal session (asciinema v2 cast)
    #[command(
        long_about = "Replay a governed terminal session captured as an asciinema v2
.cast file. By default timing is honored (idle gaps capped so replay
never stalls); pass --no-timing to dump the output instantly."
    )]
    Replay {
        /// The .cast file
        cast_file: String,
        /// honor recorded frame timing
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set,
              num_args = 0..=1, require_equals = true, default_missing_value = "true")]
        realtime: bool,
        /// dump output instantly, ignoring timing
        #[arg(long)]
        no_timing: bool,
    },
    /// Inspect and set up hardened container runtimes (gVisor/Kata)
    #[command(
        long_about = "Inspect this host for VM-grade isolation runtimes (gVisor's runsc and
Kata Containers) registered with Docker and/or Kubernetes, and print the
steps to wire them into Rune Box via a Charter's [host] runtime_class.

Run with no subcommand for a check; `runtime guide` prints full setup
instructions. See docs/security-model.md."
    )]
    Runtime(RuntimeArgs),
    /// Run the control plane: governed REST API + web dashboard
    #[command(
        long_about = "Start the Rune Box control plane. Every governed sandbox tool call is routed
through policy, budget/loop limits (Rationing), and the signed audit trail
(Chronicle). Serves the REST API, an approval inbox (Conclave),
inbox, an interactive terminal WebSocket, and (unless --no-ui) the web
dashboard.

Binds to 127.0.0.1 by default. Exposing it on another interface
(--bind) requires an API token (--token or RUNEWARD_API_TOKEN)."
    )]
    Serve(crate::serve::ServeArgs),
    /// Install Rune Box (CRDs + controller) into the current cluster
    #[command(
        long_about = "One-command install: applies the Rune Box CRDs and, unless --crds-only,
the controller bundle (namespace, RBAC, Deployment) via server-side apply.
Idempotent — safe to re-run to upgrade. Uses the ambient kubeconfig."
    )]
    Up {
        /// controller image (or $RUNEWARD_IMAGE); defaults to runeward:latest
        #[arg(long, default_value = "")]
        image: String,
        /// install only the CRDs, not the controller
        #[arg(long)]
        crds_only: bool,
    },
    /// Statically validate and lint policy files (Charters)
    #[command(
        long_about = "Resolve policy files (Charters) and lint them for likely misconfigurations —
missing images, unresolved secret references, dead egress and
policy rules — without launching anything. Exits non-zero on any
error-severity finding; --strict also fails on warnings."
    )]
    Validate {
        /// Charters to validate (default: every resolvable Charter)
        charters: Vec<String>,
        /// treat warnings as failures (exit non-zero)
        #[arg(long)]
        strict: bool,
    },
    /// Print the Rune Box version
    Version,
    /// Enforce Rune Box ClusterPolicy on Citadel/Cohort (admission webhook)
    #[command(
        long_about = "Serve a validating+mutating admission webhook that applies
runeward.dev/v1alpha1 ClusterPolicy defaults and guardrails to Citadel
and Cohort resources. Apply the ClusterPolicy CRD first (or use
`runeward up`). The webhook self-registers its configurations and serves
HTTPS with a self-signed certificate it mints on startup."
    )]
    Webhook {
        /// HTTPS port to serve admission requests on
        #[arg(long, default_value_t = 8443)]
        port: u16,
        /// name of the Service fronting the webhook (or $RUNEWARD_WEBHOOK_SERVICE)
        #[arg(long, env = "RUNEWARD_WEBHOOK_SERVICE", default_value = "")]
        service: String,
        /// Secret name used to persist/share the serving cert across restarts and replicas (default <service>-cert)
        #[arg(long, env = "RUNEWARD_WEBHOOK_CERT_SECRET", default_value = "")]
        cert_secret: String,
    },
}

/// `archive` subcommands.
#[derive(Debug, Subcommand)]
pub enum ArchiveCmd {
    /// Generate an ed25519 keypair for signing policy bundles
    Keygen {
        /// write bundle.key (0600) and bundle.pub to this directory instead of stdout
        #[arg(long, default_value = "")]
        out: String,
    },
    /// Push a signed policy bundle to an OCI registry
    Push {
        /// OCI reference
        reference: String,
        /// path to the policy file (.rego module, or TOML fragment with [[cel]] rules)
        #[arg(long, default_value = "")]
        policy: String,
        /// policy engine: rego or cel
        #[arg(long, default_value = "")]
        engine: String,
        /// optional Rego decision query (rego only)
        #[arg(long, default_value = "")]
        query: String,
        /// path to a base64 ed25519 private key file (from `archive keygen`)
        #[arg(long, default_value = "")]
        key: String,
        /// use http instead of https (local/insecure registries)
        #[arg(long)]
        plain_http: bool,
    },
    /// Pull (and optionally verify) a signed policy bundle
    Pull {
        /// OCI reference
        reference: String,
        /// base64 ed25519 public key (or a path to a file containing one); when set the signature is required
        #[arg(long, default_value = "")]
        verify_key: String,
        /// use http instead of https (local/insecure registries)
        #[arg(long)]
        plain_http: bool,
        /// write the raw policy to this file instead of printing it
        #[arg(long, default_value = "")]
        out: String,
    },
}

/// `auth` subcommands.
#[derive(Debug, Subcommand)]
pub enum AuthCmd {
    /// Log in using an OIDC device flow or a token read securely from stdin
    Login {
        /// OIDC issuer URL
        #[arg(long, env = "RUNEWARD_OIDC_ISSUER", default_value = "")]
        issuer: String,
        /// OIDC public client id
        #[arg(long, env = "RUNEWARD_OIDC_CLIENT_ID", default_value = "")]
        client_id: String,
        /// OIDC audience
        #[arg(long, env = "RUNEWARD_OIDC_AUDIENCE", default_value = "")]
        audience: String,
        /// OIDC scopes
        #[arg(long, default_value = "openid profile email")]
        scope: String,
        /// read a bearer token from stdin instead of using OIDC
        #[arg(long)]
        token_stdin: bool,
    },
    /// Show the current login without revealing its token
    Status,
    /// Remove the stored client credential
    Logout,
}

/// `charter` subcommands.
#[derive(Debug, Subcommand)]
pub enum CharterCmd {
    /// Sign a Charter TOML file, writing a detached signature
    Sign {
        /// The Charter file
        file: String,
        /// path to a base64 ed25519 private key file (from `archive keygen`)
        #[arg(long, default_value = "")]
        key: String,
        /// write the detached signature here (default <file>.sig; use - for stdout)
        #[arg(long, default_value = "")]
        out: String,
    },
    /// Verify a Charter TOML file against a detached signature
    Verify {
        /// The Charter file
        file: String,
        /// base64 ed25519 public key (or a path to a file containing one)
        #[arg(long, default_value = "")]
        verify_key: String,
        /// path to the detached signature file (default <file>.sig)
        #[arg(long, default_value = "")]
        sig: String,
    },
}

/// `chronicle` subcommands.
#[derive(Debug, Subcommand)]
pub enum ChronicleCmd {
    /// Verify an exported, signed Chronicle (audit) transcript bundle
    Verify {
        /// The exported bundle
        bundle: String,
    },
}

/// `evidence` subcommands.
#[derive(Debug, Subcommand)]
pub enum EvidenceCmd {
    /// Package the resolved policy and signed audit trail as JSON
    Export {
        /// The Charter
        charter: String,
        /// include only one sandbox/session (default: all events)
        #[arg(long, default_value = "")]
        session: String,
        /// write to a file, or - for stdout
        #[arg(short = 'o', long, default_value = "-")]
        output: String,
        /// replace an existing output file
        #[arg(long)]
        force: bool,
    },
    /// Verify the policy digest, hash chain, and every event signature
    Verify {
        /// The evidence package
        evidence: String,
    },
}

/// `policy` subcommands.
#[derive(Debug, Subcommand)]
pub enum PolicyCmd {
    /// Simulate a policy (Charter) against sample actions
    #[command(
        long_about = "Load a policy (Charter) and evaluate it offline against a table of
sample actions, asserting the verdict of each. Cases come from a TOML
file (--cases) and/or inline --case flags. Exits non-zero if any case
fails, so policy rules can be unit-tested in CI.

Cases file schema:

  [[case]]
  name   = \"block rm -rf\"   # optional label
  tool   = \"shell\"
  action = \"rm -rf /\"
  args   = [\"rm\", \"-rf\", \"/\"]  # optional argv vector
  expect = \"deny\"            # allow | deny | require-approval
"
    )]
    Test {
        /// The Charter
        charter: String,
        /// path to a TOML file of [[case]] assertions
        #[arg(long, default_value = "")]
        cases: String,
        /// inline case as key=value pairs, e.g. tool=shell,action=rm -rf /,expect=deny (repeatable)
        #[arg(long = "case")]
        case: Vec<String>,
    },
    /// Print a ready-made policy template for a common control
    #[command(
        long_about = "Print a ready-made policy snippet for a common control (deny prod
mutations, gate package installs, confine egress, …). Run without a
template name (or with --list) to see what's available, then paste the
output into a Charter:

  runeward policy scaffold package-approval >> mycharter.toml
"
    )]
    Scaffold {
        /// Template name
        template: Option<String>,
        /// list available templates
        #[arg(long)]
        list: bool,
    },
    /// Suggest exact policy rules from a prior audit trail
    #[command(
        long_about = "Read a portable evidence package or signed Chronicle bundle and print a
reviewable TOML draft. Denied and approval-gated actions retain their
verdict; --include-allowed also proposes exact rules for observed allows.
No policy file is modified automatically."
    )]
    Learn {
        /// Evidence package or Chronicle bundle
        input: String,
        /// also propose exact allow rules observed in the audit trail
        #[arg(long)]
        include_allowed: bool,
    },
}

/// Connection flags of the REST-client commands.
#[derive(Debug, Args)]
pub struct RemoteArgs {
    /// control-plane base URL (or $RUNEWARD_BASE)
    #[arg(
        long,
        global = true,
        env = "RUNEWARD_BASE",
        default_value = "http://127.0.0.1:8080"
    )]
    pub base: String,
    /// control-plane bearer token (or $RUNEWARD_API_TOKEN / `runeward auth login`)
    #[arg(long, global = true, default_value = "")]
    pub token: String,
    /// print the server's JSON instead of text
    #[arg(long, global = true)]
    pub json: bool,
}

/// `citadel` flags and subcommands.
#[derive(Debug, Args)]
pub struct CitadelArgs {
    #[command(flatten)]
    pub remote: RemoteArgs,
    #[command(subcommand)]
    pub command: CitadelCmd,
}

/// `citadel` subcommands.
#[derive(Debug, Subcommand)]
pub enum CitadelCmd {
    /// Copy a Citadel's workspace into a new, independent Citadel
    Fork {
        /// The Citadel id
        id: String,
        /// Charter for the fork (default: the source's); one not provably within the source's needs an administrator
        #[arg(long, default_value = "")]
        charter: String,
        /// agent name recorded on the fork's run
        #[arg(long, default_value = "")]
        agent: String,
        /// model recorded on the fork's run
        #[arg(long, default_value = "")]
        model: String,
    },
    /// Put a persistent Citadel to sleep now (workspace disk kept)
    Sleep {
        /// The Citadel id
        id: String,
    },
    /// Wake a sleeping Citadel under the same id
    Wake {
        /// The Citadel id
        id: String,
    },
    /// Show a Citadel's isolation tier, usage and workspace state
    Status {
        /// The Citadel id
        id: String,
    },
    /// List a Citadel's egress and request-broker decisions
    Perimeter {
        /// The Citadel id
        id: String,
    },
}

/// `session` flags and subcommands.
#[derive(Debug, Args)]
pub struct SessionArgs {
    #[command(flatten)]
    pub remote: RemoteArgs,
    #[command(subcommand)]
    pub command: SessionCmd,
}

/// `session` subcommands.
#[derive(Debug, Subcommand)]
pub enum SessionCmd {
    /// Start the next turn of an agent session and stream it
    Turn {
        /// The agent session id
        session: String,
        /// The prompt for the agent
        prompt: String,
        /// agent CLI to run: cursor | codex | claude (default: the session's)
        #[arg(long, default_value = "")]
        agent: String,
        /// model for this and later turns (default: the session's)
        #[arg(long, default_value = "")]
        model: String,
    },
    /// Replay an agent session after a sequence number, then follow it
    Attach {
        /// The agent session id
        session: String,
        /// replay events after this sequence number
        #[arg(long, default_value_t = 0)]
        after: i64,
    },
    /// Cancel the active turn (does not rewind)
    Cancel {
        /// The agent session id
        session: String,
    },
}

/// `schedule` flags and subcommands.
#[derive(Debug, Args)]
pub struct ScheduleArgs {
    #[command(flatten)]
    pub remote: RemoteArgs,
    #[command(subcommand)]
    pub command: ScheduleCmd,
}

/// `schedule` subcommands.
#[derive(Debug, Subcommand)]
pub enum ScheduleCmd {
    /// Schedule recurring agent runs for a Citadel or Cohort
    Create {
        /// target Citadel id
        #[arg(long, default_value = "")]
        citadel: String,
        /// target Cohort id (runs in its first member)
        #[arg(long, default_value = "")]
        cohort: String,
        /// 5-field cron expression, UTC (or --every)
        #[arg(long, default_value = "")]
        cron: String,
        /// fixed interval such as 30m or 6h, at least 1m (or --cron)
        #[arg(long, default_value = "")]
        every: String,
        /// prompt appended to the command as its last argument
        #[arg(long, default_value = "")]
        prompt: String,
        /// agent CLI to run when no command is given: cursor | codex | claude
        #[arg(long, default_value = "")]
        agent: String,
        /// model slug passed to the agent
        #[arg(long, default_value = "")]
        model: String,
        /// cheap check run first (whitespace-separated argv); the agent starts only if it exits 0
        #[arg(long, default_value = "")]
        precheck: String,
        /// explicit command to run instead of the agent CLI (after `--`)
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// List schedules (all visible, or one Citadel's or Cohort's)
    List {
        /// only this Citadel's schedules
        #[arg(long, default_value = "")]
        citadel: String,
        /// only this Cohort's schedules
        #[arg(long, default_value = "")]
        cohort: String,
    },
    /// Show one schedule
    Get {
        /// The schedule id
        id: String,
    },
    /// Delete a schedule
    Delete {
        /// The schedule id
        id: String,
    },
    /// Fire a schedule now (policy, precheck and budgets still apply)
    Run {
        /// The schedule id
        id: String,
    },
}

/// `cohort` flags shared by every subcommand.
#[derive(Debug, Args)]
pub struct CohortArgs {
    /// control-plane base URL (or $RUNEWARD_BASE)
    #[arg(
        long,
        global = true,
        env = "RUNEWARD_BASE",
        default_value = "http://127.0.0.1:8080"
    )]
    pub base: String,
    /// agent to run: cursor | codex | claude (or $AGENT)
    #[arg(long, global = true, env = "AGENT", default_value = "cursor")]
    pub agent: String,
    /// model slug passed to the agent (or $MODEL)
    #[arg(long, global = true, env = "MODEL", default_value = "")]
    pub model: String,
    /// Cohort id; defaults to the one saved by `cohort up`
    #[arg(long, global = true, default_value = "")]
    pub cohort: String,
    /// control-plane bearer token (or $RUNEWARD_API_TOKEN / `runeward auth login`)
    #[arg(long, global = true, default_value = "")]
    pub token: String,
    /// print the server's JSON instead of text (memory, note, brief, handoff, task)
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: CohortCmd,
}

/// `cohort` subcommands.
#[derive(Debug, Subcommand)]
pub enum CohortCmd {
    /// Create a Cohort (default Charter: build-fleet) and remember its id
    Up {
        /// The Charter
        charter: Option<String>,
    },
    /// Add a prompt to the shared Command Board (fanned out by `run`)
    Add {
        /// The prompt
        prompt: String,
    },
    /// Drain the Command Board: every worker builds pending prompts in parallel
    Run,
    /// up-if-needed + add + run, in one shot
    Build {
        /// The prompt
        prompt: String,
    },
    /// Run a prompt on ONE Citadel (--citadel, else the first) so changes accumulate
    Exec {
        /// The prompt
        prompt: String,
        /// target a specific citadel id (default: first in the cohort)
        #[arg(long, default_value = "")]
        citadel: String,
    },
    /// Show the Command Board
    Status,
    /// Copy every worker's /workspace to ./out (or <dir>)
    Export {
        /// Destination directory
        dir: Option<String>,
    },
    /// Tear down the Cohort and forget it
    Down,
    /// Read and write the Cohort's shared memory
    #[command(subcommand)]
    Memory(MemoryCmd),
    /// Leave a handoff note on a task
    Note {
        /// The task id
        task: String,
        /// The note text (at most 8 KiB)
        text: String,
    },
    /// Set (or with an empty brief clear) the brief an agent gets on a task
    Brief {
        /// The task id
        task: String,
        /// The brief text; empty clears it
        brief: String,
        /// the agent the brief is for ('*' for every agent)
        #[arg(long = "for", default_value = "*")]
        target: String,
    },
    /// Complete (or --requeue) a claimed task and leave a handoff note
    Handoff {
        /// The task id
        task: String,
        /// the lease token from the claim
        #[arg(long)]
        lease_token: String,
        /// the handoff note for whoever works on this next
        #[arg(long)]
        note: String,
        /// the result when completing
        #[arg(long, default_value = "")]
        result: String,
        /// give the task back to the board instead of completing it
        #[arg(long)]
        requeue: bool,
        /// the worker that claimed the task (ignored under RBAC, where it is the caller)
        #[arg(long, default_value = "cli")]
        owner: String,
    },
    /// Inspect and split Command Board tasks
    #[command(subcommand)]
    Task(TaskCmd),
}

/// `cohort memory` subcommands.
#[derive(Debug, Subcommand)]
pub enum MemoryCmd {
    /// Write an entry
    Put {
        /// The key (at most 256 bytes)
        key: String,
        /// The text (at most 16 KiB)
        text: String,
        /// tag the entry (repeatable)
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// only write if the current version is this (0: the key must be new)
        #[arg(long)]
        expected_version: Option<u64>,
    },
    /// Read one entry
    Get {
        /// The key
        key: String,
    },
    /// Search entries by text and tags (ranked, byte-capped)
    Search {
        /// Text to search for
        query: Option<String>,
        /// match this tag (repeatable)
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// most entries to return
        #[arg(long, default_value_t = 0)]
        limit: usize,
        /// byte budget for the returned texts
        #[arg(long, default_value_t = 0)]
        max_bytes: usize,
    },
    /// List every entry
    List,
    /// Delete an entry
    Delete {
        /// The key
        key: String,
        /// only delete if the current version is this
        #[arg(long)]
        version: Option<u64>,
    },
}

/// `cohort task` subcommands.
#[derive(Debug, Subcommand)]
pub enum TaskCmd {
    /// Show what an agent gets when it claims a task (brief, notes, parent, memory)
    Context {
        /// The task id
        task: String,
        /// whose brief to show (default: the caller)
        #[arg(long = "for", default_value = "")]
        target: String,
        /// byte budget of the memory slice
        #[arg(long, default_value_t = 0)]
        memory_bytes: usize,
    },
    /// Split a task: add a pending child task linked to it
    Child {
        /// The parent task id
        task: String,
        /// The child task's prompt
        payload: String,
    },
}

/// `runtime` flags and subcommands.
#[derive(Debug, Args)]
pub struct RuntimeArgs {
    /// exit non-zero if neither gVisor nor Kata is available (useful in CI)
    #[arg(long)]
    pub strict: bool,
    #[command(subcommand)]
    pub command: Option<RuntimeCmd>,
}

/// `runtime` subcommands.
#[derive(Debug, Subcommand)]
pub enum RuntimeCmd {
    /// Report which hardened runtimes are registered here
    Check {
        /// exit non-zero if neither gVisor nor Kata is available (useful in CI)
        #[arg(long)]
        strict: bool,
    },
    /// Print full gVisor/Kata setup instructions for Docker and Kubernetes
    Guide,
    /// Install and register a hardened runtime (gVisor/Kata) with Docker or Kubernetes
    #[command(
        long_about = "Install a VM-grade isolation runtime and wire it into a backend.

Dry-run is the DEFAULT: without --apply this prints the exact commands
and manifests it would run and mutates nothing. All downloads are
checksum-verified (fail closed); all shell-outs are timeout-bounded.

Examples:
  runeward runtime install gvisor                 # dry-run docker plan
  runeward runtime install gvisor --apply         # download+verify+register
  runeward runtime install gvisor --engine k8s    # print a RuntimeClass
  runeward runtime install kata --engine k8s --apply"
    )]
    Install {
        /// gvisor or kata
        runtime: String,
        /// target backend: "docker" or "k8s"
        #[arg(long, default_value = "docker")]
        engine: String,
        /// actually perform the install (default is a safe dry-run)
        #[arg(long)]
        apply: bool,
        /// gVisor release to install (e.g. "latest" or "20240101")
        #[arg(long, default_value = "latest")]
        version: String,
        /// k8s RuntimeClass name (default "gvisor"/"kata")
        #[arg(long, default_value = "")]
        runtime_class: String,
        /// optional sha256 pin for the runsc binary (hex); otherwise the bucket's .sha512 sidecar is required
        #[arg(long, default_value = "")]
        sha256: String,
    },
}

/// The real subcommands (plus help flags); any other first argument is a
/// Charter name to enter.
pub const RESERVED: &[&str] = &[
    "auth",
    "serve",
    "mcp",
    "list",
    "print",
    "version",
    "enter",
    "export",
    "cohort",
    "citadel",
    "session",
    "schedule",
    "chronicle",
    "archive",
    "controller",
    "webhook",
    "up",
    "validate",
    "policy",
    "charter",
    "replay",
    "runtime",
    "init",
    "quickstart",
    "doctor",
    "evidence",
    "help",
    "completion",
    "-h",
    "--help",
];

/// Injects `enter` before the first non-flag token when that token is not
/// a reserved subcommand, so `runeward <charter>` means `enter <charter>`.
pub fn rewrite_for_enter(args: Vec<OsString>) -> Vec<OsString> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].to_string_lossy();
        if a.starts_with('-') {
            // Flags that take a value skip it too; --config-dir is the only
            // one today.
            if a == "--config-dir" || a == "-c" {
                i += 1;
            }
            i += 1;
            continue;
        }
        if RESERVED.contains(&a.as_ref()) {
            return args;
        }
        let mut out = Vec::with_capacity(args.len() + 1);
        out.extend_from_slice(&args[..i]);
        out.push("enter".into());
        out.extend_from_slice(&args[i..]);
        return out;
    }
    args
}

/// Parses `argv` (without the program name) and runs the command. Returns
/// the process exit code: 0 on success, 1 on any error (usage errors too,
/// as the Go CLI does).
pub async fn execute(argv: Vec<OsString>) -> i32 {
    let mut full = vec![OsString::from("runeward")];
    full.extend(rewrite_for_enter(argv));
    let cli = match Cli::try_parse_from(full) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 1 } else { 0 };
            let _ = e.print();
            return code;
        }
    };
    match dispatch(cli).await {
        Ok(()) => 0,
        Err(e) => {
            let _ = std::io::stdout().flush();
            if let Some(r) = e.downcast_ref::<crate::cohort::Refused>() {
                eprintln!("{r}");
                return r.exit_code();
            }
            eprintln!("error: {e}");
            1
        }
    }
}

async fn dispatch(cli: Cli) -> Result<()> {
    let cfg = cli.config_dir.as_str();
    let Some(command) = cli.command else {
        if cli.show_version {
            println!("runeward version {}", crate::version::VERSION);
            return Ok(());
        }
        Cli::command().print_long_help()?;
        return Ok(());
    };
    if cli.show_version {
        println!("runeward version {}", crate::version::VERSION);
        return Ok(());
    }
    match command {
        Command::Archive(c) => match c {
            ArchiveCmd::Keygen { out } => crate::signing::keygen(&out),
            ArchiveCmd::Push {
                reference,
                policy,
                engine,
                query,
                key,
                plain_http,
            } => crate::signing::push(&reference, &policy, &engine, &query, &key, plain_http).await,
            ArchiveCmd::Pull {
                reference,
                verify_key,
                plain_http,
                out,
            } => crate::signing::pull(&reference, &verify_key, plain_http, &out).await,
        },
        Command::Auth(c) => match c {
            AuthCmd::Login {
                issuer,
                client_id,
                audience,
                scope,
                token_stdin,
            } => crate::auth::login(&issuer, &client_id, &audience, &scope, token_stdin).await,
            AuthCmd::Status => crate::auth::status(),
            AuthCmd::Logout => crate::auth::logout(),
        },
        Command::Charter(c) => match c {
            CharterCmd::Sign { file, key, out } => crate::signing::charter_sign(&file, &key, &out),
            CharterCmd::Verify {
                file,
                verify_key,
                sig,
            } => crate::signing::charter_verify(&file, &verify_key, &sig),
        },
        Command::Chronicle(ChronicleCmd::Verify { bundle }) => {
            crate::audit::chronicle_verify(&bundle)
        }
        Command::Cohort(args) => cohort(args).await,
        Command::Citadel(args) => citadel(args).await,
        Command::Session(args) => session(args).await,
        Command::Schedule(args) => schedule(args).await,
        Command::Completion { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "runeward",
                &mut std::io::stdout(),
            );
            Ok(())
        }
        Command::Controller {
            workers,
            all_namespaces,
        } => crate::kube::controller(workers, all_namespaces, cfg).await,
        Command::Doctor { charter, json } => {
            crate::onboarding::doctor(charter.as_deref(), json, cfg).await
        }
        Command::Enter {
            charter,
            command,
            keep,
        } => crate::enter::run(&charter, &command, keep, cfg).await,
        Command::Evidence(c) => match c {
            EvidenceCmd::Export {
                charter,
                session,
                output,
                force,
            } => crate::audit::evidence_export(&charter, &session, &output, force, cfg).await,
            EvidenceCmd::Verify { evidence } => crate::audit::evidence_verify(&evidence),
        },
        Command::Export {
            citadel_id,
            dest_dir,
        } => {
            let dest = go_abs(&expand_home(&dest_dir))?;
            runeward_backend::export(&citadel_id, std::path::Path::new(&dest)).await?;
            eprintln!("runeward: exported citadel {citadel_id} workspace -> {dest}");
            Ok(())
        }
        Command::Init {
            project_dir,
            force,
            name,
        } => crate::onboarding::init(project_dir.as_deref(), &name, force),
        Command::List => crate::inspect::list(cfg),
        Command::Mcp(args) => crate::serve::mcp(&args, cfg).await,
        Command::Policy(c) => match c {
            PolicyCmd::Test {
                charter,
                cases,
                case,
            } => crate::policy::test(&charter, &cases, &case, cfg),
            PolicyCmd::Scaffold { template, list } => {
                crate::policy::scaffold(template.as_deref(), list)
            }
            PolicyCmd::Learn {
                input,
                include_allowed,
            } => crate::policy::learn(&input, include_allowed),
        },
        Command::Print { charter } => crate::inspect::print(&charter, cfg),
        Command::Quickstart {
            project_dir,
            no_run,
            force,
        } => crate::onboarding::quickstart(project_dir.as_deref(), no_run, force).await,
        Command::Replay {
            cast_file,
            realtime,
            no_timing,
        } => replay(&cast_file, realtime && !no_timing),
        Command::Runtime(args) => match args.command {
            None => crate::runtime::check(args.strict).await,
            Some(RuntimeCmd::Check { strict }) => crate::runtime::check(strict).await,
            Some(RuntimeCmd::Guide) => crate::runtime::guide(),
            Some(RuntimeCmd::Install {
                runtime,
                engine,
                apply,
                version,
                runtime_class,
                sha256,
            }) => {
                let opts = crate::runtime::install::resolve_opts(
                    &runtime,
                    &engine,
                    apply,
                    &version,
                    &runtime_class,
                    &sha256,
                )?;
                crate::runtime::install::run(&opts).await
            }
        },
        Command::Serve(args) => crate::serve::serve(&args, cfg).await,
        Command::Up { image, crds_only } => crate::kube::up(&image, crds_only).await,
        Command::Validate { charters, strict } => crate::inspect::validate(&charters, strict, cfg),
        Command::Version => {
            crate::version::print();
            Ok(())
        }
        Command::Webhook {
            port,
            service,
            cert_secret,
        } => crate::kube::webhook(port, &service, &cert_secret).await,
    }
}

fn replay(path: &str, honor_timing: bool) -> Result<()> {
    let f = std::fs::File::open(path)
        .map_err(|e| anyhow!("open cast file: {}", go_io_error("open", path, &e)))?;
    let stdout = std::io::stdout().lock();
    runeward_termrec::replay(std::io::BufReader::new(f), stdout, honor_timing)?;
    Ok(())
}

/// The bearer token: the flag, else `$RUNEWARD_API_TOKEN`, else the
/// stored `runeward auth login` credential.
fn resolve_token(flag: &str) -> String {
    if flag.is_empty() {
        std::env::var("RUNEWARD_API_TOKEN")
            .ok()
            .filter(|t| !t.trim().is_empty())
            .unwrap_or_else(runeward_credentials::load_token)
    } else {
        flag.to_owned()
    }
}

fn client(base: &str, token_flag: &str) -> FleetClient {
    FleetClient::new(base, &resolve_token(token_flag))
}

async fn citadel(args: CitadelArgs) -> Result<()> {
    let c = client(&args.remote.base, &args.remote.token);
    let mut stdout = std::io::stdout();
    let mut out = Out {
        w: &mut stdout,
        json: args.remote.json,
    };
    use crate::remote as r;
    match args.command {
        CitadelCmd::Fork {
            id,
            charter,
            agent,
            model,
        } => r::citadel_fork(&c, &mut out, &id, &charter, &agent, &model).await,
        CitadelCmd::Sleep { id } => r::citadel_sleep(&c, &mut out, &id).await,
        CitadelCmd::Wake { id } => r::citadel_wake(&c, &mut out, &id).await,
        CitadelCmd::Status { id } => r::citadel_status(&c, &mut out, &id).await,
        CitadelCmd::Perimeter { id } => r::citadel_perimeter(&c, &mut out, &id).await,
    }
}

async fn session(args: SessionArgs) -> Result<()> {
    let c = client(&args.remote.base, &args.remote.token);
    let mut stdout = std::io::stdout();
    let mut out = Out {
        w: &mut stdout,
        json: args.remote.json,
    };
    use crate::remote as r;
    match args.command {
        SessionCmd::Turn {
            session,
            prompt,
            agent,
            model,
        } => r::session_turn(&c, &mut out, &session, &prompt, &agent, &model).await,
        SessionCmd::Attach { session, after } => {
            r::session_attach(&c, &mut out, &session, after).await
        }
        SessionCmd::Cancel { session } => r::session_cancel(&c, &mut out, &session).await,
    }
}

async fn schedule(args: ScheduleArgs) -> Result<()> {
    let c = client(&args.remote.base, &args.remote.token);
    let mut stdout = std::io::stdout();
    let mut out = Out {
        w: &mut stdout,
        json: args.remote.json,
    };
    use crate::remote as r;
    match args.command {
        ScheduleCmd::Create {
            citadel,
            cohort,
            cron,
            every,
            prompt,
            agent,
            model,
            precheck,
            command,
        } => {
            let spec = r::ScheduleSpec {
                citadel,
                cohort,
                cron,
                every,
                prompt,
                agent,
                model,
                precheck,
                command,
            };
            r::schedule_create(&c, &mut out, &spec).await
        }
        ScheduleCmd::List { citadel, cohort } => {
            r::schedule_list(&c, &mut out, &citadel, &cohort).await
        }
        ScheduleCmd::Get { id } => r::schedule_get(&c, &mut out, &id).await,
        ScheduleCmd::Delete { id } => r::schedule_delete(&c, &mut out, &id).await,
        ScheduleCmd::Run { id } => r::schedule_run(&c, &mut out, &id).await,
    }
}

async fn cohort(args: CohortArgs) -> Result<()> {
    let opts = CohortOptions {
        base: args.base,
        agent: args.agent,
        model: args.model,
        cohort: args.cohort,
        token: resolve_token(&args.token),
    };
    use crate::cohort as c;
    match args.command {
        CohortCmd::Up { charter } => c::up(&opts, charter.as_deref()).await,
        CohortCmd::Add { prompt } => c::add(&opts, &prompt).await,
        CohortCmd::Run => c::run(&opts).await,
        CohortCmd::Build { prompt } => c::build(&opts, &prompt).await,
        CohortCmd::Exec { prompt, citadel } => c::exec(&opts, &citadel, &prompt).await,
        CohortCmd::Status => c::status(&opts).await,
        CohortCmd::Export { dir } => c::export(&opts, dir.as_deref()).await,
        CohortCmd::Down => c::down(&opts).await,
        other => cohort_context(&opts, args.json, other).await,
    }
}

/// The Cohort memory and task-context subcommands.
async fn cohort_context(opts: &CohortOptions, json: bool, cmd: CohortCmd) -> Result<()> {
    let id = crate::cohort::resolve_fleet_id(&opts.cohort)?;
    let cl = FleetClient::new(&opts.base, &opts.token);
    let mut stdout = std::io::stdout();
    let mut out = Out {
        w: &mut stdout,
        json,
    };
    let out = &mut out;
    use crate::remote as r;
    match cmd {
        CohortCmd::Memory(m) => match m {
            MemoryCmd::Put {
                key,
                text,
                tags,
                expected_version,
            } => r::memory_put(&cl, out, &id, &key, &text, &tags, expected_version).await,
            MemoryCmd::Get { key } => r::memory_get(&cl, out, &id, &key).await,
            MemoryCmd::Search {
                query,
                tags,
                limit,
                max_bytes,
            } => {
                let q = query.unwrap_or_default();
                r::memory_search(&cl, out, &id, &q, &tags, limit, max_bytes).await
            }
            MemoryCmd::List => r::memory_list(&cl, out, &id).await,
            MemoryCmd::Delete { key, version } => {
                r::memory_delete(&cl, out, &id, &key, version).await
            }
        },
        CohortCmd::Note { task, text } => r::task_note(&cl, out, &id, &task, &text).await,
        CohortCmd::Brief {
            task,
            brief,
            target,
        } => r::task_brief(&cl, out, &id, &task, &target, &brief).await,
        CohortCmd::Handoff {
            task,
            lease_token,
            note,
            result,
            requeue,
            owner,
        } => {
            let h = r::Handoff {
                owner: &owner,
                lease_token: &lease_token,
                note: &note,
                result: &result,
                requeue,
            };
            r::task_handoff(&cl, out, &id, &task, &h).await
        }
        CohortCmd::Task(TaskCmd::Context {
            task,
            target,
            memory_bytes,
        }) => r::task_context(&cl, out, &id, &task, &target, memory_bytes).await,
        CohortCmd::Task(TaskCmd::Child { task, payload }) => {
            r::task_child(&cl, out, &id, &task, &payload).await
        }
        CohortCmd::Up { .. }
        | CohortCmd::Add { .. }
        | CohortCmd::Run
        | CohortCmd::Build { .. }
        | CohortCmd::Exec { .. }
        | CohortCmd::Status
        | CohortCmd::Export { .. }
        | CohortCmd::Down => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rw(args: &[&str]) -> Vec<String> {
        rewrite_for_enter(args.iter().map(OsString::from).collect())
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn auth_is_reserved_command() {
        assert_eq!(rw(&["auth", "status"]), ["auth", "status"]);
    }

    #[test]
    fn bare_charter_means_enter() {
        assert_eq!(rw(&["dev"]), ["enter", "dev"]);
        assert_eq!(
            rw(&["-c", "dir", "dev", "--", "ls"]),
            ["-c", "dir", "enter", "dev", "--", "ls"]
        );
        assert_eq!(rw(&["--config-dir", "list"]), ["--config-dir", "list"]);
        assert_eq!(rw(&["--help"]), ["--help"]);
        assert_eq!(rw(&["validate", "dev"]), ["validate", "dev"]);
        assert!(rw(&[]).is_empty());
    }

    #[test]
    fn command_tree_is_consistent() {
        Cli::command().debug_assert();
        for name in RESERVED.iter().filter(|n| !n.starts_with('-')) {
            assert!(
                Cli::command().find_subcommand(name).is_some() || *name == "help",
                "reserved {name} is not a subcommand"
            );
        }
    }

    #[test]
    fn enter_takes_a_trailing_command() {
        let cli = Cli::try_parse_from(["runeward", "enter", "dev", "--keep", "--", "ls", "-la"])
            .unwrap_or_else(|e| panic!("{e}"));
        match cli.command {
            Some(Command::Enter {
                charter,
                command,
                keep,
            }) => {
                assert_eq!(charter, "dev");
                assert_eq!(command, ["ls", "-la"]);
                assert!(keep);
            }
            other => panic!("{other:?}"),
        }
    }
}
