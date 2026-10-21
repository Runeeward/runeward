# Quickstart

This proves Rune Box's core loop—allow, deny before execution, and signed audit—in about a minute.
It assumes the current `main` build and a running Docker, OrbStack, or Podman engine.

## 1. Create and run the proof

From the project you want to govern:

```bash
runeward quickstart
```

Rune Box creates `.runeward/quickstart.toml` without overwriting an existing policy, checks the
runtime and state directory, starts an isolated sandbox, runs an allowed command, blocks a recursive
delete, and verifies its signed audit trail.

To create the starter policy without launching anything:

```bash
runeward quickstart --no-run
```

## 2. Diagnose setup

```bash
runeward doctor quickstart
runeward doctor quickstart --json
```

`doctor` checks policy validity, runtime reachability, the image reference, and writable state. Its
errors give recovery instructions without exposing local engine socket paths in the dashboard.

## 3. Run your own command

```bash
runeward --config-dir .runeward print quickstart
runeward --config-dir .runeward enter quickstart -- uname -a
```

The `quickstart` after `enter` is the policy name. A policy file is also called a **Charter** in
existing Rune Box APIs.

## 4. Open the control plane

Give each running instance its own state directory because the signed audit ledger is single-writer:

```bash
RUNEWARD_STATE_DIR=/tmp/runeward-quickstart \
  runeward --config-dir .runeward serve
```

Open [http://localhost:8080](http://localhost:8080). The dashboard distinguishes server liveness
from launch readiness, shows setup guidance, and lets you:

- create and drive a sandbox;
- resolve approval requests;
- inspect policy, network, budget, and signed audit events;
- download the workspace or portable signed evidence;
- create and restore recovery snapshots.

## 5. Export portable evidence

Stop the server before opening the same local ledger from the CLI, then run:

```bash
runeward --config-dir .runeward evidence export quickstart -o runeward-evidence.json
runeward evidence verify runeward-evidence.json
runeward policy learn runeward-evidence.json > proposed-policy.toml
```

The evidence package includes a digest of the resolved, secret-redacted policy and the Chronicle's
signed event bundle. `evidence verify` checks that digest as well as the bundle's hash chain and
signatures. A bare Chronicle bundle (for example from `GET /v1/chronicle/export`) has no policy in it;
verify that with `runeward chronicle verify`, which checks only the chain and signatures (see
[Compliance & evidence](why-governance.md#compliance-evidence)). `policy learn` verifies the package and
prints exact proposals for human review; it does not modify the policy.

## 6. Work on your own code

Rune Box takes a one-time copy rather than mounting the host folder, so the agent edits an isolated
`/workspace`.

```bash
# Add this to .runeward/quickstart.toml before launching:
# [host]
# copy_from = "/absolute/path/to/your-project"

runeward --config-dir .runeward enter quickstart --keep
runeward export <sandbox-id> ./agent-output
```

You can also set `host.copy_from` in the policy or use the dashboard's create dialog.

## Next

- [Naming](naming.md) — plain terms and compatibility names.
- [Policies](profiles.md) — network, approval, audit, and budget controls.
- [Security model](security-model.md) — deployment boundaries and experimental features.
