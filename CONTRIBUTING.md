# Contributing to Rune Box

Rune Box is a governance and isolation boundary for AI agents. Contributions
are welcome from people who understand and can explain the code they submit.
By participating, you agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Before writing code

For anything beyond a typo or narrowly scoped documentation fix, open or find
an issue first. A short design discussion is especially important for changes
to authentication, tenant isolation, policy evaluation, approvals, egress,
secrets, archive extraction, task leases, audit signing, or runtime backends.
Those paths contain security constraints that are easy to miss in a local edit.

Security vulnerabilities must not be discussed in public issues or pull
requests. Follow [SECURITY.md](SECURITY.md) instead.

## Engineering invariants

Every contribution must preserve these rules:

- Fail closed. An error must never silently broaden a Charter, skip an approval,
  disable isolation, or downgrade authentication or TLS.
- Treat paths structurally. Clean, validate, and constrain filesystem paths;
  never use naive string-prefix checks as a containment boundary.
- Keep all agent actions that require per-action policy on the governed REST,
  MCP, dashboard, or SDK path.
- Keep tenant ownership separate from actor attribution. Shared tenant access
  must not erase which human or agent performed an action.
- Never place raw secrets, bearer tokens, signing keys, Chronicles, state files,
  or generated credentials in commits, logs, fixtures, or screenshots.
- Check every returned error in security-sensitive code. Document any
  best-effort cleanup that cannot safely be retried.
- Add tests for behavior changes. Authorization, policy, archive, network,
  credential, persistence, and cryptographic changes need negative tests.

## Development setup

Requirements:

- Rust 1.95 or newer (the workspace MSRV in `Cargo.toml`), with `rustfmt` and `clippy`;
- Python 3.9 or newer for the Python adapter tests;
- Node.js 18 or newer for the TypeScript adapter;
- Docker, Podman, or OrbStack for local Citadels;
- Helm and, for Kubernetes work, a disposable kind/k3d/OrbStack cluster.

Build and inspect the project:

```bash
cargo build --locked -p runeward-cli --bin runeward
./target/debug/runeward --config-dir examples list
./target/debug/runeward --config-dir examples/safe validate --strict

RUNEWARD_STATE_DIR=/tmp/runeward-dev \
  ./target/debug/runeward --config-dir examples serve
```

Always give a development server its own `RUNEWARD_STATE_DIR`. Concurrent
writers sharing state can invalidate assumptions around persistence and the
tamper-evident Chronicle.

## Run checks locally

The shortest path is:

```bash
make ci
```

That runs `cargo fmt --check`, `cargo clippy -D warnings`, the workspace tests,
builds, strict Charter validation, both SDK suites, Helm rendering, and the
dependency checks (`cargo deny` and `cargo audit`, installed with
`cargo install --locked cargo-deny cargo-audit`). Individual targets such as
`make test`, `make lint`, `make sdk-test`, `make helm`, and `make security` are
available while iterating. `make docker-test` runs the opt-in tests against a
real Docker engine (`RUNEWARD_TEST_DOCKER=1`).

Before a release, also run the Docker and Kubernetes end-to-end procedures in
[docs/E2E-TESTING.md](docs/E2E-TESTING.md), build and scan every release image,
and require every hosted release workflow to pass.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/) so release notes
can distinguish features, fixes, security work, documentation, and maintenance:

```text
<type>(<optional scope>): <short description>
```

Accepted types are `feat`, `fix`, `security`, `docs`, `perf`, `refactor`, `test`,
`ci`, `build`, and `chore`.

Examples:

```text
feat(cohort): rotate task leases on heartbeat
fix(authz): preserve actor attribution inside a shared tenant
security(oidc): rate-limit unknown-key refreshes
```

Use focused commits and explain the reason for non-obvious changes in the body.
DCO sign-off with `git commit -s` is encouraged and may become mandatory once
automated enforcement is enabled.

## Pull-request process

1. Link the issue or explain why a prior issue is unnecessary.
2. Create a focused branch and keep unrelated changes out of the PR.
3. Add tests and documentation with the implementation.
4. Run `make ci` and any relevant Docker/Kubernetes/browser suites.
5. Open the PR against `main` and complete the template honestly.

The test plan should distinguish what passed, what was not run, and why. A clear
statement that an environment-dependent suite remains outstanding is more useful
than implying complete coverage.

Reviewers may request smaller changes, stronger negative tests, a threat-model
update, or a release note before merging security-boundary work.

## AI-assisted contributions

AI assistance is allowed, but responsibility stays with the contributor. In the
PR template, disclose the tools used and confirm that you:

- reviewed and understand every submitted change;
- verified generated claims against code or primary documentation;
- did not provide secrets or private user data to an external model;
- ran the reported tests yourself;
- can maintain and explain the resulting behavior.

Do not submit speculative vulnerability reports or large generated changes that
you cannot reproduce, review, and support.

## Scope and security claims

Rune Box governs agent actions routed through its control plane and isolates
Citadels using the configured backend. It does not transparently intercept each
keystroke in an interactive terminal or IDE, and pre-1.0 guarantees may change.
Documentation and PR descriptions must not claim protections the implementation
does not enforce.

## License

By contributing, you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).
