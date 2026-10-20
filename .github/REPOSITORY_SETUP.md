# Repository discovery and release setup

These settings live in GitHub rather than the repository, so a maintainer must apply them manually.

## About panel

- Description: `Rune Box: an environment where your AI agent can roam freely but securely. Open-source governance harness for AI agents.`
- Website: `https://runeeward.github.io/runeward/`
- Topics: `ai-agents`, `agent-security`, `sandbox`, `policy-engine`, `human-in-the-loop`,
  `agent-harness`, `multi-agent`, `audit-log`, `mcp`, `docker`, `kubernetes`, `rego`, `cel`, `rust`
- Social preview: upload `docs/assets/runeward-banner-v2.png`. Check the crop in GitHub's preview
  editor so the subtitle remains visible.

## Before the next release

- Run `make ci` (or `cargo test --workspace --locked`), the security workflow, and the documented
  quickstart from a clean machine.
- Confirm the release builds with Rust 1.95 (the workspace MSRV), uploads the Linux, macOS and
  Windows archives, `checksums.txt` with its cosign signatures and the SBOM, and publishes all six
  container images (control plane, egress, agent, sandbox, ide, ide-agents) for amd64 and arm64.
- Optional: set the `HOMEBREW_TAP_TOKEN` secret (write access to `Runeeward/homebrew-tap`) so the
  release workflow pushes the Homebrew formula; without it the formula is rendered but not pushed.
- Confirm the tagged CLI contains `quickstart`, `doctor`, `evidence`, and `policy learn` before
  removing the `main`/release distinction from the README.
- Confirm the Homebrew tap contains the current formula and `brew install Runeeward/tap/runeward`
  still succeeds before updating public install docs.
- Publish and verify the current Python/npm versions before updating registry install docs.
- Run `scripts/set-release-version.py <version>` to update the SDKs, `dist/mcp/server.json`, the
  MCP crate version, the Codex plugin and the Helm chart together.
- Generate a short terminal recording of `runeward quickstart` for the release notes and docs.

## SDK registry publishing

The `publish SDKs` workflow publishes `runeward` to PyPI and `@runeward/sdk` to npm from a `v*`
tag. Both packages use the same version as the release tag.

1. Create protected GitHub environments named `pypi` and `npm`. Require a maintainer approval and
   restrict deployment to protected release tags.
2. In PyPI, create a pending trusted publisher for project `runeward` with owner `Runeeward`,
   repository `runeward`, workflow `publish-sdks.yml`, and environment `pypi`.
3. Create or confirm the `runeward` npm organization. The first `@runeward/sdk` version must be
   bootstrapped by an authenticated npm owner because npm trusted publishing is configured from an
   existing package's settings.
4. After that bootstrap, configure the npm trusted publisher with owner `Runeeward`, repository
   `runeward`, workflow `publish-sdks.yml`, environment `npm`, and permission to `npm publish`.
5. Revoke any bootstrap npm token. Future publications use short-lived GitHub OIDC credentials and
   npm provenance rather than a repository secret.

If the GitHub organization is ever renamed, update both trusted publishers and all package
repository metadata before publishing another version.
