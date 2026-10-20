# Security and dashboard review

This page records the security and dashboard review performed on 10 September
2026. It covers the `Runewardd/runeward` application and the
`Runewardd/homebrew-tap` distribution repository.

> Rune Box has since moved from Go to Rust. The Go dependency findings below describe the earlier
> implementation; the Rust workspace's dependencies are checked by `cargo deny` and `cargo audit`
> (see `deny.toml`).

## Findings and remediation

| Severity | Finding | Exposure | Remediation |
| --- | --- | --- | --- |
| Critical | CVE-2026-56854 in `golang.org/x/crypto` 0.54.0 | Authentication callbacks using SSH source-address restrictions could fail to enforce those restrictions. GitHub reported this in filesystem and application-image scans (alerts 2971 and 2973). | Upgrade to 0.55.0 through the Go dependency update. |
| High | CVE-2026-84445 in `google.golang.org/grpc` 1.83.0 | A malformed xDS request without authority headers could crash an xDS server (Dependabot alert 3). | Upgrade to 1.83.2 through the Go dependency update. |
| High | CVE-2026-84304 in `google.golang.org/grpc` 1.83.0 | Fragmented HTTP/2 DATA frames could cause disproportionate memory consumption and denial of service. GitHub reported this in filesystem and application-image scans (alerts 2972 and 2974; Dependabot alert 1). | Upgrade to 1.83.2 through the Go dependency update. |
| Medium | CVE-2026-84303 in `google.golang.org/grpc` 1.83.0 | Mixed-case headers could bypass the xDS RBAC HTTP filter's matching rules (Dependabot alert 2). | Upgrade to 1.83.2 through the Go dependency update. |
| High | CVE-2026-14456 in Alpine OpenSSL 3.5.7 | The agent, egress, and browser-sandbox images inherited vulnerable `libcrypto3` and `libssl3` packages (alerts 2965–2970). | Upgrade Alpine packages before installing each runtime image's packages. The resulting images contain OpenSSL 3.5.8 or later. |
| High | CVE-2026-84375 in `js-yaml` 4.3.1 | The bundled code-server dependency could consume excessive CPU while parsing crafted YAML. | Replace the bundled package with `js-yaml` 4.3.2 in both IDE image targets. |
| Medium | Several internal HTTP servers accepted request headers without a deadline. | A slow client with network access to an agent, webhook, or proxy listener could retain connections and consume resources. | Apply a 10-second `ReadHeaderTimeout` to every Go HTTP server. |
| Medium, defense in depth | Dashboard authentication treated every non-API GET path as a public static asset. | A future sensitive GET route outside the known API prefixes could have become public accidentally. | Replace the denylist with an exact allowlist of the five embedded dashboard assets. |
| Low, defense in depth | The dashboard DOM helper exposed a generic `innerHTML` option even though no caller used it. | There was no confirmed injection path, but a future caller could have turned untrusted API data into markup. | Remove the option. Dynamic content continues to use `textContent` or DOM nodes. |

The dependency work also incorporates the open Dependabot updates for the Go
module graph, Docker build images, and GitHub CodeQL actions. A clean security
pipeline on the pull request is required before merge. GitHub closes the listed
code-scanning alerts after the fixed `main` branch publishes fresh SARIF.

## Follow-up review: 19 September 2026

A follow-up covered every repository visible in the `Runewardd` organization:
`runeward` and `homebrew-tap`. GitHub reported no open Dependabot or code
scanning alerts in `runeward`, no Dependabot alerts in `homebrew-tap`, and no
open pull requests in the tap.

The review found and addressed two additional issues:

- `golang.org/x/crypto` 0.55.0 was present through OPA's JWE/PBKDF2 dependency
  chain. Although Rune Box did not call the affected SSH code, the module was
  subject to GO-2026-6354 and GO-2026-6355, two denial-of-service advisories.
  The module is upgraded to 0.56.0.
- GitHub Actions in CI, security scanning, documentation, SDK publishing, and
  release workflows used mutable version tags. Every external action is now
  pinned to the verified commit behind its documented version, preventing a
  moved or compromised tag from silently changing privileged workflow code.
  A workflow-dispatch value is also passed through an environment variable
  instead of being interpolated directly into a shell command.

`govulncheck` continues to mention GO-2026-5932 because the `x/crypto` module
contains the deprecated `openpgp` package. Rune Box does not import that package,
and the advisory has no fixed module version. The scanner reports zero
vulnerabilities in symbols or packages used by Rune Box.

The malware-oriented review found no unexpected executables, encoded payloads,
download-and-execute paths, or suspicious workflow steps. The Homebrew formula
contains only versioned HTTPS release URLs and SHA-256 checksums; fresh downloads
of all four formula archives matched the release checksum manifest and the
formula.

## Dashboard UX and accessibility

The desktop information hierarchy is clear: environment health and audit
integrity remain visible, sandbox creation communicates readiness, and direct
PTY access is visually separated from governed shell execution. The review
also confirmed that PTY Terminal and Live chat are separate tabs.

Two usability problems were corrected:

- An empty Live chat connection now says that it is connected and waiting for
  an agent, instead of presenting a blank terminal under a "following live"
  badge.
- Sandbox tool tabs now expose tab and tabpanel relationships, keep
  `aria-selected` synchronized, support arrow/Home/End navigation, and show a
  visible keyboard-focus ring.

The dashboard remains desktop-first. On narrow screens the large number of
sandbox tool tabs requires horizontal space, so mobile operation should be
treated as a secondary inspection surface rather than the primary terminal.

## Controls verified

- The server refuses unauthenticated non-loopback binds.
- Non-loopback HTTP requires TLS unless the operator explicitly acknowledges a
  trusted TLS proxy configuration.
- API responses use a deny-by-default content security policy and are marked
  `no-store`.
- The dashboard uses framing, content-type, referrer, permissions, and content
  security headers. CDN scripts and styles are version-pinned and protected by
  Subresource Integrity.
- Terminal and conversation WebSockets use short-lived tickets; the terminal
  also enforces same-origin checks.
- The Homebrew formula downloads versioned release archives over HTTPS,
  verifies a SHA-256 digest for every supported platform, and invokes the
  installed binary without a shell command string.

## Repository security settings

GitHub's Dependabot alert API reported that vulnerability alerts were disabled
for both reviewed repositories at the start of the review. Vulnerability alerts
and automated security updates were enabled for both repositories during
remediation, so newly published advisories are no longer limited to scheduled
Trivy runs or version-update pull requests.

## Static-analysis disposition

The repository's configured high-severity `gosec` gate reports zero findings.
The broader scan still reports medium and low findings, chiefly where the
sandbox orchestrator intentionally launches operator-selected commands or
opens operator-selected paths. Those call sites remain protected by the
existing policy, ownership, workspace-confinement, and audit controls. The
actionable HTTP slow-client findings discovered by the broader scan were fixed
with request-header deadlines as described above.

## Validation

The remediated tree passed the complete Go test suite, `go vet`, the TypeScript
and Python SDK tests, `govulncheck`, and npm's advisory audit. Trivy's current
database reported zero high or critical findings in the repository filesystem
and in all six shipped image targets: control plane, egress, agent, browser
sandbox, IDE, and agent-enabled IDE.
