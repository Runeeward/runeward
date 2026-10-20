# Security Policy

Rune Box is designed to reduce the blast radius of untrusted AI-agent activity,
so vulnerabilities in Rune Box itself are treated as high priority. We welcome
careful security research and coordinated disclosure.

## Project status

Rune Box is **pre-1.0** and under active development. Interfaces may change and
security guarantees are not yet stable. The `v0.3.x` line is suitable for
evaluation and carefully controlled deployments, but it has not completed an
independent third-party security audit.

Rune Box is defense in depth, not an absolute containment guarantee. Do not use
infrastructure you cannot afford to lose when evaluating genuinely hostile code.

## Report vulnerabilities privately

**Do not open a public issue, discussion, or pull request for a suspected
vulnerability.** Use one of these private channels instead:

- GitHub's [private vulnerability reporting](https://github.com/Runeeward/runeward/security/advisories/new)
  is preferred.
- Email **adefemi171@gmail.com** with the subject `Rune Box security`.

Include, when possible:

- the affected version or commit and execution backend;
- a clear impact statement and the boundary that can be crossed;
- minimal, reproducible steps or a proof of concept;
- relevant configuration with credentials and personal data removed;
- any mitigation or remediation you have tested.

Please allow a reasonable remediation window before public disclosure.

## AI-assisted and scanner-generated reports

Reports discovered with an LLM, scanner, or automated agent are welcome, but
they must be validated by the reporter. Before submitting, confirm that you can:

- reproduce the behavior against a supported revision;
- explain the trust boundary and realistic impact;
- distinguish reachable product code from an unused or development dependency;
- remove speculative claims and duplicate scanner output.

Unverified alert dumps slow response to actionable findings. A concise report
with a working reproduction is much more useful than a long generated analysis.

## Response expectations

We aim to:

- acknowledge a report within three business days;
- provide an initial assessment within seven business days;
- keep the reporter informed during remediation;
- ship confirmed high or critical fixes as quickly as practical, targeting 30
  days when a safe fix is available;
- coordinate publication and credit with the reporter.

Timelines are goals rather than guarantees, especially when remediation depends
on an upstream runtime, kernel, or dependency.

## Supported versions

Until 1.0, security fixes are applied to the latest tagged release and `main`.
Older pre-1.0 releases may not receive backports. GitHub Security Advisories and
release notes will identify the first fixed version.

## Scope and threat model

Examples of issues that are in scope:

- escape from a Citadel to the host or another tenant's Citadel;
- bypass of Charter policy, Conclave approval, Perimeter egress, Rationing, or
  tenant authorization;
- forged or silently modified Chronicle records that still verify;
- traversal or archive extraction outside the intended workspace;
- unauthorized REST, MCP, browser IDE, terminal, webhook, or Kubernetes access;
- secret exposure through logs, APIs, the dashboard, evidence, or state files;
- task-lease replay, cross-actor completion, or run-lineage attribution bypass.

Operator-controlled or normally out-of-scope areas include:

- vulnerabilities in the host kernel, container runtime, Kubernetes cluster,
  or third-party agent that do not rely on a Rune Box defect;
- deliberately weakened Charters, oversized resource grants, disabled signing,
  or `--allow-insecure-http` deployments;
- untrusted images or secrets supplied directly by an operator;
- denial of service that remains within limits the operator intentionally gave
  the workload.

We may still help route an upstream issue or improve hardening even when the
root cause is outside Rune Box.

## Verifying releases

Release archives are listed in `checksums.txt`, which the release workflow signs keylessly with
cosign (GitHub OIDC). `install.sh` performs these checks automatically and fails closed.

```bash
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Runeeward/runeward/\.github/workflows/release\.yml@refs/tags/.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --ignore-missing -c checksums.txt
```

Container images are signed by digest:

```bash
cosign verify ghcr.io/runeeward/runeward:<tag> \
  --certificate-identity-regexp 'https://github.com/Runeeward/runeward' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Each release also ships an SPDX SBOM of the Rust dependency graph
(`runeward_<version>.sbom.spdx.json`), covered by the same signature.

## Safe harbor

We consider good-faith research authorized when it follows this policy, avoids
privacy violations and unnecessary disruption, uses only the access required to
demonstrate the issue, and gives us time to remediate. We will not initiate legal
action for research conducted under those conditions. If you are unsure whether
a test is safe, contact us privately before proceeding.

## Security work before 1.0

Before claiming stable 1.0 security guarantees, the project intends to complete
independent review of its threat model and enforcement boundaries, harden native
and remote execution paths, and publish the resulting guarantees and residual
risks. Current release gates are enforced by the CI, security, and release
workflows.
