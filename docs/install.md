# Install

## Choose an installation

| Install with | What it installs | Command |
| --- | --- | --- |
| [Homebrew](https://github.com/Runeeward/homebrew-tap) | Rune Box CLI for macOS or Linux | `brew install Runeeward/tap/runeward` |
| [PyPI](https://pypi.org/project/runeward/) | Python client and agent-framework adapters | `python -m pip install runeward` |
| [npm](https://www.npmjs.com/package/@runeward/sdk) | TypeScript client and agent-framework tools | `npm install @runeward/sdk` |

For normal local use, install the CLI with Homebrew. For an agent integration, install the SDK for
its language as well. The pip and npm packages connect to a running Rune Box API; they do not
replace the CLI/runtime.

## Homebrew — CLI

Homebrew installs the current signed CLI release on macOS or Linux:

```bash
brew install Runeeward/tap/runeward
runeward version
runeward quickstart
```

Local sandboxes also require a running Docker, OrbStack, or Podman engine.

## pip — Python SDK

Requires Python 3.9 or newer. The base client has no third-party runtime dependencies.

```bash
python -m pip install runeward
python -c "import runeward; print(runeward.__version__)"
```

## npm — TypeScript SDK

Requires Node.js 18 or newer.

```bash
npm install @runeward/sdk
npm ls @runeward/sdk
```

See [Adapters](adapters.md) for optional framework dependencies.

## Signed release installer (macOS/Linux alternative)

The installer requires `curl` or `wget`, `tar`, a SHA-256 utility, and
[`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/). It fails closed: the
signed checksum manifest is verified before the archive checksum and install.

```bash
curl -fsSL https://raw.githubusercontent.com/Runeeward/runeward/main/install.sh | sh
```

Pin a release or location:

```bash
RUNEWARD_VERSION=v0.4.0 RUNEWARD_BIN_DIR="$HOME/.local/bin" \
  sh -c "$(curl -fsSL https://raw.githubusercontent.com/Runeeward/runeward/main/install.sh)"
```

The shell installer supports macOS and Linux. Windows CLI archives are available from
[GitHub Releases](https://github.com/Runeeward/runeward/releases); the in-sandbox helpers are Linux
binaries because they run inside Docker or Kubernetes.

## From source

The documentation follows `main`. Build from source with **Rust 1.95** or newer to use unreleased
changes:

```bash
git clone https://github.com/Runeeward/runeward
cd runeward
cargo build --release --locked -p runeward-cli --bin runeward
./target/release/runeward version
```

The Linux-only helpers build the same way: `-p runeward-egress`, `-p runeward-supervisor` and
`-p runeward-browser`.

## Container images

Published multi-architecture images:

```bash
docker pull ghcr.io/runeeward/runeward:latest
docker pull ghcr.io/runeeward/runeward-egress:latest
docker pull ghcr.io/runeeward/runeward-agent:latest
docker pull ghcr.io/runeeward/runeward-sandbox:latest
docker pull ghcr.io/runeeward/runeward-ide:latest
docker pull ghcr.io/runeeward/runeward-ide-agents:latest
```

Images and release checksums are signed by the release workflow. Verification examples are in
[SECURITY.md](https://github.com/Runeeward/runeward/blob/main/SECURITY.md).

## Runtime prerequisites

- Docker, OrbStack, or Podman for local sandboxes.
- Optionally Kubernetes and Helm for cluster deployments.
- Run `runeward doctor <policy>` before launch to check the selected runtime and image.

Next: [Quickstart](quickstart.md).
