#!/bin/sh
# Rune Box installer: installs the `runeward` CLI.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Runewardd/runeward/main/install.sh | sh
#
# Environment overrides:
#   RUNEWARD_VERSION   release tag to install (default: latest)
#   RUNEWARD_BIN_DIR   install directory (default: /usr/local/bin, falls back to ~/.local/bin)
#   RUNEWARD_INSECURE_SKIP_CHECKSUM=1   skip checksums.txt verification
#   RUNEWARD_INSECURE_SKIP_SIGNATURE=1  skip cosign verification of checksums.txt
#
set -eu

REPO="Runewardd/runeward"
BIN_NAME="runeward"

info()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
err()   { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"; }

# --- pick a downloader ---------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
  DL="curl -fsSL"
  DLO="curl -fsSL -o"
elif command -v wget >/dev/null 2>&1; then
  DL="wget -qO-"
  DLO="wget -qO"
else
  err "need curl or wget to download Rune Box"
fi
need tar
need uname

# --- detect os/arch ------------------------------------------------------------
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux)  os=linux ;;
  darwin) os=darwin ;;
  *) err "unsupported OS: $os (linux and darwin are supported; on Windows download runeward_windows_amd64.zip from the release page)" ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) err "unsupported architecture: $arch (amd64 and arm64 are supported)" ;;
esac

# --- resolve version -----------------------------------------------------------
version="${RUNEWARD_VERSION:-latest}"
if [ "$version" = "latest" ]; then
  info "Resolving latest release..."
  version=$($DL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -n1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
  [ -n "$version" ] || err "could not resolve the latest release tag (set RUNEWARD_VERSION)"
fi
info "Installing Rune Box (runeward) ${version} (${os}/${arch})"

asset="${BIN_NAME}_${os}_${arch}.tar.gz"
base="https://github.com/${REPO}/releases/download/${version}"

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t runeward)
trap 'rm -rf "$tmp"' EXIT

# --- download ------------------------------------------------------------------
info "Downloading ${asset}"
$DLO "$tmp/$asset" "$base/$asset" || err "download failed: $base/$asset"

# --- verify release signatures + checksum (fail closed) -----------------------
# By default we verify checksums.txt with cosign first, then verify the artifact
# digest against checksums.txt. Missing files/tools or any mismatch is fatal.
# The signature is a Sigstore bundle (checksums.txt.sigstore.json); releases
# without one are verified from the detached checksums.txt.sig/.pem pair.
# Escape hatches (NOT recommended):
#   - RUNEWARD_INSECURE_SKIP_SIGNATURE=1 bypasses cosign verification only.
#   - RUNEWARD_INSECURE_SKIP_CHECKSUM=1 bypasses both signature + checksum checks.
identity='^https://github.com/Runewardd/runeward/\.github/workflows/release\.yml@refs/tags/.*$'
issuer="https://token.actions.githubusercontent.com"
skip_checksum="${RUNEWARD_INSECURE_SKIP_CHECKSUM:-0}"
if [ "$skip_checksum" = "1" ]; then
  warn "RUNEWARD_INSECURE_SKIP_CHECKSUM=1 set; skipping checksum verification"
elif $DLO "$tmp/checksums.txt" "$base/checksums.txt" 2>/dev/null; then
  skip_signature="${RUNEWARD_INSECURE_SKIP_SIGNATURE:-0}"
  if [ "$skip_signature" = "1" ]; then
    warn "RUNEWARD_INSECURE_SKIP_SIGNATURE=1 set; skipping checksums.txt signature verification"
  else
    command -v cosign >/dev/null 2>&1 \
      || err "cosign is required to verify the signed release manifest; install it from https://docs.sigstore.dev/cosign/system_config/installation/ (or explicitly set RUNEWARD_INSECURE_SKIP_SIGNATURE=1 to accept checksum-only verification)"
    info "Verifying checksums signature"
    if $DLO "$tmp/checksums.txt.sigstore.json" "$base/checksums.txt.sigstore.json" 2>/dev/null; then
      cosign verify-blob \
        --bundle "$tmp/checksums.txt.sigstore.json" \
        --certificate-identity-regexp "$identity" \
        --certificate-oidc-issuer "$issuer" \
        "$tmp/checksums.txt" >/dev/null \
        || err "cosign verification failed for checksums.txt (set RUNEWARD_INSECURE_SKIP_SIGNATURE=1 to override)"
    else
      $DLO "$tmp/checksums.txt.sig" "$base/checksums.txt.sig" 2>/dev/null \
        || err "no checksums.txt signature published for $version; refusing unsigned checksums (set RUNEWARD_INSECURE_SKIP_SIGNATURE=1 to override)"
      $DLO "$tmp/checksums.txt.pem" "$base/checksums.txt.pem" 2>/dev/null \
        || err "no checksums.txt.pem published for $version; refusing unsigned checksums (set RUNEWARD_INSECURE_SKIP_SIGNATURE=1 to override)"
      cosign verify-blob \
        --certificate "$tmp/checksums.txt.pem" \
        --signature "$tmp/checksums.txt.sig" \
        --certificate-identity-regexp "$identity" \
        --certificate-oidc-issuer "$issuer" \
        "$tmp/checksums.txt" >/dev/null \
        || err "cosign verification failed for checksums.txt (set RUNEWARD_INSECURE_SKIP_SIGNATURE=1 to override)"
    fi
    info "Checksum signature OK"
  fi
  info "Verifying checksum"
  want=$(grep " $asset\$" "$tmp/checksums.txt" 2>/dev/null | awk '{print $1}' | head -n1)
  [ -n "$want" ] || err "no checksum entry for $asset in checksums.txt (set RUNEWARD_INSECURE_SKIP_CHECKSUM=1 to override)"
  if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "$tmp/$asset" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    got=$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')
  else
    err "no sha256 tool found (need sha256sum or shasum) to verify the download; set RUNEWARD_INSECURE_SKIP_CHECKSUM=1 to override"
  fi
  [ "$got" = "$want" ] || err "checksum mismatch for $asset (expected $want, got $got)"
  info "Checksum OK"
else
  err "no checksums.txt published for $version; refusing to install unverified binary (set RUNEWARD_INSECURE_SKIP_CHECKSUM=1 to override)"
fi

# --- extract -------------------------------------------------------------------
tar -xzf "$tmp/$asset" -C "$tmp"
# Release archives contain a binary named runeward (older ones may use
# runeward_<os>_<arch>).
if [ -f "$tmp/${BIN_NAME}" ]; then
  binpath="$tmp/${BIN_NAME}"
elif [ -f "$tmp/${BIN_NAME}_${os}_${arch}" ]; then
  binpath="$tmp/${BIN_NAME}_${os}_${arch}"
else
  binpath=$(find "$tmp" -type f -name "${BIN_NAME}*" ! -name '*.tar.gz' | head -n1)
  [ -n "$binpath" ] || err "could not find the runeward binary in the archive"
fi
chmod +x "$binpath"

# --- choose install dir --------------------------------------------------------
bindir="${RUNEWARD_BIN_DIR:-/usr/local/bin}"
if [ ! -d "$bindir" ] || [ ! -w "$bindir" ]; then
  if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && [ "$bindir" = "/usr/local/bin" ]; then
    info "Installing to $bindir (using sudo)"
    sudo install -m 0755 "$binpath" "$bindir/$BIN_NAME"
    installed="$bindir/$BIN_NAME"
  else
    bindir="$HOME/.local/bin"
    mkdir -p "$bindir"
    install -m 0755 "$binpath" "$bindir/$BIN_NAME"
    installed="$bindir/$BIN_NAME"
  fi
else
  install -m 0755 "$binpath" "$bindir/$BIN_NAME"
  installed="$bindir/$BIN_NAME"
fi

info "Installed: $installed"
case ":$PATH:" in
  *":$bindir:"*) : ;;
  *) warn "$bindir is not on your PATH. Add it, e.g.: export PATH=\"$bindir:\$PATH\"" ;;
esac

"$installed" version 2>/dev/null || true
info "Done. Run '$BIN_NAME --help' to get started."
