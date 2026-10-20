#!/usr/bin/env python3
"""Set every publishable Rune Box version from one validated input."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[1-9][0-9]*)?$")


def replace_one(path: Path, pattern: str, replacement: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise SystemExit(f"could not update {label} in {path.relative_to(ROOT)}")
    path.write_text(updated, encoding="utf-8")


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Set stable or RC versions across SDK, MCP, and Helm metadata."
    )
    parser.add_argument("version", help="for example 0.3.0 or 0.3.0-rc.1")
    args = parser.parse_args()
    version = args.version.removeprefix("v")
    if VERSION_RE.fullmatch(version) is None:
        parser.error("version must be MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-rc.N")

    replace_one(
        ROOT / "adapters/python/pyproject.toml",
        r'^(version\s*=\s*)["\'][^"\']+["\']\s*(?:#.*)?$',
        rf'\g<1>"{version}"',
        "Python project version",
    )
    replace_one(
        ROOT / "adapters/python/runeward/__init__.py",
        r'^__version__ = "[^"]+"$',
        f'__version__ = "{version}"',
        "Python import version",
    )

    npm_path = ROOT / "adapters/typescript/package.json"
    npm = json.loads(npm_path.read_text(encoding="utf-8"))
    npm["version"] = version
    write_json(npm_path, npm)

    lock_path = ROOT / "adapters/typescript/package-lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock["version"] = version
    lock["packages"][""]["version"] = version
    write_json(lock_path, lock)

    replace_one(
        ROOT / "crates/runeward-mcp/src/lib.rs",
        r'^pub const VERSION: &str = "[^"]+";$',
        f'pub const VERSION: &str = "{version}";',
        "MCP implementation version",
    )

    manifest_path = ROOT / "dist/mcp/server.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["version"] = version
    manifest["packages"][0]["identifier"] = f"ghcr.io/runeeward/runeward:v{version}"
    write_json(manifest_path, manifest)

    plugin_path = ROOT / "dist/codex-plugin/runeward/.codex-plugin/plugin.json"
    plugin = json.loads(plugin_path.read_text(encoding="utf-8"))
    plugin["version"] = version
    write_json(plugin_path, plugin)

    replace_one(
        ROOT / "deploy/helm/runeward/Chart.yaml",
        r"^version: [^\s]+$",
        f"version: {version}",
        "Helm chart version",
    )
    replace_one(
        ROOT / "deploy/helm/runeward/Chart.yaml",
        r'^appVersion: "[^"]+"$',
        f'appVersion: "{version}"',
        "Helm app version",
    )

    replace_one(
        ROOT / "Cargo.toml",
        r'^(\[workspace\.package\]\s*\nversion = )"[^"]+"$',
        f'\\1"{version}"',
        "Cargo workspace version",
    )
    # The workspace crates' entries in Cargo.lock follow the new version.
    subprocess.run(["cargo", "update", "--workspace", "--offline"], cwd=ROOT, check=True)

    print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
