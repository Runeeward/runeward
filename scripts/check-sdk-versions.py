#!/usr/bin/env python3
"""Fail a release when the tag and SDK package versions do not match."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def python_project_version() -> str:
    """Read the PEP 621 version without requiring Python 3.11's tomllib."""
    pyproject = (ROOT / "adapters/python/pyproject.toml").read_text(encoding="utf-8")
    project = re.search(
        r"^\[project\]\s*$\n(?P<body>.*?)(?=^\[|\Z)",
        pyproject,
        re.MULTILINE | re.DOTALL,
    )
    if project is None:
        raise SystemExit("could not find [project] in Python pyproject.toml")
    version = re.search(
        r'^version\s*=\s*["\']([^"\']+)["\']\s*(?:#.*)?$',
        project.group("body"),
        re.MULTILINE,
    )
    if version is None:
        raise SystemExit("could not find Python project version")
    return version.group(1)


def main() -> int:
    expected = sys.argv[1].strip() if len(sys.argv) > 1 else ""
    expected = expected.removeprefix("v")

    python_version = python_project_version()

    npm_version = json.loads(
        (ROOT / "adapters/typescript/package.json").read_text(encoding="utf-8")
    )["version"]
    npm_lock = json.loads(
        (ROOT / "adapters/typescript/package-lock.json").read_text(encoding="utf-8")
    )

    init_text = (ROOT / "adapters/python/runeward/__init__.py").read_text(
        encoding="utf-8"
    )
    match = re.search(r'^__version__ = "([^"]+)"$', init_text, re.MULTILINE)
    if match is None:
        raise SystemExit("could not find Python __version__")
    import_version = match.group(1)

    mcp_text = (ROOT / "crates/runeward-mcp/src/lib.rs").read_text(encoding="utf-8")
    mcp_match = re.search(r'^pub const VERSION: &str = "([^"]+)";$', mcp_text, re.MULTILINE)
    if mcp_match is None:
        raise SystemExit("could not find MCP implementation version")

    manifest = json.loads(
        (ROOT / "dist/mcp/server.json").read_text(encoding="utf-8")
    )
    manifest_version = manifest["version"]

    plugin_root = ROOT / "dist/codex-plugin/runeward"
    plugin = json.loads(
        (plugin_root / ".codex-plugin/plugin.json").read_text(encoding="utf-8")
    )

    chart_text = (ROOT / "deploy/helm/runeward/Chart.yaml").read_text(encoding="utf-8")
    chart_match = re.search(r'^version: ([^\s]+)$', chart_text, re.MULTILINE)
    if chart_match is None:
        raise SystemExit("could not find Helm chart version")
    app_match = re.search(r'^appVersion: "([^\"]+)"$', chart_text, re.MULTILINE)
    if app_match is None:
        raise SystemExit("could not find Helm appVersion")

    versions = {
        "Python project": python_version,
        "Python import": import_version,
        "npm package": npm_version,
        "npm lock": npm_lock["version"],
        "npm lock root": npm_lock["packages"][""]["version"],
        "MCP implementation": mcp_match.group(1),
        "MCP manifest": manifest_version,
        "Codex plugin": plugin["version"],
        "Helm chart": chart_match.group(1),
        "Helm app": app_match.group(1),
    }
    if len(set(versions.values())) != 1:
        for label, version in versions.items():
            print(f"{label}: {version}", file=sys.stderr)
        raise SystemExit("SDK package versions do not match")

    actual = python_version
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[1-9][0-9]*)?", actual) is None:
        raise SystemExit(f"unsupported stable/RC release version {actual!r}")
    if expected and actual != expected:
        raise SystemExit(f"SDK version {actual} does not match release version {expected}")

    image = manifest["packages"][0]["identifier"]
    if not image.endswith(f":v{actual}"):
        raise SystemExit(f"MCP OCI image {image!r} does not match v{actual}")

    if plugin.get("name") != plugin_root.name:
        raise SystemExit("Codex plugin name must match its directory")
    if plugin.get("skills") != "./skills/" or plugin.get("mcpServers") != "./.mcp.json":
        raise SystemExit("Codex plugin component paths are invalid")
    plugin_mcp = json.loads((plugin_root / ".mcp.json").read_text(encoding="utf-8"))
    runeward_mcp = plugin_mcp.get("mcpServers", {}).get("runeward", {})
    if runeward_mcp.get("command") != "runeward" or runeward_mcp.get("args") != ["mcp"]:
        raise SystemExit("Codex plugin MCP command must run `runeward mcp`")
    skill_path = plugin_root / "skills/runeward-governed-execution/SKILL.md"
    skill_text = skill_path.read_text(encoding="utf-8")
    frontmatter = re.match(r"^---\n(?P<body>.*?)\n---", skill_text, re.DOTALL)
    if frontmatter is None:
        raise SystemExit("Codex plugin skill has invalid frontmatter")
    for field in ("name", "description"):
        if re.search(rf"^{field}:\s*\S", frontmatter.group("body"), re.MULTILINE) is None:
            raise SystemExit(f"Codex plugin skill is missing {field}")

    print(actual)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
