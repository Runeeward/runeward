# Naming and positioning

The product is **Rune Box**, made by the company **Runeward**. Its promise is:

> An environment where your agent can roam freely but with receipts.

Category line, where a short description is needed:

> The open-source governance harness for AI agents.

Supporting explanation:

> Put enforceable policy, human approvals, isolated execution, budgets, and signed evidence around
> any AI agent without replacing its model or orchestration framework.

## Product and technical names

| Use | For | Notes |
| --- | --- | --- |
| Rune Box | The product, in prose, titles, and UI copy | Formerly "Runeward Sandbox" and "Runeward". |
| Runeward | The company | Copyright, organization, and maintainer references. |
| environment | What the agent runs in, in user-facing copy | Prefer it over "box" or "cell". "Sandbox" stays the familiar term for a Citadel. |
| `runeward`, `runeward-egress`, `runeward-supervisor`, `runeward-browser` | Binaries and commands | Unchanged. |
| `RUNEWARD_*` | Environment variables | Unchanged. |
| `runeward.dev` | Kubernetes CRD group | Unchanged. |
| `runeward-*` crates, `runeward` (PyPI), `@runeward/sdk` (npm), `ghcr.io/runeeward/runeward*` | Packages and images | Unchanged. |

Technical names keep working across the rename: file paths (`.runeward/`), API paths, and
configuration fields are not renamed.

## Writing convention

Use the familiar term first. Add the Rune Box term only when it helps someone connect the UI or
documentation to an existing API path, configuration field, or Kubernetes kind.

| Write first | Rune Box compatibility name | Examples that retain it |
| --- | --- | --- |
| sandbox | Citadel | `/v1/citadels`, `Citadel` CRD |
| policy or policy file | Charter | `/v1/charters`, CLI `<charter>` arguments |
| approvals | Conclave | `/v1/conclave` |
| signed audit trail | Chronicle | `/v1/chronicle`, `[chronicle]` |
| network controls | Perimeter | `/perimeter`, egress implementation |
| budgets and limits | Rationing | `[rationing]` |
| agent group or fleet | Cohort | `/v1/cohorts`, `[cohort]` |
| signed policy bundle | Archive | `runeward archive` |

“Agent governance harness” is the product category, not a replacement name for an existing
Rune Box concept. Likewise, a Cohort remains a group of peer workers; do not use “subagent” as a
synonym for Cohort. A subagent is a child delegated by a parent agent in an external orchestrator.

Good: “Download the signed audit trail (Chronicle).”

Avoid: “Inspect the Chronicle” before the reader has learned what it does.

Compatibility names are not being removed in a breaking sweep. New UI labels and explanatory copy
use plain language; programmatic surfaces keep stable names until a separately versioned migration.

## Positioning boundaries

Lead with the control loop—policy, approval, execution, proof—not the number of agent frameworks or
runtime features. Rune Box is not a model, agent framework, or claim of perfect containment. It is an
enforcement and evidence layer around agent actions, with clearly documented backend guarantees.
