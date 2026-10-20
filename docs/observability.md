# Observability

Operators run `runeward serve` and `runeward controller` as long-lived
services, so both expose Prometheus metrics and emit structured logs. Usage
telemetry is available too, but it is strictly opt-in and off by default.

## Metrics

The control plane serves Prometheus metrics at `GET /metrics` (same listener as
the REST API and dashboard; when an API token / RBAC is configured, `/metrics`
requires the token too, so give the scraper a bearer credential). Point a
scraper at it — the `job_name` must contain `runeward` so the
`RunewardTargetDown` alert matches:

```yaml
scrape_configs:
  - job_name: runeward
    metrics_path: /metrics
    static_configs:
      - targets: ["localhost:8080"]
```

The control plane exports:

| Metric                             | Type      | Labels           | Meaning                                              |
| ---------------------------------- | --------- | ---------------- | ---------------------------------------------------- |
| `runeward_actions_total`           | counter   | `tool`, `verdict`| Governed actions processed, by tool and verdict.     |
| `runeward_actions_duration_seconds`| histogram | `tool`           | Wall-clock duration of executed governed actions.    |
| `runeward_sandboxes_created_total` | counter   | —                | Sandboxes created since start.                       |
| `runeward_usage_tokens_total`      | counter   | `profile`        | Model tokens reported via the usage API, by profile. |
| `runeward_usage_cost_usd_total`    | counter   | `profile`        | Reported spend (USD) via the usage API, by profile.  |
| `runeward_build_info`              | gauge     | `version`        | Always `1`; carries the running version as a label.  |

`verdict` mirrors the ledger: `allow`, `deny`, `require-approval`, or `error`.
A label series appears only after its first event, so a fresh process shows just
`runeward_build_info` and `runeward_sandboxes_created_total` until traffic flows.

Because `runeward_actions_duration_seconds` is a histogram, Prometheus also
exposes `runeward_actions_duration_seconds_bucket` (with an `le` label),
`_sum`, and `_count` series for quantile and average calculations.

## Grafana dashboard

A ready-to-import dashboard lives at
[`deploy/grafana/runeward-dashboard.json`](https://github.com/Runewardd/runeward/blob/main/deploy/grafana/runeward-dashboard.json).
It contains only panels built from the metrics above: deny ratio,
require-approval rate, action rate by verdict, top tools by action rate, p95
action duration per tool, sandbox creation rate/total, and a build-info table.

To import:

1. In Grafana, go to **Dashboards → New → Import**.
2. Upload `runeward-dashboard.json` (or paste its contents).
3. When prompted for the **`DS_PROMETHEUS`** input, select the Prometheus
   datasource that scrapes Rune Box, then click **Import**.

Every panel references the `${DS_PROMETHEUS}` datasource, so the whole
dashboard is repointed by that single selection.

## Alert rules

Prometheus alerting rules live at
[`deploy/prometheus/runeward-alerts.yaml`](https://github.com/Runewardd/runeward/blob/main/deploy/prometheus/runeward-alerts.yaml).
Reference the file from `prometheus.yml` and reload (or restart) Prometheus:

```yaml
rule_files:
  - /etc/prometheus/rules/runeward-alerts.yaml
```

```bash
# Validate before shipping (part of the Prometheus toolchain):
promtool check rules deploy/prometheus/runeward-alerts.yaml

# Hot-reload a running Prometheus once the file is in place:
curl -X POST http://localhost:9090/-/reload
```

The group `runeward` contains:

| Alert                      | Severity | Fires when                                                        | Indicates                                                            |
| -------------------------- | -------- | ----------------------------------------------------------------- | -------------------------------------------------------------------- |
| `RunewardDenySpike`        | warning  | deny ratio > 50% for 10m                                          | Policy is blocking most traffic — bad actor or too-strict profile.   |
| `RunewardHighActionLatency`| warning  | p95 action duration for a tool > 30s for 10m                      | Governed actions are slow; backend/sandbox or downstream is degraded.|
| `RunewardNoActivity`       | info     | overall action rate == 0 for 30m                                  | Idle, or agents can no longer reach the control plane.               |
| `RunewardTargetDown`       | critical | `up` for a `.*runeward.*` job == 0 for 5m                         | The control plane is down or unreachable.                            |

## Structured logs

Both services log through Go's `log/slog`. Two environment variables control
output (stderr):

| Variable               | Values                          | Default |
| ---------------------- | ------------------------------- | ------- |
| `RUNEWARD_LOG_FORMAT`  | `text`, `json`                  | `text`  |
| `RUNEWARD_LOG_LEVEL`   | `debug`, `info`, `warn`, `error`| `info`  |

Use `json` when shipping to a log aggregator:

```bash
RUNEWARD_LOG_FORMAT=json RUNEWARD_LOG_LEVEL=info runeward --config-dir examples serve
```

```json
{"time":"2026-07-04T11:28:37Z","level":"INFO","msg":"request","method":"POST","path":"/v1/citadels","status":200,"duration_ms":142}
```

`/metrics` and `/healthz` are excluded from the access log so scrapes and health
probes do not drown out the signal.

## Telemetry (opt-in, off by default)

Rune Box never phones home unless you turn it on **and** point it at a collector
you control. Telemetry is active only when both are set:

```bash
export RUNEWARD_TELEMETRY=1
export RUNEWARD_TELEMETRY_ENDPOINT=https://your-collector.example/ingest
```

The [DO_NOT_TRACK](https://consoledonottrack.com) convention always wins: if
`DO_NOT_TRACK` is truthy, telemetry stays off regardless of the flags above.

What is sent: a small JSON event per service start containing only the Rune Box
`version`, `os`, `arch`, and non-identifying properties (e.g. whether the
dashboard is enabled). There are no hostnames, paths, profile contents, IDs, or
any other identifying data, and no persistent device identifier. Sends are
best-effort with a 2-second timeout and never block or fail the process.

Every `serve`/`controller` startup logs the current telemetry state so it is
never a surprise:

```
telemetry disabled (opt in with RUNEWARD_TELEMETRY=1 and RUNEWARD_TELEMETRY_ENDPOINT)
```
