# Scan drift replay (API layer)

`replay.py` drives a running Harbor through its REST and registry APIs with the scan report
scenarios in `src/pkg/scan/postprocessors/drift/testdata/scenarios/*.yaml` and records what a user
sees. The DB-layer suite in `src/pkg/scan/postprocessors/drift` replays the same files against the
persistence code directly. Together they pin the current behavior of the scan report write path
(`report_converters.go`), so a rewrite can be checked against it.

## What a run does

Per scenario, in a fresh project `scandrift-<random>`:

- pushes one tiny image per artifact label (random config and layer, so digests are unique),
  repository `<project>/<label>`, tag `<label>`
- registers a webhook policy for `SCANNING_COMPLETED` and `SCANNING_FAILED` that posts to a
  receiver run by the script
- runs the steps:
  - `register_scanner`: `POST /scanners` pointing at the stub scanner
  - `scan`: stores the step's report in the stub, sets the project scanner, `POST .../scan`, polls
    the scan overview until a new report reaches `Success` or `Error`
  - `concurrent`: starts the group's scans in parallel threads (one scanner per group, since the
    project has one scanner)
  - `delete_artifact`, `delete_scanner`: the DELETE call; a refusal is recorded as `error: <status>`
  - `cleanup`: no-op, recorded as `ok`
  - `capture`: records the outputs below; `rows_unchanged` is DB-only and ignored
- deletes the project and its scanners, and restores the original default scanner

Capture outputs, per live (artifact, scanner) unless noted:

| | API | Scanner it reads |
|---|---|---|
| O1 | `GET .../artifacts/{tag}/additions/vulnerabilities` | project scanner |
| O2 | `GET .../artifacts/{tag}?with_scan_overview=true` | project scanner |
| O3 | `GET /security/summary?with_dangerous_cve=true&with_dangerous_artifact=true`, `GET /security/vul` (all, `severity=Critical`, `cvss_score_v3=[7.0~10.0]`, all filtered by `project_id`), per scanner | system default scanner |
| O4 | `POST /export/cve` for the project, CSV download, once per capture | every scanner (the export SQL does not filter by registration) |
| O7 | webhook payloads received since the previous capture, once per capture | project scanner |
| O8 | manifest GET with `prevent_vul=true`, `severity=high`; again with the highest CVE allowlisted; again with every High and Critical CVE allowlisted | project scanner |

Scoping comes from the code: `controller/scan/base_controller.go` `GetReport` and `controller/scan/checker.go`
use `GetRegistrationByProject`; `server/v2.0/handler/security.go` and `controller/securityhub` use
`DefaultScannerUUID`; `pkg/scan/export/manager.go` joins every `scanner_registration`. The replay
switches the project scanner (O1, O2, O7, O8) or the default scanner (O3) to each scenario scanner in turn.

Normalization replaces digests, project name and id, scanner names and UUIDs, stub scanner names
and artifact ids with labels, replaces any other UUID with `<uuid>`, drops timestamps, durations,
report and execution ids, sorts lists whose order the API does not define, and hashes strings over
512 characters in the DB layer's `<long:len:sha16>` format. Recording runs every scenario twice and
refuses to write a golden file when the two runs differ.

Two API results depend on record ids or ties, so they are recorded the way the DB layer records
them:

- `/security/vul` is read page by page to the end. It orders by score, then record id, so a single
  page holds whichever records got the lowest ids, which differs between concurrent runs and between
  write paths.
- A full top-5 list in `/security/summary` (dangerous artifacts and CVEs) orders only by counts or
  score, so which of several tied rows makes the cut varies (s09). It is recorded by its ordering
  values only.

`/security/summary` is global: totals and dangerous CVEs include every artifact in the instance.
Run against a devenv that holds no other scanned artifacts. The script removes leftover
`scandrift-*` projects and scanners at start.

Expected differences from the DB layer (`--compare-db` reports them):

- `s12` after-rejected-reports: an empty or `null` report fails the scan job, so the API overview
  shows `scan_status: Error` with no severity or summary. The DB layer only calls the converter and
  keeps the previous `Success` summary. The findings (O1) still match: the old report rows survive.

Not covered: `s19-large-report` (no YAML scenario), `rows_unchanged` (needs DB access). Reports of a
deleted scanner are not reachable through the API, so `s17` shows only the surviving scanner.

## Run

Devenv on SLOT=2 (core 8280, postgres 5632, redis 6579, registry 50200). The full `task dev:up`
compiles three services in parallel and can exhaust Docker Desktop memory, so start them one at a time:

```bash
task dev:infra:up SLOT=2
task dev:gen:private-key dev:gen:secret-key SLOT=2
task build:gen-apis
export COMPOSE_PROJECT_NAME=harbor-2 PROJECT_PREFIX=harbor-2 PORT_CORE=8280 PORT_PORTAL=4400 \
  PORT_POSTGRES=5632 PORT_REDIS=6579 PORT_REGISTRY=50200 PORT_REGISTRYCTL=8285 PORT_TRIVY=8281 \
  PORT_DEBUG_REGISTRYCTL=2547 HOST_GOMODCACHE=$(go env GOMODCACHE) HOST_GOCACHE=$(go env GOCACHE) \
  DEV_UID=$(id -u) DEV_GID=$(id -g)
dc() { docker compose -f devenv/docker-compose.yml --env-file versions.env "$@"; }   # works in bash and zsh
dc --profile core up -d --build core              # wait for curl localhost:8280/api/v2.0/ping
dc --profile core --profile jobservice up -d --no-deps jobservice   # wait for "API server is serving"
dc --profile registryctl up -d --no-deps registryctl
```

Stub scanner on the host, reachable from the containers as `host.docker.internal:18089`:

```bash
cd src && go run ./testing/stubscanner -addr :18089
```

Replay (Python 3 with PyYAML; the webhook receiver listens on :18090):

```bash
python3 -I tests/scan-drift/replay.py                 # record tests/scan-drift/golden/*.json (two runs each)
python3 -I tests/scan-drift/replay.py --check         # compare, print a unified diff, exit 1 on drift
python3 -I tests/scan-drift/replay.py --only s04,s11  # subset by name prefix
python3 -I tests/scan-drift/replay.py --compare-db    # O1/O2 versus the DB-layer goldens
SCAN_DRIFT_TRACE=1 python3 -I tests/scan-drift/replay.py --check --only s01   # per-request timings
```

A full recording takes roughly 30 to 60 minutes; most of it is waiting for scan, export and webhook jobs.

## Check a new implementation

1. Put the new code in the workspace the devenv mounts (or rebuild the devenv from the new
   workspace). Air rebuilds core on any `.go` change under `src/`, and jobservice also on `.yaml`/`.yml` changes there (the scenario files), so do not edit `src/` while a replay runs; wait for
   `/api/v2.0/ping` and for jobservice to log `API server is serving`.
2. Keep the stub scanner running.
3. `python3 -I tests/scan-drift/replay.py --check`. Any diff is a behavior change. Scenarios with a
   `known_bug` in their YAML pin a defect on purpose (s11); a diff there is expected once the bug
   is fixed and must match the scenario's `expect_fixed`.
