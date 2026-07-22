# `EEG - Extensive Exposure Guard`

### Full fledged AI Security gateway and static analysis tool

![](asset/logo.png)

[![PyPI](https://img.shields.io/pypi/v/eeg-security)](https://pypi.org/project/eeg-security/)
[![Python](https://img.shields.io/pypi/pyversions/eeg-security)](https://pypi.org/project/eeg-security/)
[![Tests](https://github.com/findthehead/EEG/actions/workflows/publish.yml/badge.svg)](https://github.com/findthehead/EEG/actions/workflows/publish.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **AI-first cloud security.** EEG catches AI-specific risks in agent code and at runtime — before and after you ship.

| Surface | How |
|---------|-----|
| **Static (SAST)** | `eeg --headless` / `eeg scan` — catalog profiles over your repo |
| **Dynamic (gateway)** | `eeg --gateway-wrap URL` — local EEG runtime in front of an AI app |
| **Console** | `eeg --serve` — full OSS web app (Django) |
| **CI** | GitHub Action + CLI exit codes / SARIF |
| **Distribute** | Push to `main` → tests → publish **eeg-security** to PyPI |

See [docs/CLI.md](docs/CLI.md) for full CLI reference.

---

## Installation

```bash
pip install eeg-security
```

This installs the **full package**: CLI (scan / gateway-wrap), rules, and the OSS dashboard (`eeg --serve`), including Django and console dependencies.

Cloud extras (optional authenticated / cloud-static paths):

```bash
pip install eeg-security[aws]
pip install eeg-security[azure]
pip install eeg-security[gcp]
pip install eeg-security[all]
```

From source:

```bash
git clone https://github.com/findthehead/EEG.git
cd EEG
pip install -e ".[dev]"
```

```bash
pip install --upgrade eeg-security
```

---

## Quick start

```bash
# Static catalog scan (CI / local) — default profile: code
eeg --headless .
eeg --headless ./my-agent --profile full --format sarif -o eeg-results.sarif
eeg scan ./my-agent --profile agent --fail-on high

# List profiles from catalog.yaml
eeg profiles

# Dynamic runtime: wrap an OpenAI-compatible / chat endpoint
eeg --gateway-wrap https://myaiapp.example --port 8787
# Point your app or clients at http://127.0.0.1:8787

# Full OSS web UI (included with pip install eeg-security)
eeg --serve --host 127.0.0.1 --port 8000
```

Equivalent module form (useful in CI):

```bash
python -m eeg --headless . --profile code --format sarif -o eeg-results.sarif
python -m eeg scan . --profile code --fail-on high
```

---

## CLI modes

### 1. Static — `--headless` / `scan`

Runs scan profiles from `eeg/rules/catalog.yaml` against a directory.

| Flag | Default | Description |
|------|---------|-------------|
| `target` | `.` | Path to scan |
| `--profile` | `code` | `code` · `agent` · `full` · `model` · `dep` |
| `--format` | `json` | `json` or `sarif` |
| `--output` / `-o` | stdout | Write report file |
| `--fail-on` | `high` | `none` · `low` · `medium` · `high` · `critical` · `any` |
| `--cloud` | — | `aws` · `azure` · `gcp` · `any` (enables cloud static rules on `full`) |
| `--include-model` | off | Add model artifact scan |
| `--pretty` | off | Pretty-print JSON |
| `--verbose` | off | Scanner progress |

**Profiles (summary):**

| Profile | Focus |
|---------|--------|
| `code` | Code security, forensics, gateway OSS surface |
| `agent` | Agent / MCP / memory / gateway surfaces |
| `full` | Broad static pack (+ cloud static when `--cloud` set) |
| `model` | Model artifacts |
| `dep` | Dependency / CVE-oriented dependency scan |

### 2. Dynamic — `--gateway-wrap`

Puts EEG’s runtime gateway in front of an upstream AI HTTP endpoint (OpenAI-style chat completions where possible). Use for local dynamic protection and smoke tests before wiring production gateways.

```bash
eeg --gateway-wrap https://api.example.com --host 127.0.0.1 --port 8787
# Health: GET http://127.0.0.1:8787/  → {"status":"ok","mode":"gateway-wrap",...}
```

Private/loopback upstreams are gated; set `EEG_ALLOW_PRIVATE_UPSTREAM=1` for local demos, or pass `--no-private-upstream` to refuse them.

### 3. Console — `--serve`

Runs the full Django OSS dashboard. Included with `pip install eeg-security` (no extra requirements file needed).

Runtime data (SQLite DB, repos) defaults to `~/.eeg` for PyPI installs, or the repo root in a source checkout. Override with `EEG_HOME`.

---

## Exit codes (CI)

| Code | Meaning |
|------|---------|
| `0` | Below `--fail-on` threshold |
| `1` | Findings at or above `--fail-on` |
| `2` | Usage / path / execution error |

---

## GitHub Action

The published Action runs the **same CLI** used locally (`python -m eeg scan …`). Prefer the composite action under `.github/actions/eeg-scan`, or the repo root Action after install from PyPI.

### Composite action (in-repo / reusable)

```yaml
name: AI Security Scan
on: [push, pull_request]

jobs:
  eeg:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install EEG
        run: pip install eeg-security
      - name: EEG scan
        uses: findthehead/EEG/.github/actions/eeg-scan@main
        with:
          path: .
          profile: code
          format: sarif
          output: eeg-results.sarif
          fail-on: high
```

### Root Action inputs (marketplace-style)

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to scan | `.` |
| `profile` | `code` · `agent` · `full` · `model` · `dep` | `code` |
| `format` | `json` · `sarif` | `sarif` |
| `output` | Report path | `eeg-results.sarif` |
| `fail-on` | Severity gate | `high` |
| `version` | Pin `eeg-security==…` | latest |
| `cloud` | Optional `--cloud` | — |

Example:

```yaml
- uses: findthehead/EEG@v1
  with:
    path: .
    profile: code
    format: sarif
    output: eeg-results.sarif
    fail-on: high
```

Upload SARIF to code scanning with `github/codeql-action/upload-sarif` when desired.

---

## PyPI release

On push to **`main`** (non-docs paths), [`.github/workflows/publish.yml`](.github/workflows/publish.yml):

1. Runs the test matrix (Python 3.9–3.12)
2. Builds the package
3. Publishes **`eeg-security`** to PyPI via trusted publishing (OIDC)

Configure the PyPI project’s trusted publisher for this GitHub repo before the first publish. `skip-existing: true` avoids failing on already-published versions — bump `version` in `pyproject.toml` when you intend a new release.

---

## What it scans (high level)

- **Agent & prompt risks** — injection, unsafe agency, secrets in prompts/config  
- **MCP / A2A / gateway surfaces** — client configs, tool response leaks, OSS gateway patterns  
- **Code & forensics packs** — vendored rule bundles (practice patterns, prompt guard, etc.)  
- **Dependencies** — AI-stack oriented dependency / CVE paths (`dep` / `full`)  
- **Cloud static** — AWS / Azure / GCP AI surface rules when `--cloud` is set on `full`  
- **Runtime (gateway-wrap / OSS gateway)** — ML-only guardrails (BERT / transformers): prompt injection, jailbreak, toxicity, PII, tool abuse. Config: `eeg/runtime/runtime_ml_models.yaml`. See [docs/RUNTIME_ML.md](docs/RUNTIME_ML.md).  

---

## Architecture & structure

```
eeg/
├── cli.py / cli_serve.py   # CLI: headless, serve, gateway-wrap
├── scans/                  # Static scan registry
├── probes/                 # Dynamic / HTTP surface probes
├── gateway/                # Runtime proxy & streaming
├── rules/                  # catalog.yaml + static/dynamic/bundles
└── runtime/                # ML guard (BERT/transformers) + policy
```

Web UI and org features live under `apps/`, `core/`, `eeg/webdata/` (templates + static), and `manage.py` (OSS console via `--serve`).

### Runtime ML (OSS)

OSS runtime detection is **gated to HuggingFace transformers** (`platform: hf|local`, `inference: transformers` only). Install:

```bash
pip install -r requirements-runtime-ml.txt
# or: pip install transformers torch
```

Disable: `EEG_RUNTIME_ML=0`. Full reference: [docs/RUNTIME_ML.md](docs/RUNTIME_ML.md). SaaS adds Ollama / **guard_http** (remote Llama Guard service) / URI backends — see [`../EEG-SAAS/backend/docs/RUNTIME_ML.md`](../EEG-SAAS/backend/docs/RUNTIME_ML.md).

---

## Testing

```bash
pip install -e ".[dev]"
pytest tests/test_cli.py tests/test_scan_fixtures.py tests/test_catalog_loader.py -v

# Manual CLI smoke
python -m eeg profiles
python -m eeg --headless fixtures/vulnerable-agent --profile code --fail-on none
python -m eeg --gateway-wrap --help
```

Benchmark fixtures: `fixtures/vulnerable-agent`, `fixtures/clean-agent`.

---

## Troubleshooting

**`error: not a directory`** — pass a real project path to `--headless` / `scan`.

**Gateway wrap refuses upstream** — private/loopback targets need `EEG_ALLOW_PRIVATE_UPSTREAM=1`, or use a public URL; `--no-private-upstream` forces refusal.

**`eeg --serve` import/Django errors** — upgrade to the latest `eeg-security` (≥2.5). Console deps ship with the package; set `EEG_HOME` if the default data dir is not writable.

**Action / PyPI version lag** — wait for the publish workflow on `main`, or `pip install git+https://github.com/findthehead/EEG.git`.

---

## Contributing

Pull requests welcome. For major changes, open an issue first. Keep CLI, Action, and README aligned — the Action must call the same `eeg` / `python -m eeg` entry points.

## License

[MIT](LICENSE)
