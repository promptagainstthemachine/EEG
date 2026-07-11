# EEG CLI reference

Package: **`eeg-security`** · entry point: **`eeg`** / **`python -m eeg`**

The CLI is the supported surface for **local use**, **GitHub Actions**, and **PyPI-distributed** scans. Static analysis and dynamic gateway wrapping are both first-class modes.

## Modes

| Mode | Command | Role |
|------|---------|------|
| Static | `eeg --headless [PATH]` or `eeg scan [PATH]` | Catalog SAST profiles over a repo |
| Dynamic | `eeg --gateway-wrap URL` | Local EEG runtime proxy in front of an AI HTTP API |
| Console | `eeg --serve` | Full OSS Django web app |
| Meta | `eeg profiles` | List scan profiles from `catalog.yaml` |

```bash
eeg --help
eeg --headless --help
eeg --gateway-wrap --help
eeg --serve --help
```

## Static scans (`--headless` / `scan`)

```bash
eeg --headless .
eeg --headless ./app --profile full --cloud aws --format sarif -o out.sarif
eeg scan ./app --profile agent --fail-on high --pretty
```

| Option | Values | Default |
|--------|--------|---------|
| `target` | path | `.` |
| `--profile` | `code` `agent` `full` `model` `dep` | `code` |
| `--format` | `json` `sarif` | `json` |
| `--output` / `-o` | file | stdout |
| `--fail-on` | `none` `low` `medium` `high` `critical` `any` | `high` |
| `--cloud` | `aws` `azure` `gcp` `any` | unset |
| `--include-model` | flag | off |
| `--pretty` / `--verbose` | flags | off |

Profiles are defined in `eeg/rules/catalog.yaml` (`scan_profiles`). CI should prefer `--format sarif` for code-scanning upload.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings at/above `--fail-on` |
| `1` | Findings meet fail threshold |
| `2` | Bad path / usage / hard error |

## Dynamic gateway (`--gateway-wrap`)

Technically: EEG binds a local HTTP server that proxies OpenAI-style chat completions through the EEG gateway runtime (policy, blocks, headers). Upstream URL is normalized to `…/v1/chat/completions` when needed.

```bash
eeg --gateway-wrap https://myaiapp.example --host 127.0.0.1 --port 8787
curl -s http://127.0.0.1:8787/   # health JSON
```

| Option | Default | Notes |
|--------|---------|-------|
| `--gateway-wrap URL` | required | Upstream AI app / API |
| `--host` | `127.0.0.1` | Bind address |
| `--port` | `8787` | Bind port |
| `--no-private-upstream` | off | Reject private/loopback targets |

Local demos against loopback: `EEG_ALLOW_PRIVATE_UPSTREAM=1`.

This is the CLI path for **dynamic** protection where a full in-cluster gateway is not yet deployed. Production orgs typically also use the OSS/SAAS gateway with agent keys (`X-EEG-Agent` / metadata).

## Console (`--serve`)

```bash
pip install -r requirements.txt
eeg --serve --host 127.0.0.1 --port 8000
```

Requires the Django stack from `requirements.txt` (not all of which ships as hard deps of the minimal PyPI wheel).

## GitHub Action

Composite action: `.github/actions/eeg-scan/action.yml` — runs:

```bash
python -m eeg scan "$PATH" --profile … --format … --output … --fail-on …
```

Root `action.yml` installs `eeg-security` from PyPI (optional version pin) and invokes the same CLI. Keep Action inputs aligned with these flags when changing the CLI.

Repo CI: `.github/workflows/eeg-scan.yml` scans `fixtures/vulnerable-agent` to SARIF and runs CLI fixture tests.

## PyPI

Workflow: `.github/workflows/publish.yml`

- Trigger: push to `main` (markdown/docs-only changes ignored)
- Job `test`: pytest matrix 3.9–3.12
- Job `publish`: `python -m build` → `pypa/gh-action-pypi-publish` (OIDC trusted publishing)

Bump `[project].version` in `pyproject.toml` for each intended release.

## Fixtures

| Path | Purpose |
|------|---------|
| `fixtures/vulnerable-agent` | Must produce multiple critical findings on `code` |
| `fixtures/clean-agent` | Must stay clean on `code` |
| `fixtures/expected/*.json` | Golden expectations for `tests/test_scan_fixtures.py` |

## Packaging notes

- Console script: `eeg = eeg.cli:main` (`pyproject.toml`)
- Package data: rule YAML under `eeg/rules/**`, runtime packs
- Optional extras: `[aws]`, `[azure]`, `[gcp]`, `[all]`, `[dev]`
