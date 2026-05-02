# EEG Architecture

> **Extensive Exposure Guard** — Multi-Cloud AI Security & Vulnerability Management Framework

## High-Level Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                    CLI                                       │
│                              (eeg/cli.py)                                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
         ┌───────────────────────────┼───────────────────────────┐
         ▼                           ▼                           ▼
┌─────────────────┐      ┌─────────────────────┐      ┌─────────────────────┐
│  Static Scan    │      │   Authenticated     │      │   Vulnerability     │
│  (Detectors)    │      │   Live Audit        │      │   Management        │
└─────────────────┘      └─────────────────────┘      └─────────────────────┘
         │                           │                           │
         ▼                           ▼                           ▼
┌─────────────────┐      ┌─────────────────────┐      ┌─────────────────────┐
│  YAML Rules     │      │  AWS/Azure/GCP      │      │  NVD CVE Fetcher    │
│  (rules/static) │      │  Auth Scanners      │      │  Dependency Parser  │
└─────────────────┘      └─────────────────────┘      └─────────────────────┘
         │                           │                           │
         └───────────────────────────┼───────────────────────────┘
                                     ▼
                          ┌─────────────────────┐
                          │     Collector       │
                          │  (Deduplication)    │
                          └─────────────────────┘
                                     │
                                     ▼
                          ┌─────────────────────┐
                          │   Report Generators │
                          │  JSON / HTML / CSV  │
                          └─────────────────────┘
```

## Directory Structure

```
eeg/
├── __init__.py
├── __main__.py          # Entry point for `python -m eeg`
├── cli.py               # CLI argument parsing and orchestration
├── collector.py         # Finding aggregation with deduplication
│
├── detectors/           # Static analysis detectors (AST + Regex)
│   ├── base.py          # Abstract base class, rule loader
│   ├── iam.py           # IAM/permission misconfiguration
│   ├── guardrail.py     # AI guardrail configuration
│   ├── model.py         # Model security (weights, endpoints)
│   ├── network.py       # Network exposure detection
│   ├── policy.py        # Policy misconfigurations
│   ├── prompt.py        # Prompt injection patterns
│   ├── secrets.py       # Hardcoded secrets/keys
│   ├── storage.py       # Storage bucket security
│   ├── logging_monitor.py # Logging configuration
│   └── iac.py           # Infrastructure-as-Code issues
│
├── auth_scanner/        # Live authenticated scanning
│   ├── aws_scanner.py   # Bedrock, SageMaker audit
│   ├── azure_scanner.py # Azure OpenAI, AI Foundry audit
│   ├── gcp_scanner.py   # Vertex AI audit
│   └── check_runner.py  # Config-driven check execution
│
├── vuln_manager/        # Vulnerability management
│   ├── cve_fetcher.py   # NVD API integration
│   └── dependency_parser.py # AI package detection
│
├── rules/               # Detection rules
│   ├── static/          # Static analysis rules (YAML)
│   │   ├── aws_static.yaml
│   │   ├── azure_static.yaml
│   │   └── gcp_static.yaml
│   └── dynamic/         # Live audit check configs
│
└── utils/               # Shared utilities
    ├── auth.py          # Cloud credential discovery
    ├── cloud_console.py # Cloud shell detection
    ├── repocrawler.py   # File system traversal
    ├── threadpoolexecutor.py # Parallel scanning
    ├── htmlreport.py    # HTML report generator
    ├── jsonreport.py    # JSON report generator
    └── csvreport.py     # CSV report generator
```

## Core Components

### 1. CLI (`cli.py`)

Entry point that orchestrates the entire scan pipeline:

1. Parse arguments
2. Detect console environment (local vs cloud shell)
3. Authenticate if `--auth true`
4. Run static analysis via detectors
5. Run live audit via auth scanners (if authenticated)
6. Fetch CVEs via vulnerability manager (if `--vm true`)
7. Generate report

### 2. Collector (`collector.py`)

Central aggregator for all findings:

- **Finding**: Dataclass with rule_id, severity, category, file_path, line_number, code_snippet, recommendation, CWE, OWASP LLM mapping
- **Deduplication**: Key = `rule_id|file_path|line_number`
- **Permission Tracking**: Records checks skipped due to IAM restrictions
- **Metadata**: Stores scan context (cloud, auth status, duration)

### 3. Detectors (`detectors/`)

Plugin-style detection modules:

```python
class BaseDetector:
    def __init__(self, cloud_env: str):
        self.rules = self._load_rules()  # From YAML
    
    def scan(self, files: List[Dict], collector: Collector):
        for rule in self.rules:
            self._run_rule(rule, files, collector)
    
    def _scan_regex(self, rule, files, collector): ...
    def _scan_ast(self, rule, files, collector): ...
```

Each detector (IAMDetector, GuardrailDetector, etc.) inherits from `BaseDetector` and automatically loads rules for its `category` from YAML.

### 4. Rules (`rules/static/*.yaml`)

YAML-driven detection patterns:

```yaml
rules:
  - id: AWS-IAM-001
    name: "Wildcard Bedrock permissions"
    severity: CRITICAL
    category: iam
    owasp_llm: "LLM06: Excessive Agency"
    patterns:
      - type: regex
        match: '["'']bedrock:\*["'']'
        file_types: [".py", ".json", ".yaml", ".tf"]
    recommendation: "Scope to specific actions"
```

**Pattern Types:**
- `regex`: Line-by-line regex matching
- `ast`: Python AST analysis (f-string injection, etc.)
- `regex_absent`: Detect missing patterns (e.g., missing guardrail)

### 5. Auth Scanners (`auth_scanner/`)

Live resource auditing via cloud APIs:

```python
class AWSAuthScanner:
    def scan(self, collector: Collector):
        self._check_guardrails(bedrock, collector)
        self._check_agents(bedrock_agent, collector)
        self._check_knowledge_bases(bedrock_agent, s3, collector)
        self._check_model_invocation_logging(bedrock, collector)
```

**Dual-Mode Execution:**
- SDK mode (boto3/azure-identity/google-cloud)
- CLI fallback (aws/az/gcloud CLI for cloud shells)

### 6. Vulnerability Manager (`vuln_manager/`)

```
┌──────────────────┐     ┌─────────────────┐     ┌──────────────┐
│ DependencyParser │────▶│  AI Package     │────▶│  CVEFetcher  │
│ (requirements.txt│     │  Registry       │     │  (NVD API)   │
│  pyproject.toml) │     │  (AI keywords)  │     └──────────────┘
└──────────────────┘     └─────────────────┘
```

- Parses `requirements.txt`, `pyproject.toml`, `Pipfile`
- Filters to AI-relevant packages (langchain, openai, boto3, etc.)
- Queries NVD API with keyword mapping

### 7. Cloud Console Detection (`utils/cloud_console.py`)

Detects cloud shell environments for seamless operation:

| Environment | Detection Method |
|-------------|------------------|
| Azure Cloud Shell | `ACC_CLOUD=AzureCloud`, `/home/cloudshell` |
| AWS CloudShell | `AWS_EXECUTION_ENV=CloudShell` |
| GCP Cloud Shell | `CLOUD_SHELL=true` |

## Data Flow

```
Input Repository
       │
       ▼
┌─────────────────┐
│  RepoCrawler    │  Traverses files, filters by extension
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Detectors[]    │  Run YAML-driven rules (regex + AST)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  AuthScanner    │  (Optional) Live API audit
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  CVEFetcher     │  (Optional) NVD vulnerability lookup
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Collector      │  Aggregate + Deduplicate
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  ReportGenerator│  JSON / HTML / CSV output
└─────────────────┘
```

## Severity Levels

| Level | Weight | Description |
|-------|--------|-------------|
| CRITICAL | 5 | Immediate exploitation risk (public model weights, admin creds) |
| HIGH | 4 | Serious misconfiguration (weak guardrails, wildcard IAM) |
| MEDIUM | 3 | Notable security gap (missing logging, broad permissions) |
| LOW | 2 | Best practice violation |
| INFO | 1 | Informational finding |

## Threading Model

```
--thread med  →  ThreadPoolExecutor(max_workers=4)
--thread max  →  ThreadPoolExecutor(max_workers=8)
(default)     →  Sequential execution
```

Files are distributed to worker threads, each running detector scans independently.

## Extension Points

### Adding a New Detector

1. Create `eeg/detectors/newcategory.py`:
   ```python
   from eeg.detectors.base import BaseDetector
   
   class NewCategoryDetector(BaseDetector):
       name = "newcategory"
       category = "newcategory"
   ```

2. Add rules to `eeg/rules/static/{cloud}_static.yaml`:
   ```yaml
   - id: AWS-NEWCAT-001
     category: newcategory
     ...
   ```

3. Register in `eeg/detectors/__init__.py`

### Adding a New Cloud Provider

1. Create `eeg/auth_scanner/{cloud}_scanner.py`
2. Add static rules in `eeg/rules/static/{cloud}_static.yaml`
3. Add console detection in `eeg/utils/cloud_console.py`
4. Update CLI choices in `cli.py`

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=eeg --cov-report=html

# Run specific test file
pytest tests/test_detectors.py -v
```

## Security Standards Alignment

- **OWASP LLM Top 10**: Mapped in findings (`owasp_llm` field)
- **CWE**: Common Weakness Enumeration IDs (`cwe` field)
- **CVSS**: CVE severity from NVD API
