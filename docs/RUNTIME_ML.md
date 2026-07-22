# Runtime ML guardrails

Runtime detection (prompt injection, jailbreak, toxicity, PII, tool abuse) runs **before agent dispatch** via ML models — not regex heuristics.

Static code analysis (Semgrep / rule packs) is unchanged and separate.

## OSS vs SaaS

| | **EEG OSS** | **EEG SaaS** |
|--|-------------|--------------|
| Config | `eeg/runtime/runtime_ml_models.yaml` | same path under SaaS `backend/eeg/runtime/` |
| **platform** | `hf` \| `local` only | `hf` \| `local` \| `uri` |
| **inference** | `transformers` only (BERT-family) | `transformers` \| `ollama` \| `llama_cpp` |
| Default stack | DeBERTa PI + Toxic-BERT + AI4Privacy PII | Same BERT defaults; optional Llama Guard via llama.cpp / Ollama |

OSS **rejects** `ollama` / `llama_cpp` / `uri` entries.

## Install ML deps

```bash
# OSS
cd EEG && .venv/bin/python -m pip install -r requirements-runtime-ml.txt

# SaaS
cd EEG-SAAS/backend && .venv/bin/python -m pip install -r requirements-runtime-ml.txt
```

Disable all runtime ML: `EEG_RUNTIME_ML=0` or `EEG_AURORA_NEURAL=0`.

## Config schema (SaaS)

```yaml
- provider_id: llama_guard3
  category: prompt_injection
  platform: local          # hf | local | uri
  inference: llama_cpp     # transformers | ollama | llama_cpp
  model: llama-guard3:1b   # hub id / ollama tag / name
  model_path: /path/to.gguf   # optional for hf; required for local
  base_url: http://127.0.0.1:11434  # required for uri
  enabled: true
  score_floor: 0.55
```

| platform | model_path | base_url | typical inference |
|----------|------------|----------|-------------------|
| `hf` | optional (local HF overlay) | — | `transformers` |
| `local` | required (HF dir or GGUF) | — | `transformers` or `llama_cpp` |
| `uri` | unused | required (localhost or remote) | `ollama` |

### Env overrides

```bash
EEG_RUNTIME_ML_CONFIG=/etc/eeg/runtime_ml_models.yaml
EEG_RUNTIME_ML_<PROVIDER>_PLATFORM=uri
EEG_RUNTIME_ML_<PROVIDER>_INFERENCE=ollama
EEG_RUNTIME_ML_<PROVIDER>_MODEL=llama-guard3:1b
EEG_RUNTIME_ML_<PROVIDER>_MODEL_PATH=/path/to.gguf
EEG_RUNTIME_ML_<PROVIDER>_BASE_URL=http://127.0.0.1:11434
EEG_RUNTIME_ML_<PROVIDER>=0   # disable one provider
```

### llama.cpp notes (SaaS)

- Prefer `llama-cpp-python` in the venv, or Homebrew **`llama-cli`** (`EEG_LLAMA_CLI`, `EEG_LLAMA_NGL`, `EEG_LLAMA_TIMEOUT_SEC`).
- Ollama GGUF blobs live under `~/.ollama/models/blobs/sha256-…` (use the **model** layer digest, not the manifest JSON).

## Audit

- **SaaS API:** `GET /api/v1/runtime/ml-models`
- **SDK:** `client.runtime_ml_models()` / `runtimeMlModels()` / `RuntimeMLModels()`
- **OSS gateway packs:** `ml_engines` includes the same audit payload
- Python: `from eeg.runtime.runtime_ml_guard import runtime_ml_status, reload_runtime_ml`

## Verify models load

```bash
# OSS
cd EEG && .venv/bin/python scripts/check_runtime_ml_models.py

# SaaS
cd EEG-SAAS/backend && PYTHONPATH=. .venv/bin/python scripts/check_runtime_ml_models.py
```
