"""Tests for auditable runtime ML registry URI resolution."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from eeg.runtime.runtime_ml_registry import (
    _classify_and_resolve,
    load_registry,
    reload_registry,
)


class RegistryResolveTests(unittest.TestCase):
    def test_hub_id(self):
        uri, source = _classify_and_resolve("protectai/deberta-v3-base-prompt-injection-v2")
        self.assertEqual(source, "hub")
        self.assertEqual(uri, "protectai/deberta-v3-base-prompt-injection-v2")

    def test_hf_https_url(self):
        uri, source = _classify_and_resolve(
            "https://huggingface.co/unitary/toxic-bert/tree/main"
        )
        self.assertEqual(source, "https_hub")
        self.assertEqual(uri, "unitary/toxic-bert")

    def test_local_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "model"
            path.mkdir()
            uri, source = _classify_and_resolve(str(path))
            self.assertEqual(source, "local")
            self.assertEqual(uri, str(path.resolve()))

    def test_env_override_reloads(self):
        with patch.dict(
            os.environ,
            {"EEG_RUNTIME_ML_DEBERTA_PI_V2_MODEL": "acme/custom-pi"},
            clear=False,
        ):
            reg = reload_registry()
            model = reg.by_provider("deberta_pi_v2")
            self.assertIsNotNone(model)
            assert model is not None
            self.assertEqual(model.resolved_uri, "acme/custom-pi")
            self.assertEqual(model.source_type, "hub")
            self.assertTrue(model.override_env)
            audit = reg.audit_dict()
            self.assertEqual(audit["engine"], "runtime_ml_registry")
            self.assertGreaterEqual(audit["model_count"], 3)
        reload_registry()  # restore


class RegistryStatusTests(unittest.TestCase):
    def test_default_registry_loads(self):
        reg = load_registry(force=True)
        self.assertTrue(reg.config_path.endswith("runtime_ml_models.yaml"))
        ids = {m.provider_id for m in reg.models}
        self.assertIn("deberta_pi_v2", ids)
        self.assertIn("toxic_bert", ids)
        self.assertIn("ai4privacy_pii", ids)

    def test_oss_rejects_ollama_platform(self):
        from eeg.runtime.runtime_ml_registry import _row_to_resolved

        with self.assertRaises(ValueError):
            _row_to_resolved(
                {
                    "provider_id": "llama_guard3",
                    "platform": "uri",
                    "inference": "ollama",
                    "model": "llama-guard3:1b",
                    "base_url": "http://127.0.0.1:11434",
                },
                config_path="x.yaml",
                default_task="text-classification",
            )


if __name__ == "__main__":
    unittest.main()
