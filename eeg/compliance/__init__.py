"""eeg.compliance — regulatory control mapping and real-time audit (OSS)."""

from eeg.compliance.framework_evaluate import evaluate
from eeg.compliance.posture_cards import build_posture_dashboard
from eeg.compliance.realtime_audit import run_realtime_compliance_audit

__all__ = [
    "evaluate",
    "build_posture_dashboard",
    "run_realtime_compliance_audit",
]
