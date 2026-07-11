"""EEG runtime gateway — in-path LLM request inspection and blocking."""

from eeg.gateway.proxy import GatewayBlockedError, proxy_chat_completion
from eeg.gateway.vendor_executor import proxy_chat_via_plan, stream_chat_via_plan

__all__ = [
    "GatewayBlockedError",
    "proxy_chat_completion",
    "proxy_chat_via_plan",
    "stream_chat_via_plan",
]
