"""Shared multimodal helpers for enterprise chat vendors."""
from __future__ import annotations

import base64
import re
from typing import Any

_DATA_URL_RE = re.compile(
    r"^data:(?P<media>[\w.+/-]+)?(?:;[^,]*)?;base64,(?P<data>.+)$",
    re.DOTALL | re.IGNORECASE,
)


def parse_data_url(url: str) -> tuple[str, bytes] | None:
    """Return (media_type, raw_bytes) for a data: URL, else None."""
    if not url or not isinstance(url, str):
        return None
    raw = url.strip()
    if not raw.startswith("data:"):
        return None
    m = _DATA_URL_RE.match(raw)
    if not m:
        # Fallback split for odd encodings
        try:
            header, b64 = raw.split(",", 1)
        except ValueError:
            return None
        media = "application/octet-stream"
        if header.startswith("data:"):
            media = header[5:].split(";")[0] or media
        try:
            return media, base64.b64decode(b64)
        except Exception:  # noqa: BLE001
            return None
    media = m.group("media") or "application/octet-stream"
    try:
        return media, base64.b64decode(m.group("data"))
    except Exception:  # noqa: BLE001
        return None


def image_url_to_bedrock_block(item: dict[str, Any]) -> dict[str, Any] | None:
    """Map OpenAI image_url content part → Bedrock Converse image block."""
    image_url = item.get("image_url") if isinstance(item.get("image_url"), dict) else {}
    url = str(image_url.get("url") or "").strip()
    if not url:
        return None
    parsed = parse_data_url(url)
    if not parsed:
        # Remote URLs are not fetched (SSRF); skip silently for Converse.
        return None
    media, data = parsed
    fmt = _bedrock_image_format(media)
    if not fmt:
        return None
    return {"image": {"format": fmt, "source": {"bytes": data}}}


def image_url_to_vertex_part(item: dict[str, Any]) -> dict[str, Any] | None:
    """Map OpenAI image_url content part → Vertex Gemini inlineData part."""
    image_url = item.get("image_url") if isinstance(item.get("image_url"), dict) else {}
    url = str(image_url.get("url") or "").strip()
    if not url:
        return None
    parsed = parse_data_url(url)
    if parsed:
        media, data = parsed
        return {
            "inlineData": {
                "mimeType": media or "image/png",
                "data": base64.b64encode(data).decode("ascii"),
            }
        }
    # Vertex accepts fileData with gs:// or https:// for some models; pass through https.
    if url.startswith("gs://") or url.startswith("https://"):
        mime = "image/jpeg"
        lower = url.lower()
        if lower.endswith(".png"):
            mime = "image/png"
        elif lower.endswith(".webp"):
            mime = "image/webp"
        return {"fileData": {"mimeType": mime, "fileUri": url}}
    return None


def _bedrock_image_format(media: str) -> str | None:
    media = (media or "").lower().strip()
    mapping = {
        "image/png": "png",
        "image/jpeg": "jpeg",
        "image/jpg": "jpeg",
        "image/gif": "gif",
        "image/webp": "webp",
    }
    return mapping.get(media)


def b64_audio_response(*, audio_bytes: bytes, content_type: str = "audio/mpeg") -> dict[str, Any]:
    """Wrap binary TTS audio in a JSON envelope for gateway JSON responses."""
    return {
        "object": "audio.speech",
        "content_type": content_type,
        "data": base64.b64encode(audio_bytes).decode("ascii"),
    }
