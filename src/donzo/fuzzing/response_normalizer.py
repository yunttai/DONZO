from __future__ import annotations

import hashlib
import json
import re
from difflib import SequenceMatcher
from typing import Any

DYNAMIC_KEY_PATTERNS = (
    "csrf",
    "nonce",
    "request_id",
    "requestid",
    "trace_id",
    "traceid",
    "span_id",
    "spanid",
    "timestamp",
    "created_at",
    "updated_at",
    "expires_at",
    "session",
)

UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.I,
)
ISO_TIME_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b")
LONG_HEX_RE = re.compile(r"\b[0-9a-f]{24,}\b", re.I)


def normalize_response_body(value: Any) -> Any:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            try:
                return normalize_response_body(json.loads(stripped))
            except json.JSONDecodeError:
                return normalize_text(stripped)
        return ""
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if is_dynamic_key(key_text):
                normalized[key_text] = "[DYNAMIC]"
            else:
                normalized[key_text] = normalize_response_body(item)
        return {key: normalized[key] for key in sorted(normalized)}
    if isinstance(value, list):
        return [normalize_response_body(item) for item in value]
    return value


def normalize_text(value: str) -> str:
    value = UUID_RE.sub("[UUID]", value)
    value = ISO_TIME_RE.sub("[TIMESTAMP]", value)
    value = LONG_HEX_RE.sub("[HEX]", value)
    return value


def is_dynamic_key(key: str) -> bool:
    lowered = re.sub(r"[^a-z0-9_]+", "_", key.lower())
    return any(pattern in lowered for pattern in DYNAMIC_KEY_PATTERNS)


def normalized_response_text(value: Any) -> str:
    normalized = normalize_response_body(value)
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def normalized_response_hash(value: Any) -> str:
    text = normalized_response_text(value)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def response_similarity(left: Any, right: Any) -> float:
    left_text = normalized_response_text(left)
    right_text = normalized_response_text(right)
    if left_text == right_text:
        return 1.0
    return round(SequenceMatcher(a=left_text, b=right_text).ratio(), 4)


def result_body(record: dict[str, Any]) -> Any:
    for key in ("normalized_body", "body", "response_body", "body_observation"):
        if key in record:
            return record[key]
    return ""


def result_hash(record: dict[str, Any]) -> str:
    return str(
        record.get("normalized_response_hash") or normalized_response_hash(result_body(record))
    )
