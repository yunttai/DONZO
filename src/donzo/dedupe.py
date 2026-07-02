from __future__ import annotations

from typing import Any
from urllib.parse import urlparse


def dedupe_key(record: dict[str, Any]) -> tuple[str, str, str, str]:
    if record.get("parameter_id") or record.get("endpoint_url"):
        return (
            str(record.get("endpoint_url") or "").strip().lower(),
            str(record.get("location") or "query").strip().lower(),
            "parameter",
            str(record.get("name") or "").strip().lower(),
        )
    target = str(record.get("target") or record.get("url") or record.get("asset") or "")
    parsed = urlparse(target)
    path = parsed.path.rstrip("/") or "/"
    if record.get("asset") and not parsed.netloc:
        return (
            str(record.get("asset") or "").strip().lower(),
            str(record.get("type") or "").strip().lower(),
            "asset",
            "",
        )
    return (
        parsed.netloc.lower(),
        path.lower(),
        str(record.get("candidate_type") or "").upper(),
        str(record.get("title") or record.get("candidate_id") or "").strip().lower(),
    )


def dedupe_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str]] = set()
    output: list[dict[str, Any]] = []
    for record in records:
        key = dedupe_key(record)
        if key in seen:
            continue
        seen.add(key)
        output.append(record)
    return output
