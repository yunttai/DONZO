from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9_]{30,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{30,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{16,}"),
)


def load_payload() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {"value": data}
    except json.JSONDecodeError:
        return {"text": raw}


def payload_text(payload: dict[str, Any]) -> str:
    values: list[str] = []
    for key in ("prompt", "text", "command", "cmd", "tool_input", "value"):
        value = payload.get(key)
        if isinstance(value, str):
            values.append(value)
        elif value is not None:
            values.append(json.dumps(value, ensure_ascii=False))
    return "\n".join(values)


def find_secret_patterns(text: str) -> list[str]:
    matches: list[str] = []
    for pattern in SECRET_PATTERNS:
        if pattern.search(text):
            matches.append(pattern.pattern)
    return matches


def deny(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(2)


def iter_text_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    paths: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".zip", ".gz", ".tar"}:
            continue
        if path.stat().st_size > 5_000_000:
            continue
        paths.append(path)
    return paths
