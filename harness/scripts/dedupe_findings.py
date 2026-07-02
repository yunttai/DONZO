from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def dedupe_key(record: dict[str, Any]) -> tuple[str, str, str, str]:
    parsed = urlparse(str(record.get("target", "")))
    normalized_path = parsed.path.rstrip("/") or "/"
    return (
        parsed.netloc.lower(),
        normalized_path.lower(),
        str(record.get("candidate_type", "")).upper(),
        str(record.get("title", "")).strip().lower(),
    )


def dedupe_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for record in records:
        key = dedupe_key(record)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(record)
    return deduped


def load_jsonl(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            item = json.loads(line)
            if isinstance(item, dict):
                records.append(item)
    return records


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    text = args.input.read_text(encoding="utf-8") if args.input else sys.stdin.read()
    output = "".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
        for record in dedupe_records(load_jsonl(text))
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
