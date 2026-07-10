from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from donzo.config import load_scope_config

ID_IN_PATH_RE = re.compile(
    r"/(?:[0-9]{1,18}|[0-9a-fA-F]{8,}(?:-[0-9a-fA-F]{4,}){2,})"
)
DEFAULT_BLOCKED_WORDS = {
    "admin",
    "approval",
    "refusal",
    "delete",
    "remove",
    "warn",
    "status",
    "submit-action",
    "create",
    "update",
    "password",
    "logout",
}
SENSITIVE_FIELD_NAMES = {
    "email",
    "phone",
    "phonenumber",
    "studentnumber",
    "name",
    "address",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Replay low-rate baseline GET object URLs with a comparison actor "
            "session and write redacted cross-actor observations."
        )
    )
    parser.add_argument("-c", "--config", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--baseline-traffic", type=Path, required=True)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--actor", default="user_B")
    parser.add_argument("--profile-dir", type=Path)
    parser.add_argument("--max-requests", type=int, default=20)
    parser.add_argument("--delay-ms", type=int, default=350)
    parser.add_argument("--allow-admin-readonly", action="store_true")
    return parser.parse_args()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def target_origin(target: str) -> str:
    parsed = urlparse(target)
    return f"{parsed.scheme}://{parsed.netloc}"


def candidate_url(target: str, path: str) -> str:
    return urljoin(target_origin(target).rstrip("/") + "/", path.lstrip("/"))


def is_candidate_path(path: str, *, allow_admin_readonly: bool) -> bool:
    lowered = path.lower()
    blocked = set(DEFAULT_BLOCKED_WORDS)
    if allow_admin_readonly:
        blocked.discard("admin")
    if any(word in lowered for word in blocked):
        return False
    return "/api/" in lowered and ID_IN_PATH_RE.search(path) is not None


def extract_candidate_paths(
    records: list[dict[str, Any]],
    *,
    allow_admin_readonly: bool,
    max_requests: int,
) -> list[str]:
    paths: list[str] = []
    for record in records:
        request = record.get("request") or {}
        response = record.get("response") or {}
        path = str(request.get("path") or "")
        if request.get("method") != "GET":
            continue
        if response.get("status") != 200:
            continue
        if not is_candidate_path(path, allow_admin_readonly=allow_admin_readonly):
            continue
        if path not in paths:
            paths.append(path)
        if len(paths) >= max_requests:
            break
    return paths


def digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()[:16]


def parse_json_body(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return None


def collect_schema_fields(value: Any) -> tuple[list[str], list[str], list[str]]:
    keys: set[str] = set()
    sensitive_fields: set[str] = set()
    id_fields: set[str] = set()

    def walk(item: Any, path: str = "") -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                key_text = str(key)
                next_path = f"{path}.{key_text}" if path else key_text
                lowered = key_text.lower()
                keys.add(next_path)
                if lowered in SENSITIVE_FIELD_NAMES:
                    sensitive_fields.add(next_path)
                if lowered.endswith("id") or lowered in {"userid", "groupid", "studygroupid"}:
                    id_fields.add(next_path)
                walk(child, next_path)
        elif isinstance(item, list):
            for child in item[:10]:
                walk(child, f"{path}[]")

    walk(value)
    return sorted(keys), sorted(sensitive_fields), sorted(id_fields)


def main() -> int:
    args = parse_args()
    config = load_scope_config(args.config)
    target_decision = config.scope.decide(args.target)
    if not target_decision.allowed:
        print(
            json.dumps(
                {
                    "executed": False,
                    "error": "target_out_of_scope",
                    "reasons": target_decision.reasons,
                },
                ensure_ascii=False,
            )
        )
        return 2

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(json.dumps({"executed": False, "error": "playwright_not_installed"}))
        return 2

    baseline_records = read_jsonl(args.baseline_traffic)
    paths = extract_candidate_paths(
        baseline_records,
        allow_admin_readonly=args.allow_admin_readonly,
        max_requests=max(args.max_requests, 0),
    )
    profile_dir = args.profile_dir or (args.output.parent / f".{args.actor}-browser-profile")
    args.output.parent.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    with sync_playwright() as playwright:
        context = playwright.chromium.launch_persistent_context(
            user_data_dir=str(profile_dir),
            headless=False,
            ignore_https_errors=True,
            viewport={"width": 1440, "height": 1000},
        )
        page = context.pages[0] if context.pages else context.new_page()
        page.goto(args.target, wait_until="domcontentloaded", timeout=20000)
        input(
            "Log in as the comparison actor in the opened browser, then press Enter here..."
        )
        for path in paths:
            url = candidate_url(args.target, path)
            decision = config.scope.decide(url)
            record: dict[str, Any] = {
                "actor": args.actor,
                "method": "GET",
                "url_path": path,
                "scope_allowed": decision.allowed,
                "scope_reasons": decision.reasons,
                "raw_body_stored": False,
            }
            if not decision.allowed:
                results.append(record)
                continue

            response = page.evaluate(
                """async (url) => {
                    const r = await fetch(url, {
                        method: "GET",
                        credentials: "include",
                        cache: "no-store"
                    });
                    const text = await r.text();
                    return {
                        status: r.status,
                        contentType: r.headers.get("content-type") || "",
                        bodyLength: text.length,
                        text
                    };
                }""",
                url,
            )
            body = parse_json_body(str(response.get("text") or ""))
            schema_keys, sensitive_fields, id_fields = (
                collect_schema_fields(body) if body is not None else ([], [], [])
            )
            status = response.get("status")
            record.update(
                {
                    "status": status,
                    "content_type": response.get("contentType"),
                    "body_length": response.get("bodyLength"),
                    "json_body": body is not None,
                    "body_digest": digest(body if body is not None else response.get("text", "")),
                    "schema_key_count": len(schema_keys),
                    "sensitive_field_paths": sensitive_fields,
                    "id_field_paths": id_fields,
                    "verdict": (
                        "needs_review_200_cross_actor"
                        if status == 200 and body is not None
                        else "denied_or_not_json"
                    ),
                }
            )
            results.append(record)
            time.sleep(max(args.delay_ms, 0) / 1000)
        context.close()

    args.output.write_text(
        "\n".join(json.dumps(item, ensure_ascii=False, sort_keys=True) for item in results)
        + ("\n" if results else ""),
        encoding="utf-8",
    )
    status_counts: dict[str, int] = {}
    for item in results:
        status = str(item.get("status", "scope_blocked"))
        status_counts[status] = status_counts.get(status, 0) + 1
    print(
        json.dumps(
            {
                "executed": True,
                "actor": args.actor,
                "output": str(args.output),
                "candidate_request_count": len(paths),
                "executed_count": sum(1 for item in results if item.get("status") is not None),
                "status_counts": status_counts,
                "needs_review_200_cross_actor": sum(
                    1
                    for item in results
                    if item.get("verdict") == "needs_review_200_cross_actor"
                ),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
