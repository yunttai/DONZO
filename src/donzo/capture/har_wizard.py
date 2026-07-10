from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from donzo.config import ScopeConfig
from donzo.storage.jsonl import write_jsonl
from donzo.traffic.har_ingest import ingest_har_files
from donzo.traffic.redactor import redact_headers, redact_string, redact_value


def build_flow_manifest_record(
    *,
    target: str,
    actor: str,
    role: str = "",
    tenant: str = "",
    state: str = "unknown",
    flow: str = "manual_flow",
    label: str = "",
    har_path: Path | None = None,
    traffic_path: Path | None = None,
) -> dict[str, Any]:
    return {
        "target": target,
        "actor": actor,
        "role": role,
        "tenant": tenant,
        "state": state,
        "flow": flow,
        "label": label or flow,
        "har_path": str(har_path) if har_path else "",
        "traffic_path": str(traffic_path) if traffic_path else "",
        "credential_policy": (
            "manual browser login only; raw credentials are not requested or persisted by DONZO"
        ),
        "redacted": True,
    }


def write_har_capture_artifacts(
    *,
    har_path: Path,
    output_dir: Path,
    config: ScopeConfig,
    target: str,
    actor: str,
    role: str = "",
    tenant: str = "",
    state: str = "unknown",
    flow: str = "manual_flow",
    label: str = "",
    source: str = "har_capture_wizard",
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    redacted_har_path = output_dir / "traffic.har"
    redacted_document = redact_har_document(json.loads(har_path.read_text(encoding="utf-8")))
    redacted_har_path.write_text(
        json.dumps(redacted_document, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    traffic, request_schemas, response_schemas, removed = ingest_har_files(
        [redacted_har_path],
        config=config,
        actor=actor,
        role=role,
        tenant=tenant,
        state=state,
        flow=flow,
        label=label,
        source=source,
    )
    traffic_path = output_dir / "traffic.jsonl"
    manifest_path = output_dir / "flow-manifest.jsonl"
    write_jsonl(traffic_path, traffic)
    write_jsonl(output_dir / "request-schemas.jsonl", request_schemas)
    write_jsonl(output_dir / "response-schemas.jsonl", response_schemas)
    manifest = [
        build_flow_manifest_record(
            target=target,
            actor=actor,
            role=role,
            tenant=tenant,
            state=state,
            flow=flow,
            label=label,
            har_path=redacted_har_path,
            traffic_path=traffic_path,
        )
    ]
    write_jsonl(manifest_path, manifest)
    return {
        "captured": True,
        "redacted": True,
        "traffic_count": len(traffic),
        "request_schema_count": len(request_schemas),
        "response_schema_count": len(response_schemas),
        "removed_count": len(removed),
        "flow_manifest": str(manifest_path),
        "traffic": str(traffic_path),
        "har": str(redacted_har_path),
    }


def capture_har_session(
    *,
    target: str,
    output_dir: Path,
    config: ScopeConfig,
    actor: str,
    role: str = "",
    tenant: str = "",
    state: str = "unknown",
    flow: str = "manual_flow",
    label: str = "",
    headed: bool = True,
) -> dict[str, Any]:
    decision = config.scope.decide(target)
    if not decision.allowed:
        return {
            "captured": False,
            "error": "target_out_of_scope",
            "target": target,
            "reasons": decision.reasons,
        }
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {
            "captured": False,
            "error": "playwright_not_installed",
            "hint": "Install playwright and browser dependencies, then retry.",
        }
    output_dir.mkdir(parents=True, exist_ok=True)
    temp_har = output_dir / ".donzo-capture-raw.har"
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=not headed)
            context = browser.new_context(
                record_har_path=str(temp_har),
                record_har_content="embed",
                ignore_https_errors=True,
            )
            page = context.new_page()
            page.goto(target, wait_until="domcontentloaded")
            input("Complete the authorized flow in the opened browser, then press Enter here...")
            context.close()
            browser.close()
        return write_har_capture_artifacts(
            har_path=temp_har,
            output_dir=output_dir,
            config=config,
            target=target,
            actor=actor,
            role=role,
            tenant=tenant,
            state=state,
            flow=flow,
            label=label,
        )
    finally:
        if temp_har.exists():
            temp_har.unlink()


def redact_har_document(document: Any) -> Any:
    if isinstance(document, list):
        return [redact_har_document(item) for item in document]
    if not isinstance(document, dict):
        return redact_value(document)
    output: dict[str, Any] = {}
    for key, value in document.items():
        lowered = str(key).lower()
        if lowered == "headers" and isinstance(value, list):
            header_dict = {
                str(item.get("name") or ""): str(item.get("value") or "")
                for item in value
                if isinstance(item, dict)
            }
            redacted = redact_headers(header_dict)
            output[key] = [
                {"name": name, "value": item_value} for name, item_value in redacted.items()
            ]
        elif lowered in {"cookies", "querystring"} and isinstance(value, list):
            output[key] = [
                {
                    **{
                        item_key: redact_string(str(item_value))
                        for item_key, item_value in item.items()
                    },
                    "value": "[REDACTED]"
                    if lowered == "cookies"
                    else redact_string(str(item.get("value") or "")),
                }
                for item in value
                if isinstance(item, dict)
            ]
        elif lowered == "postdata" and isinstance(value, dict):
            post_data = dict(value)
            if "text" in post_data:
                post_data["text"] = redact_string(str(post_data.get("text") or ""))
            if "params" in post_data:
                post_data["params"] = redact_har_document(post_data["params"])
            output[key] = post_data
        elif lowered in {"text", "value"}:
            output[key] = redact_string(str(value))
        else:
            output[key] = redact_har_document(value)
    return output
