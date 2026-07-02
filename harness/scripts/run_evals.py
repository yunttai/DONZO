from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
for path in (ROOT, SRC):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))


def main() -> None:
    from donzo.config import load_scope_config
    from donzo.llm_triage.stages import run_candidate_generation, run_report_draft
    from donzo.llm_triage.tribunal import run_tribunal
    from harness.scripts.dedupe_findings import dedupe_records
    from harness.scripts.normalize_findings import normalize_record
    from harness.scripts.redact_secrets import redact_text
    from harness.scripts.validate_scope import validate_scope_file

    results: list[dict[str, object]] = []

    scope_result = validate_scope_file(Path("scope.example.yaml"))
    results.append({"case": "scope", "passed": scope_result["valid"], "detail": scope_result})

    secret_sample = "token = ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    redacted = redact_text(secret_sample)
    results.append(
        {
            "case": "secret-redaction",
            "passed": "ghp_" not in redacted and "[REDACTED]" in redacted,
        }
    )

    raw = {
        "title": "Public Swagger UI",
        "severity": "medium",
        "url": "https://api.example.com/swagger-ui/",
        "tool": "fixture",
        "candidate_type": "exposed_api_docs",
    }
    normalized = normalize_record(raw)
    results.append(
        {
            "case": "finding-normalization",
            "passed": normalized["auto_exploit"] is False
            and normalized["verification_status"] == "needs_manual_review",
        }
    )

    deduped = dedupe_records([normalized, dict(normalized)])
    results.append({"case": "finding-dedupe", "passed": len(deduped) == 1})

    config = load_scope_config(Path("scope.example.yaml"))
    candidate_stage = run_candidate_generation(
        [
            {
                "url": "https://api.example.com/api/v1/orders/123",
                "method": "GET",
                "status_code": 200,
                "content_type": "application/json",
            }
        ],
        config=config,
        llm_config=config.llm,
    )
    results.append(
        {
            "case": "candidate-generator-fail-closed",
            "passed": candidate_stage.llm_status == "failed"
            and candidate_stage.submitted_count == 1
            and candidate_stage.output is None,
        }
    )

    tribunal = run_tribunal(raw, config=config, llm_config=config.llm)
    tribunal_result = tribunal.to_dict()
    results.append(
        {
            "case": "mandatory-llm-fail-closed",
            "passed": tribunal_result["llm_required"] is True
            and tribunal_result["llm_status"] == "failed"
            and tribunal_result["verification_status"] == "llm_failed"
            and tribunal_result["include_in_final_report"] is False,
        }
    )

    report_stage = run_report_draft(
        [
            {
                "title": "Order Object ID Candidate",
                "severity": "high",
                "url": "https://api.example.com/api/v1/orders/123",
                "tool": "candidate_engine",
                "candidate_type": "bola_idor",
                "verification_status": "needs_manual_review",
            }
        ],
        config=config,
        llm_config=config.llm,
    )
    results.append(
        {
            "case": "report-writer-fail-closed",
            "passed": report_stage.llm_status == "failed"
            and report_stage.submitted_count == 1
            and report_stage.output is None,
        }
    )

    out_dir = Path("artifacts/evals")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "harness-summary.json"
    out_path.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")

    failed = [item for item in results if not item["passed"]]
    print(json.dumps({"passed": not failed, "results": results}, indent=2, sort_keys=True))
    if failed:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
