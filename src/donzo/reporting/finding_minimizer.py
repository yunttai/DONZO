from __future__ import annotations

from typing import Any

from donzo.models import stable_id
from donzo.traffic.redactor import redact_value


def build_confirmed_findings_from_fuzz_verdicts(
    verdicts: list[dict[str, Any]],
    *,
    fuzz_plans: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    plan_index = {str(item.get("fuzz_id") or ""): item for item in fuzz_plans or []}
    findings: list[dict[str, Any]] = []
    for verdict in verdicts:
        if str(verdict.get("verdict") or "") != "confirmed":
            continue
        plan = plan_index.get(str(verdict.get("fuzz_id") or ""), {})
        vulnerability = str(verdict.get("vulnerability_class") or "Vulnerability")
        target = str(plan.get("path_template") or verdict.get("endpoint_id") or "")
        evidence = redact_value(
            {
                "oracle": verdict.get("oracle"),
                "evidence": verdict.get("evidence") or [],
                "target_parameter": plan.get("target_parameter"),
            }
        )
        findings.append(
            {
                "finding_id": stable_id("fuzz_confirmed_finding", verdict.get("fuzz_id"), target),
                "title": f"{vulnerability} confirmed by offline oracle",
                "severity": verdict.get("severity_hint") or "medium",
                "confidence": verdict.get("confidence", 0.0),
                "target": target,
                "candidate_type": vulnerability,
                "source": ["fuzz_oracle_engine"],
                "evidence": evidence,
                "verification_status": "confirmed_by_offline_oracle_needs_human_review",
                "auto_exploit": False,
                "manual_verification": [
                    "Review redacted baseline, control, mutation, and read-back evidence.",
                    "Confirm the target and test data are in authorized scope.",
                    "Do not submit without human validation of impact and program policy.",
                ],
            }
        )
    return findings
