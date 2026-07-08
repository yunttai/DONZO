from __future__ import annotations

from typing import Any

from donzo.models import stable_id

VULNERABILITY_CLASSES = {
    "SQLI",
    "SSRF",
    "SSTI",
    "BOLA",
    "BFLA",
    "XSS",
    "COMMAND_INJECTION",
    "PATH_TRAVERSAL",
    "XXE",
    "FILE_UPLOAD",
    "MASS_ASSIGNMENT",
    "EDE",
    "BUSINESS_LOGIC",
}

FUZZ_VERDICT_STATUSES = {
    "confirmed",
    "probable",
    "needs_more_evidence",
    "expected_behavior",
    "false_positive",
    "out_of_scope",
    "blocked_by_safety_policy",
}

ARTIFACT_PATHS = {
    "fuzz_plan": "planning/fuzz-plan.jsonl",
    "safe_probes": "planning/safe-probes.jsonl",
    "probe_plan": "planning/probe-plan.jsonl",
    "oracle_templates": "planning/oracle-templates.jsonl",
    "baseline_results": "execution/baseline-results.jsonl",
    "fuzz_results": "execution/fuzz-results.jsonl",
    "probe_results": "execution/probe-results.jsonl",
    "oast_interactions": "execution/oast-interactions.jsonl",
    "state_readback_results": "execution/state-readback-results.jsonl",
    "readback_results": "execution/readback-results.jsonl",
    "oracle_verdicts": "analysis/oracle-verdicts.jsonl",
    "false_positive_analysis": "analysis/false-positive-analysis.jsonl",
    "confirmed_findings": "reports/confirmed-findings.jsonl",
    "regression_cases": "reports/regression-cases.jsonl",
}


def fuzz_candidate_id(endpoint_id: str, vulnerability_class: str, parameter: dict[str, Any]) -> str:
    return stable_id(
        "fuzz_candidate",
        endpoint_id,
        vulnerability_class,
        parameter.get("location"),
        parameter.get("path") or parameter.get("name"),
    )


def fuzz_plan_id(candidate: dict[str, Any]) -> str:
    return stable_id(
        "fuzz_plan",
        candidate.get("endpoint_id"),
        candidate.get("vulnerability_class"),
        candidate.get("target_parameter"),
    )


def compact_record(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if value not in (None, "", [], {})}
