from __future__ import annotations

from typing import Any

from donzo.oracles.verdict import coerce_bool, oracle_verdict


def evaluate_ssti_server_side_evaluation(
    controls: list[dict[str, Any]],
    probes: list[dict[str, Any]],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evaluated = [item for item in probes if probe_evaluated(item)]
    control_evaluated = [item for item in controls if probe_evaluated(item)]
    if control_evaluated:
        return oracle_verdict(
            "false_positive",
            0.75,
            "literal/control expression was also evaluated",
            false_positive_reasons=["client-side rendering or non-isolated evaluation"],
        )
    if evaluated and all(client_side_excluded(item) for item in evaluated):
        return oracle_verdict(
            "confirmed",
            0.9,
            "template expression evaluated in raw server response or generated artifact",
            "high",
            evidence=[
                "server-side evaluation observed",
                "literal control not evaluated",
                "client-side rendering excluded",
            ],
        )
    if evaluated:
        return oracle_verdict(
            "probable",
            0.64,
            "template-like expression evaluated but client-side rendering has not been excluded",
            "medium",
            needs_more_evidence=["raw HTTP response or generated artifact evidence"],
        )
    reflected = any(coerce_bool(item.get("reflected")) for item in probes)
    if reflected:
        return oracle_verdict(
            "needs_more_evidence",
            0.4,
            "input is reflected but server-side template evaluation is not proven",
            needs_more_evidence=["server-side evaluation result"],
        )
    return oracle_verdict(
        "needs_more_evidence",
        0.3,
        "no SSTI evaluation signal was observed",
        needs_more_evidence=["raw response evaluation evidence"],
    )


def probe_evaluated(record: dict[str, Any]) -> bool:
    if coerce_bool(record.get("evaluated") or record.get("server_side_evaluated")):
        return True
    expected = record.get("expected_evaluation")
    observed = record.get("observed_value") or record.get("raw_response_contains")
    return expected not in (None, "") and observed == expected


def client_side_excluded(record: dict[str, Any]) -> bool:
    return coerce_bool(
        record.get("client_side_excluded")
        or record.get("raw_response_observed")
        or record.get("generated_artifact_observed")
    )
