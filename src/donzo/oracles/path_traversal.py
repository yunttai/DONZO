from __future__ import annotations

from typing import Any

from donzo.oracles.verdict import coerce_bool, oracle_verdict


def evaluate_path_traversal_known_safe_file(
    controls: list[dict[str, Any]],
    probes: list[dict[str, Any]],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if any(coerce_bool(item.get("sensitive_file_attempted")) for item in probes):
        return oracle_verdict(
            "blocked_by_safety_policy",
            1.0,
            "sensitive local file read attempts are blocked by policy",
            false_positive_reasons=["unsafe probe"],
        )
    if any(coerce_bool(item.get("known_safe_file_observed")) for item in controls):
        return oracle_verdict(
            "false_positive",
            0.78,
            "control request also observed the known safe file marker",
            false_positive_reasons=["control can read the fixture normally"],
        )
    if any(coerce_bool(item.get("known_safe_file_observed")) for item in probes):
        return oracle_verdict(
            "confirmed",
            0.86,
            "boundary mutation exposed a known safe fixture file that controls could not access",
            "medium",
            evidence=["known safe file marker observed", "control did not observe marker"],
        )
    return oracle_verdict(
        "needs_more_evidence",
        0.35,
        "path traversal oracle requires a known safe file marker or boundary proof",
        needs_more_evidence=["known safe fixture evidence"],
    )
