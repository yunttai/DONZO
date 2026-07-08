from __future__ import annotations

from statistics import median
from typing import Any

from donzo.oast.interaction_model import CLIENT_SOURCE_CLASSES, normalize_oast_interaction
from donzo.oracles.verdict import oracle_verdict


def evaluate_command_injection_safe_timing_oast(
    baseline: list[dict[str, Any]],
    controls: list[dict[str, Any]],
    probes: list[dict[str, Any]],
    interactions: list[dict[str, Any]] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    interactions = interactions or []
    tokens = {str(item.get("oast_token") or item.get("token") or "") for item in probes}
    tokens.discard("")
    server_interactions = [
        item
        for item in [normalize_oast_interaction(item) for item in interactions]
        if item.get("token") in tokens
        and item.get("source_class") not in CLIENT_SOURCE_CLASSES
        and not item.get("browser_loaded")
        and not item.get("control_interaction")
    ]
    if server_interactions:
        return oracle_verdict(
            "confirmed",
            0.88,
            "safe OAST token callback was tied to the command-sink candidate",
            "high",
            evidence=["OAST token matched", "source classified server-side"],
        )
    base_times = timings(baseline)
    control_times = timings(controls)
    probe_times = timings(probes)
    if len(base_times) >= 2 and len(probe_times) >= 2:
        threshold = float((context or {}).get("minimum_delay_ms") or 750)
        base = max(median(base_times), median(control_times) if control_times else 0.0)
        if median(probe_times) - base >= threshold:
            return oracle_verdict(
                "confirmed",
                0.82,
                "safe timing marker repeatedly delayed only the mutation path",
                "high",
                evidence=[
                    "baseline timing normal",
                    "control timing normal",
                    "mutation timing delayed",
                ],
            )
    return oracle_verdict(
        "needs_more_evidence",
        0.4,
        "command injection oracle needs isolated safe timing or OAST evidence",
        needs_more_evidence=["safe timing differential or server-side OAST callback"],
    )


def timings(records: list[dict[str, Any]]) -> list[float]:
    return [
        float(item.get("timing_ms")) for item in records if item.get("timing_ms") not in (None, "")
    ]
