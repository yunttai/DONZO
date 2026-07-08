from __future__ import annotations

from typing import Any

from donzo.oracles.verdict import coerce_bool, oracle_verdict


def evaluate_xss_browser_execution(
    controls: list[dict[str, Any]],
    probes: list[dict[str, Any]],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if any(coerce_bool(item.get("browser_event_executed")) for item in controls):
        return oracle_verdict(
            "false_positive",
            0.76,
            "control marker also triggered browser execution",
            false_positive_reasons=["instrumentation or page state not isolated"],
        )
    if any(
        coerce_bool(item.get("browser_event_executed")) and coerce_bool(item.get("marker_matched"))
        for item in probes
    ):
        return oracle_verdict(
            "confirmed",
            0.9,
            "instrumented browser observed execution of the unique marker",
            "medium",
            evidence=["unique marker executed in browser", "control did not execute"],
        )
    if any(coerce_bool(item.get("reflected")) for item in probes):
        return oracle_verdict(
            "probable",
            0.55,
            "marker was reflected but browser execution was not observed",
            "low",
            needs_more_evidence=["instrumented browser execution evidence"],
        )
    return oracle_verdict("needs_more_evidence", 0.3, "no XSS execution signal was observed")
