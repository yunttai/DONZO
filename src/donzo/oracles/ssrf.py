from __future__ import annotations

from typing import Any

from donzo.oast.interaction_model import CLIENT_SOURCE_CLASSES, normalize_oast_interaction
from donzo.oracles.verdict import oracle_verdict


def evaluate_ssrf_oast_callback(
    probes: list[dict[str, Any]],
    interactions: list[dict[str, Any]],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    tokens = {str(item.get("oast_token") or item.get("token") or "") for item in probes}
    tokens.discard("")
    normalized = [normalize_oast_interaction(item) for item in interactions]
    matching = [item for item in normalized if str(item.get("token") or "") in tokens]
    control = [item for item in matching if item.get("control_interaction")]
    if control:
        return oracle_verdict(
            "false_positive",
            0.78,
            "OAST interaction was also observed for a control request",
            false_positive_reasons=["control callback interaction"],
        )
    if not matching:
        return oracle_verdict(
            "needs_more_evidence",
            0.35,
            "no matching OAST interaction was observed for the SSRF token",
            needs_more_evidence=["matched DNS/HTTP OAST interaction"],
        )
    client_side = [
        item
        for item in matching
        if item.get("source_class") in CLIENT_SOURCE_CLASSES or item.get("browser_loaded")
    ]
    server_side = [
        item
        for item in matching
        if item.get("source_class") not in CLIENT_SOURCE_CLASSES and not item.get("browser_loaded")
    ]
    if server_side:
        return oracle_verdict(
            "confirmed",
            0.92,
            "unique OAST token received a server-side interaction and controls stayed quiet",
            "medium",
            evidence=[
                "token matched original request",
                "source classified server-side",
                "no control interaction",
            ],
        )
    return oracle_verdict(
        "false_positive",
        0.72,
        "matching interaction appears to be browser, client, proxy, or link-preview activity",
        false_positive_reasons=[
            str(item.get("source_class") or "client_side") for item in client_side
        ],
    )
