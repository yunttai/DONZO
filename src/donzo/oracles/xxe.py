from __future__ import annotations

from typing import Any

from donzo.oast.interaction_model import CLIENT_SOURCE_CLASSES, normalize_oast_interaction
from donzo.oracles.verdict import coerce_bool, oracle_verdict


def evaluate_xxe_external_entity_oast(
    probes: list[dict[str, Any]],
    interactions: list[dict[str, Any]],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if any(
        coerce_bool(item.get("dos_payload") or item.get("sensitive_file_attempted"))
        for item in probes
    ):
        return oracle_verdict(
            "blocked_by_safety_policy",
            1.0,
            "XXE DoS and sensitive local file reads are blocked by policy",
        )
    tokens = {str(item.get("oast_token") or item.get("token") or "") for item in probes}
    tokens.discard("")
    matches = [
        item
        for item in [normalize_oast_interaction(item) for item in interactions]
        if item.get("token") in tokens and not item.get("control_interaction")
    ]
    server = [
        item
        for item in matches
        if item.get("source_class") not in CLIENT_SOURCE_CLASSES and not item.get("browser_loaded")
    ]
    if server:
        return oracle_verdict(
            "confirmed",
            0.86,
            "external entity OAST token produced a server-side callback",
            "high",
            evidence=["XXE token matched OAST interaction", "source classified server-side"],
        )
    if any(item.get("parser_error") for item in probes):
        return oracle_verdict(
            "needs_more_evidence",
            0.42,
            "XML parser error alone does not confirm XXE",
            needs_more_evidence=["safe OAST external entity interaction"],
        )
    return oracle_verdict("needs_more_evidence", 0.35, "no XXE OAST evidence was observed")
