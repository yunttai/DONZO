from __future__ import annotations

from typing import Any

from donzo.models import stable_id

CLIENT_SOURCE_CLASSES = {
    "browser",
    "client",
    "proxy",
    "link_preview",
    "scanner",
    "unknown",
    "unknown_client",
}


def normalize_oast_interaction(record: dict[str, Any]) -> dict[str, Any]:
    token = str(record.get("token") or record.get("oast_token") or "")
    source_class = str(record.get("source_class") or "").strip().lower()
    browser_loaded = record.get("browser_loaded")
    if not source_class:
        source_class = infer_source_class(record)
    return {
        "interaction_id": str(
            record.get("interaction_id") or stable_id("oast_interaction", token, record)
        ),
        "token": token,
        "protocol": str(record.get("protocol") or "unknown").lower(),
        "source_ip": record.get("source_ip"),
        "user_agent": record.get("user_agent"),
        "timestamp": record.get("timestamp"),
        "matched_request_id": record.get("matched_request_id") or record.get("request_id"),
        "fuzz_id": record.get("fuzz_id"),
        "endpoint_id": record.get("endpoint_id"),
        "parameter": record.get("parameter"),
        "source_class": source_class,
        "browser_loaded": bool(browser_loaded)
        if browser_loaded is not None
        else source_class == "browser",
        "control_interaction": bool(record.get("control_interaction")),
    }


def match_oast_interactions(
    requests: list[dict[str, Any]],
    interactions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    token_index: dict[str, list[dict[str, Any]]] = {}
    for interaction in interactions:
        normalized = normalize_oast_interaction(interaction)
        token_index.setdefault(str(normalized.get("token") or ""), []).append(normalized)
    matches: list[dict[str, Any]] = []
    for request in requests:
        token = str(request.get("oast_token") or request.get("token") or "")
        if not token:
            continue
        for interaction in token_index.get(token, []):
            matches.append(
                {
                    "match_id": stable_id(
                        "oast_match", request.get("request_id"), interaction.get("interaction_id")
                    ),
                    "request_id": request.get("request_id"),
                    "fuzz_id": request.get("fuzz_id"),
                    "endpoint_id": request.get("endpoint_id"),
                    "parameter": request.get("parameter") or request.get("target_parameter"),
                    "interaction_id": interaction.get("interaction_id"),
                    "token": token,
                    "server_side_candidate": interaction.get("source_class")
                    not in CLIENT_SOURCE_CLASSES
                    and not interaction.get("browser_loaded"),
                    "interaction": interaction,
                }
            )
    return matches


def infer_source_class(record: dict[str, Any]) -> str:
    if record.get("server_side") is True:
        return "server_side"
    user_agent = str(record.get("user_agent") or "").lower()
    if any(marker in user_agent for marker in ("mozilla", "chrome", "safari", "firefox")):
        return "browser"
    if any(marker in user_agent for marker in ("slackbot", "discordbot", "facebookexternalhit")):
        return "link_preview"
    if any(marker in user_agent for marker in ("waf", "proxy", "scanner")):
        return "proxy"
    return "unknown_client"
