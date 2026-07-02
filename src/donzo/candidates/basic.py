from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from donzo.models import Candidate


def build_basic_candidates(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for endpoint in endpoints:
        candidates.extend(candidates_for_endpoint(endpoint))
    return candidates


def candidates_for_endpoint(endpoint: dict[str, Any]) -> list[dict[str, Any]]:
    url = str(endpoint.get("url") or "")
    method = str(endpoint.get("method") or "GET").upper()
    hints = {str(item) for item in endpoint.get("risk_hints") or []}
    params = {str(item).lower() for item in endpoint.get("params") or []}
    output: list[dict[str, Any]] = []

    if "api_docs" in hints:
        output.append(
            Candidate(
                candidate_type="EXPOSED_API_DOCS",
                target=url,
                severity="medium",
                confidence=0.65,
                source=["deterministic_candidate_engine"],
                reason=["API documentation path pattern is present"],
                manual_verification=[
                    "Confirm whether the documentation is intentionally public.",
                    "Review only visible docs for sensitive internal paths or examples.",
                ],
            ).to_dict()
        )
    if "graphql" in hints:
        output.append(
            Candidate(
                candidate_type="GRAPHQL",
                target=url,
                severity="medium",
                confidence=0.6,
                source=["deterministic_candidate_engine"],
                reason=["GraphQL endpoint path pattern is present"],
                manual_verification=[
                    "Confirm GraphQL endpoint exposure and whether introspection is intended.",
                    "Do not run intrusive queries without explicit program permission.",
                ],
            ).to_dict()
        )
    if "object_resource" in hints or "object_id_parameter" in hints or object_id_path(url):
        output.append(
            Candidate(
                candidate_type="BOLA_IDOR",
                target=url,
                severity="medium" if method == "GET" else "high",
                confidence=0.55,
                source=["deterministic_candidate_engine"],
                reason=[
                    "Endpoint appears to reference a user-owned object.",
                    f"HTTP method is {method}.",
                ],
                manual_verification=[
                    "Use only authorized test accounts and seeded non-sensitive records.",
                    "Compare access behavior between account-owned and non-owned objects.",
                    "Do not enumerate object IDs or access real customer data.",
                ],
            ).to_dict()
        )
    redirect_params = sorted(params & {"next", "url", "redirect", "returnurl", "callback"})
    if redirect_params:
        output.append(
            Candidate(
                candidate_type="OPEN_REDIRECT",
                target=url,
                severity="low",
                confidence=0.45,
                source=["deterministic_candidate_engine"],
                reason=[f"Redirect-like query parameter present: {', '.join(redirect_params)}"],
                manual_verification=[
                    "Confirm expected redirect behavior with safe same-origin values first.",
                    "Do not use phishing payloads or real user flows.",
                ],
            ).to_dict()
        )
    ssrf_params = sorted(params & {"url", "uri", "endpoint", "host", "domain", "webhook"})
    if ssrf_params:
        output.append(
            Candidate(
                candidate_type="SSRF",
                target=url,
                severity="medium",
                confidence=0.4,
                source=["deterministic_candidate_engine"],
                reason=[f"Server-side fetch-like parameter present: {', '.join(ssrf_params)}"],
                manual_verification=[
                    "Review feature intent and program policy before any callback testing.",
                    "Do not use OAST or internal network targets without explicit permission.",
                ],
            ).to_dict()
        )
    file_params = sorted(params & {"file", "path", "filename", "download", "template", "image"})
    if file_params:
        output.append(
            Candidate(
                candidate_type="FILE_DISCLOSURE",
                target=url,
                severity="medium",
                confidence=0.45,
                source=["deterministic_candidate_engine"],
                reason=[f"File/path-like query parameter present: {', '.join(file_params)}"],
                manual_verification=[
                    "Confirm intended file access behavior with benign in-scope files only.",
                    "Do not attempt traversal or sensitive file reads automatically.",
                ],
            ).to_dict()
        )
    return output


def object_id_path(url: str) -> bool:
    path = urlparse(url).path.strip("/")
    if not path:
        return False
    parts = path.split("/")
    object_markers = {"users", "user", "orders", "order", "invoices", "documents", "accounts"}
    return any(part.lower() in object_markers for part in parts) and any(
        part.isdigit() for part in parts
    )
