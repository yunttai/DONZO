from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high", "critical"]
Priority = Literal["P0", "P1", "P2", "P3"]

SEVERITIES: set[str] = {"info", "low", "medium", "high", "critical"}
SEVERITY_ALIASES = {
    "informational": "info",
    "moderate": "medium",
    "med": "medium",
    "warn": "low",
}


def now_utc() -> str:
    return datetime.now(UTC).isoformat()


def stable_id(*parts: object, length: int = 16) -> str:
    joined = "\x1f".join(str(part or "") for part in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:length]


def normalize_severity(value: object) -> Severity:
    raw = str(value or "info").strip().lower()
    normalized = SEVERITY_ALIASES.get(raw, raw)
    if normalized in SEVERITIES:
        return normalized  # type: ignore[return-value]
    return "info"


def clamp_confidence(value: object, default: float = 0.5) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return default


def normalize_source(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if value:
        return [str(value)]
    return ["unknown"]


def compact_dict(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value not in (None, "", [], {})}


@dataclass(frozen=True)
class Asset:
    asset: str
    type: str
    sources: list[str]
    in_scope: bool
    risk_hints: list[str] = field(default_factory=list)
    first_seen: str = field(default_factory=now_utc)
    last_seen: str = field(default_factory=now_utc)
    asset_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["asset_id"] = self.asset_id or stable_id("asset", self.asset, self.type)
        return data


@dataclass(frozen=True)
class Service:
    url: str
    host: str
    status_code: int | None
    title: str | None = None
    content_type: str | None = None
    tech: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    source: list[str] = field(default_factory=lambda: ["unknown"])
    risk_hints: list[str] = field(default_factory=list)
    service_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = compact_dict(asdict(self))
        data["service_id"] = self.service_id or stable_id("service", self.url, self.host)
        return data


@dataclass(frozen=True)
class Endpoint:
    url: str
    method: str
    source: list[str]
    status_code: int | None = None
    content_type: str | None = None
    params: list[str] = field(default_factory=list)
    requires_auth_guess: bool | None = None
    risk_hints: list[str] = field(default_factory=list)
    endpoint_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = compact_dict(asdict(self))
        data["endpoint_id"] = self.endpoint_id or stable_id("endpoint", self.method, self.url)
        return data


@dataclass(frozen=True)
class Parameter:
    endpoint_url: str
    name: str
    location: str
    source: list[str]
    risk_hints: list[str] = field(default_factory=list)
    parameter_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = compact_dict(asdict(self))
        data["parameter_id"] = self.parameter_id or stable_id(
            "parameter",
            self.endpoint_url,
            self.location,
            self.name,
        )
        return data


@dataclass(frozen=True)
class Candidate:
    candidate_type: str
    target: str
    severity: Severity
    confidence: float
    source: list[str]
    reason: list[str]
    manual_verification: list[str]
    auto_exploit: bool = False
    candidate_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["candidate_id"] = self.candidate_id or stable_id(
            "candidate",
            self.candidate_type,
            self.target,
            self.reason,
        )
        return data


@dataclass(frozen=True)
class Finding:
    title: str
    severity: Severity
    confidence: float
    target: str
    candidate_type: str
    source: list[str]
    evidence: dict[str, Any]
    verification_status: str = "needs_manual_review"
    auto_exploit: bool = False
    manual_verification: list[str] = field(default_factory=list)
    risk_score: float | None = None
    priority: Priority | None = None
    finding_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = compact_dict(asdict(self))
        data["auto_exploit"] = False
        data["finding_id"] = self.finding_id or stable_id(
            "finding",
            self.title,
            self.target,
            self.candidate_type,
            self.source,
        )
        return data
