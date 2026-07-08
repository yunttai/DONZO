from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from donzo.models import stable_id
from donzo.scope import domain_matches, path_is_under

REDTEAM_MODES = {"plan_only", "assisted", "redteam", "lab"}
DEFAULT_EXPLICIT_OPT_IN_CLASSES = {
    "COMMANDINJECTION",
    "COMMAND_INJECTION",
    "PATHTRAVERSALSENSITIVEREAD",
    "PATH_TRAVERSAL_SENSITIVE_READ",
    "FILEUPLOADEXECUTION",
    "FILE_UPLOAD_EXECUTION",
    "DESTRUCTIVEMUTATION",
    "DESTRUCTIVE_MUTATION",
    "CLOUDMETADATAACCESS",
    "CLOUD_METADATA_ACCESS",
}
CLASS_ALIASES = {
    "BOLA": "BOLA",
    "IDOR": "BOLA",
    "BFLA": "BFLA",
    "SQLI": "SQLI",
    "SQLINJECTION": "SQLI",
    "SSRF": "SSRF",
    "SSTI": "SSTI",
    "XSS": "XSS",
    "MASSASSIGNMENT": "MASS_ASSIGNMENT",
    "MASS_ASSIGNMENT": "MASS_ASSIGNMENT",
    "EXCESSIVEDATAEXPOSURE": "EDE",
    "EXCESSIVE_DATA_EXPOSURE": "EDE",
    "EDE": "EDE",
    "BUSINESSLOGIC": "BUSINESS_LOGIC",
    "BUSINESS_LOGIC": "BUSINESS_LOGIC",
    "COMMANDINJECTION": "COMMAND_INJECTION",
    "COMMAND_INJECTION": "COMMAND_INJECTION",
    "PATHTRAVERSAL": "PATH_TRAVERSAL",
    "PATH_TRAVERSAL": "PATH_TRAVERSAL",
    "PATHTRAVERSALSENSITIVEREAD": "PATH_TRAVERSAL_SENSITIVE_READ",
    "PATH_TRAVERSAL_SENSITIVE_READ": "PATH_TRAVERSAL_SENSITIVE_READ",
    "FILEUPLOAD": "FILE_UPLOAD",
    "FILE_UPLOAD": "FILE_UPLOAD",
    "FILEUPLOADEXECUTION": "FILE_UPLOAD_EXECUTION",
    "FILE_UPLOAD_EXECUTION": "FILE_UPLOAD_EXECUTION",
    "DESTRUCTIVEMUTATION": "DESTRUCTIVE_MUTATION",
    "DESTRUCTIVE_MUTATION": "DESTRUCTIVE_MUTATION",
    "CLOUDMETADATAACCESS": "CLOUD_METADATA_ACCESS",
    "CLOUD_METADATA_ACCESS": "CLOUD_METADATA_ACCESS",
}


@dataclass(frozen=True)
class RedteamLimits:
    max_rps: float = 0.0
    max_concurrent_requests: int = 0
    max_requests_per_endpoint: int = 0
    max_total_requests: int = 0
    stop_on_5xx_rate_percent: float = 0.0
    stop_on_429: bool = True
    present: bool = False

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> RedteamLimits:
        data = data or {}
        return cls(
            max_rps=float(data.get("max_rps") or data.get("max_requests_per_second") or 0),
            max_concurrent_requests=int(
                data.get("max_concurrent_requests") or data.get("max_concurrency") or 0
            ),
            max_requests_per_endpoint=int(data.get("max_requests_per_endpoint") or 0),
            max_total_requests=int(data.get("max_total_requests") or 0),
            stop_on_5xx_rate_percent=float(data.get("stop_on_5xx_rate_percent") or 0),
            stop_on_429=bool(data.get("stop_on_429", True)),
            present=bool(data),
        )


@dataclass(frozen=True)
class RedteamEvidencePolicy:
    redact_secrets: bool = True
    store_raw_responses: bool = False
    store_minimal_body_diff: bool = True
    screenshot_on_browser_oracle: bool = True

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> RedteamEvidencePolicy:
        data = data or {}
        return cls(
            redact_secrets=bool(data.get("redact_secrets", True)),
            store_raw_responses=bool(data.get("store_raw_responses", False)),
            store_minimal_body_diff=bool(data.get("store_minimal_body_diff", True)),
            screenshot_on_browser_oracle=bool(data.get("screenshot_on_browser_oracle", True)),
        )


@dataclass(frozen=True)
class RedteamEngagement:
    name: str = ""
    mode: str = "plan_only"
    start_time: datetime | None = None
    end_time: datetime | None = None
    operator: str = ""
    authorization_ref: str = ""
    present: bool = False

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> RedteamEngagement:
        data = data or {}
        return cls(
            name=str(data.get("name") or ""),
            mode=str(data.get("mode") or "plan_only"),
            start_time=parse_datetime(data.get("start_time")),
            end_time=parse_datetime(data.get("end_time")),
            operator=str(data.get("operator") or ""),
            authorization_ref=str(data.get("authorization_ref") or ""),
            present=bool(data),
        )


@dataclass
class RedteamExecutionState:
    total_requests: int = 0
    requests_per_endpoint: dict[str, int] = field(default_factory=dict)
    status_counts: dict[str, int] = field(default_factory=dict)
    seen_429: bool = False

    def record_result(self, endpoint_id: str, status: int | None) -> None:
        self.total_requests += 1
        self.requests_per_endpoint[endpoint_id] = self.requests_per_endpoint.get(endpoint_id, 0) + 1
        if status is None:
            return
        if status == 429:
            self.seen_429 = True
        bucket = "5xx" if 500 <= status <= 599 else str(status)
        self.status_counts[bucket] = self.status_counts.get(bucket, 0) + 1


@dataclass(frozen=True)
class ScopeGuardDecision:
    allowed: bool
    status: str
    reasons: list[str]
    request_id: str
    method: str
    url: str
    vulnerability_class: str
    actor: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "status": self.status,
            "reasons": self.reasons,
            "request_id": self.request_id,
            "method": self.method,
            "url": self.url,
            "vulnerability_class": self.vulnerability_class,
            "actor": self.actor,
        }


@dataclass
class RedteamScopeGuard:
    allowed_hosts: tuple[str, ...] = ()
    denied_hosts: tuple[str, ...] = ()
    allowed_schemes: tuple[str, ...] = ("https",)
    allowed_paths: tuple[str, ...] = ()
    denied_paths: tuple[str, ...] = ()
    allowed_methods: tuple[str, ...] = ("GET",)
    allowed_classes: tuple[str, ...] = ()
    denied_classes: tuple[str, ...] = ()
    explicit_opt_in_required: tuple[str, ...] = tuple(sorted(DEFAULT_EXPLICIT_OPT_IN_CLASSES))
    explicit_opt_in: tuple[str, ...] = ()
    engagement: RedteamEngagement = field(default_factory=RedteamEngagement)
    limits: RedteamLimits = field(default_factory=RedteamLimits)
    evidence: RedteamEvidencePolicy = field(default_factory=RedteamEvidencePolicy)
    kill_switch_path: Path | None = None
    source_path: Path | None = None
    engagement_path: Path | None = None
    state: RedteamExecutionState = field(default_factory=RedteamExecutionState)

    def preflight(self, *, mode: str, actors_present: bool = False) -> list[str]:
        normalized_mode = mode.strip().lower()
        reasons: list[str] = []
        if normalized_mode not in REDTEAM_MODES:
            reasons.append(f"unknown_mode:{mode}")
        if not self.source_path:
            reasons.append("scope_yaml_missing")
        if normalized_mode == "redteam":
            if not self.engagement.present:
                reasons.append("engagement_yaml_missing")
            if not self.engagement.authorization_ref:
                reasons.append("authorization_ref_missing")
            if not actors_present:
                reasons.append("actors_yaml_missing")
            if not self.limits.present or self.limits.max_rps <= 0:
                reasons.append("rate_limit_missing")
            if self.kill_switch_path is None:
                reasons.append("kill_switch_missing")
            if not self.evidence.redact_secrets:
                reasons.append("evidence_redaction_required")
        return reasons

    def evaluate_request(
        self,
        request: dict[str, Any],
        *,
        mode: str,
        actors_present: bool = False,
        now: datetime | None = None,
    ) -> ScopeGuardDecision:
        method = str(request.get("method") or "GET").upper()
        url = str(request.get("url") or request.get("target") or "")
        vulnerability_class = normalize_class(
            request.get("vulnerability_class") or request.get("class") or ""
        )
        request_id = str(
            request.get("request_id")
            or stable_id("redteam_request", method, url, vulnerability_class)
        )
        actor = str(request.get("actor") or "")
        reasons = self.preflight(mode=mode, actors_present=actors_present)
        normalized_mode = mode.strip().lower()
        parsed = urlparse(url)

        if normalized_mode == "plan_only":
            reasons.append("mode_plan_only_no_execution")
        if self.kill_switch_path and self.kill_switch_path.exists():
            reasons.append("kill_switch_present")
        if not parsed.scheme or not parsed.netloc:
            reasons.append("invalid_url")
        else:
            host = (parsed.hostname or "").lower().rstrip(".")
            scheme = parsed.scheme.lower()
            path = parsed.path or "/"
            if self.allowed_schemes and scheme not in self.allowed_schemes:
                reasons.append(f"scheme_not_allowed:{scheme}")
            if self.allowed_hosts and not any(
                domain_matches(host, rule) for rule in self.allowed_hosts
            ):
                reasons.append(f"host_not_allowed:{host}")
            if any(domain_matches(host, rule) for rule in self.denied_hosts):
                reasons.append(f"host_denied:{host}")
            if self.allowed_paths and not any(
                path_is_under(path, rule) for rule in self.allowed_paths
            ):
                reasons.append(f"path_not_allowed:{path}")
            denied_path = next(
                (rule for rule in self.denied_paths if path_is_under(path, rule)),
                "",
            )
            if denied_path:
                reasons.append(f"path_denied:{denied_path}")

        if self.allowed_methods and method not in self.allowed_methods:
            reasons.append(f"method_not_allowed:{method}")
        if self.allowed_classes and vulnerability_class not in self.allowed_classes:
            reasons.append(f"class_not_allowed:{vulnerability_class}")
        if vulnerability_class in self.denied_classes:
            reasons.append(f"class_denied:{vulnerability_class}")
        if (
            vulnerability_class in self.explicit_opt_in_required
            and vulnerability_class not in self.explicit_opt_in
        ):
            reasons.append(f"explicit_opt_in_required:{vulnerability_class}")
        reasons.extend(self._window_reasons(now or datetime.now(UTC)))
        reasons.extend(self._limit_reasons(str(request.get("endpoint_id") or f"{method} {url}")))

        allowed = not reasons
        return ScopeGuardDecision(
            allowed=allowed,
            status="allowed" if allowed else "blocked_by_scope",
            reasons=reasons,
            request_id=request_id,
            method=method,
            url=url,
            vulnerability_class=vulnerability_class,
            actor=actor,
        )

    def record_result(self, endpoint_id: str, status: int | None) -> None:
        self.state.record_result(endpoint_id, status)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_hosts": list(self.allowed_hosts),
            "denied_hosts": list(self.denied_hosts),
            "allowed_schemes": list(self.allowed_schemes),
            "allowed_paths": list(self.allowed_paths),
            "denied_paths": list(self.denied_paths),
            "allowed_methods": list(self.allowed_methods),
            "allowed_classes": list(self.allowed_classes),
            "denied_classes": list(self.denied_classes),
            "requires_explicit_opt_in": list(self.explicit_opt_in_required),
            "explicit_opt_in": list(self.explicit_opt_in),
            "engagement": {
                "name": self.engagement.name,
                "mode": self.engagement.mode,
                "start_time": self.engagement.start_time.isoformat()
                if self.engagement.start_time
                else None,
                "end_time": self.engagement.end_time.isoformat()
                if self.engagement.end_time
                else None,
                "operator": self.engagement.operator,
                "authorization_ref": self.engagement.authorization_ref,
            },
            "limits": {
                "max_rps": self.limits.max_rps,
                "max_concurrent_requests": self.limits.max_concurrent_requests,
                "max_requests_per_endpoint": self.limits.max_requests_per_endpoint,
                "max_total_requests": self.limits.max_total_requests,
                "stop_on_5xx_rate_percent": self.limits.stop_on_5xx_rate_percent,
                "stop_on_429": self.limits.stop_on_429,
            },
            "evidence": {
                "redact_secrets": self.evidence.redact_secrets,
                "store_raw_responses": self.evidence.store_raw_responses,
                "store_minimal_body_diff": self.evidence.store_minimal_body_diff,
                "screenshot_on_browser_oracle": self.evidence.screenshot_on_browser_oracle,
            },
            "kill_switch_path": str(self.kill_switch_path) if self.kill_switch_path else None,
        }

    def _window_reasons(self, now: datetime) -> list[str]:
        reasons: list[str] = []
        current = now if now.tzinfo else now.replace(tzinfo=UTC)
        start = self.engagement.start_time
        end = self.engagement.end_time
        if start and start.tzinfo is None:
            start = start.replace(tzinfo=UTC)
        if end and end.tzinfo is None:
            end = end.replace(tzinfo=UTC)
        if start and current < start:
            reasons.append("engagement_not_started")
        if end and current > end:
            reasons.append("engagement_expired")
        return reasons

    def _limit_reasons(self, endpoint_id: str) -> list[str]:
        reasons: list[str] = []
        if (
            self.limits.max_total_requests
            and self.state.total_requests >= self.limits.max_total_requests
        ):
            reasons.append("max_total_requests_exceeded")
        endpoint_count = self.state.requests_per_endpoint.get(endpoint_id, 0)
        if (
            self.limits.max_requests_per_endpoint
            and endpoint_count >= self.limits.max_requests_per_endpoint
        ):
            reasons.append("max_requests_per_endpoint_exceeded")
        if self.limits.stop_on_429 and self.state.seen_429:
            reasons.append("previous_429_stop")
        total = max(1, self.state.total_requests)
        five_xx = self.state.status_counts.get("5xx", 0)
        if (
            self.limits.stop_on_5xx_rate_percent
            and self.state.total_requests > 0
            and five_xx * 100 / total >= self.limits.stop_on_5xx_rate_percent
        ):
            reasons.append("5xx_rate_stop")
        return reasons


def load_redteam_scope_guard(
    scope_path: Path,
    *,
    engagement_path: Path | None = None,
    run_dir: Path | None = None,
) -> RedteamScopeGuard:
    scope_data = load_yaml_object(scope_path)
    engagement_data = (
        scope_data.get("engagement")
        if isinstance(scope_data.get("engagement"), dict)
        else {}
    )
    if engagement_path:
        engagement_data = {**engagement_data, **load_yaml_object(engagement_path)}
    scope_section = (
        scope_data.get("scope") if isinstance(scope_data.get("scope"), dict) else scope_data
    )
    limits = RedteamLimits.from_mapping(scope_data.get("limits"))
    evidence = RedteamEvidencePolicy.from_mapping(scope_data.get("evidence"))
    kill_switch_value = scope_data.get("kill_switch") or scope_data.get("kill_switch_path")
    kill_switch_path = Path(kill_switch_value) if kill_switch_value else None
    if kill_switch_path is None and run_dir is not None:
        kill_switch_path = run_dir / "STOP"
    return RedteamScopeGuard(
        allowed_hosts=tuple(normalize_hosts(scope_section.get("allowed_hosts") or [])),
        denied_hosts=tuple(normalize_hosts(scope_section.get("denied_hosts") or [])),
        allowed_schemes=tuple(
            str(item).lower() for item in scope_section.get("allowed_schemes") or ("https",)
        ),
        allowed_paths=tuple(str(item) for item in scope_section.get("allowed_paths") or ("/",)),
        denied_paths=tuple(str(item) for item in scope_section.get("denied_paths") or ()),
        allowed_methods=tuple(
            str(item).upper() for item in scope_section.get("allowed_methods") or ("GET",)
        ),
        allowed_classes=tuple(
            normalize_class(item) for item in scope_data.get("allowed_classes") or ()
        ),
        denied_classes=tuple(
            normalize_class(item) for item in scope_data.get("denied_classes") or ()
        ),
        explicit_opt_in_required=tuple(
            normalize_class(item)
            for item in (
                scope_data.get("requires_explicit_opt_in") or DEFAULT_EXPLICIT_OPT_IN_CLASSES
            )
        ),
        explicit_opt_in=tuple(
            normalize_class(item)
            for item in scope_data.get("explicit_opt_in") or scope_data.get("opt_in_classes") or ()
        ),
        engagement=RedteamEngagement.from_mapping(engagement_data),
        limits=limits,
        evidence=evidence,
        kill_switch_path=kill_switch_path,
        source_path=scope_path,
        engagement_path=engagement_path,
    )


def load_yaml_object(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML object")
    return data


def normalize_hosts(values: list[Any]) -> list[str]:
    return [str(item).strip().lower().rstrip(".") for item in values if str(item).strip()]


def normalize_class(value: Any) -> str:
    raw = str(value or "").strip().upper().replace("-", "_").replace(" ", "_")
    compact = raw.replace("_", "")
    return CLASS_ALIASES.get(raw) or CLASS_ALIASES.get(compact) or raw


def parse_datetime(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    return datetime.fromisoformat(text)
