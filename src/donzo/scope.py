from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class ScopeDecision:
    target: str
    target_type: str
    allowed: bool
    reasons: list[str] = field(default_factory=list)
    matched_in_scope: list[str] = field(default_factory=list)
    matched_out_of_scope: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class UrlRule:
    raw: str
    scheme: str
    host: str
    path: str

    @classmethod
    def parse(cls, value: str) -> UrlRule:
        parsed = urlparse(value)
        return cls(
            raw=value,
            scheme=parsed.scheme.lower(),
            host=normalize_host(parsed.hostname or ""),
            path=normalize_path(parsed.path or "/"),
        )

    def matches(self, target: ParsedTarget) -> bool:
        if target.target_type != "url":
            return False
        if self.scheme and target.scheme != self.scheme:
            return False
        if self.host and target.host != self.host:
            return False
        return path_is_under(target.path, self.path)


@dataclass(frozen=True)
class ParsedTarget:
    raw: str
    target_type: str
    scheme: str = ""
    host: str = ""
    path: str = "/"


@dataclass(frozen=True)
class Scope:
    in_scope_domains: tuple[str, ...] = ()
    in_scope_urls: tuple[UrlRule, ...] = ()
    in_scope_ip_ranges: tuple[str, ...] = ()
    out_scope_domains: tuple[str, ...] = ()
    out_scope_urls: tuple[UrlRule, ...] = ()
    out_scope_paths: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> Scope:
        in_scope = data.get("in_scope") or {}
        out_scope = data.get("out_of_scope") or {}
        return cls(
            in_scope_domains=tuple(
                normalize_domain(item) for item in in_scope.get("domains") or []
            ),
            in_scope_urls=tuple(UrlRule.parse(str(item)) for item in in_scope.get("urls") or []),
            in_scope_ip_ranges=tuple(str(item) for item in in_scope.get("ip_ranges") or []),
            out_scope_domains=tuple(
                normalize_domain(item) for item in out_scope.get("domains") or []
            ),
            out_scope_urls=tuple(UrlRule.parse(str(item)) for item in out_scope.get("urls") or []),
            out_scope_paths=tuple(
                normalize_path(str(item)) for item in out_scope.get("paths") or []
            ),
        )

    @property
    def has_in_scope_targets(self) -> bool:
        return bool(self.in_scope_domains or self.in_scope_urls or self.in_scope_ip_ranges)

    def decide(self, target: str) -> ScopeDecision:
        parsed = parse_target(target)
        in_matches = self._in_scope_matches(parsed)
        out_matches = self._out_scope_matches(parsed)
        reasons: list[str] = []
        if in_matches:
            reasons.append("matched_in_scope")
        else:
            reasons.append("no_in_scope_match")
        if out_matches:
            reasons.append("matched_out_of_scope")
        allowed = bool(in_matches) and not out_matches
        return ScopeDecision(
            target=target,
            target_type=parsed.target_type,
            allowed=allowed,
            reasons=reasons,
            matched_in_scope=in_matches,
            matched_out_of_scope=out_matches,
        )

    def _in_scope_matches(self, target: ParsedTarget) -> list[str]:
        matches: list[str] = []
        if target.host:
            matches.extend(
                rule for rule in self.in_scope_domains if domain_matches(target.host, rule)
            )
        if target.target_type == "url":
            matches.extend(rule.raw for rule in self.in_scope_urls if rule.matches(target))
        if target.target_type == "ip":
            matches.extend(
                rule for rule in self.in_scope_ip_ranges if ip_matches_range(target.raw, rule)
            )
        return matches

    def _out_scope_matches(self, target: ParsedTarget) -> list[str]:
        matches: list[str] = []
        if target.host:
            matches.extend(
                rule for rule in self.out_scope_domains if domain_matches(target.host, rule)
            )
        if target.target_type == "url":
            matches.extend(rule.raw for rule in self.out_scope_urls if rule.matches(target))
            matches.extend(
                f"path:{rule}" for rule in self.out_scope_paths if path_is_under(target.path, rule)
            )
        return matches


def normalize_host(value: str) -> str:
    return value.strip().lower().rstrip(".")


def normalize_domain(value: object) -> str:
    return normalize_host(str(value))


def normalize_path(value: str) -> str:
    if not value:
        return "/"
    return value if value.startswith("/") else f"/{value}"


def parse_target(target: str) -> ParsedTarget:
    parsed = urlparse(target)
    if parsed.scheme and parsed.netloc:
        return ParsedTarget(
            raw=target,
            target_type="url",
            scheme=parsed.scheme.lower(),
            host=normalize_host(parsed.hostname or ""),
            path=normalize_path(parsed.path or "/"),
        )
    normalized = normalize_host(target)
    try:
        ip_address(normalized)
    except ValueError:
        return ParsedTarget(raw=target, target_type="domain", host=normalized)
    return ParsedTarget(raw=normalized, target_type="ip")


def domain_matches(host: str, rule: str) -> bool:
    host = normalize_host(host)
    rule = normalize_domain(rule)
    if rule.startswith("*."):
        suffix = rule[1:]
        return host.endswith(suffix) and host != rule[2:]
    return host == rule


def path_is_under(path: str, rule: str) -> bool:
    path = normalize_path(path)
    rule = normalize_path(rule)
    if rule == "/":
        return True
    return path == rule or path.startswith(f"{rule.rstrip('/')}/")


def ip_matches_range(value: str, cidr: str) -> bool:
    try:
        return ip_address(value) in ip_network(cidr, strict=False)
    except ValueError:
        return False
