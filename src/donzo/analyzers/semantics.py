from __future__ import annotations

import re
from collections import Counter
from typing import Any
from urllib.parse import parse_qs, urlparse

from donzo.config import ScopeConfig
from donzo.models import stable_id

VERSION_SEGMENT = re.compile(r"^v\d+$", re.I)
PATH_PARAM = re.compile(r"^\{?[:$]?[A-Za-z_][A-Za-z0-9_-]*\}?$")

PREFIX_SEGMENTS = {
    "api",
    "apis",
    "rest",
    "rpc",
    "graphql",
    "lms",
    "portal",
    "dashboard",
    "app",
    "service",
    "services",
}
AUTH_SEGMENTS = {
    "auth",
    "oauth",
    "login",
    "logout",
    "signin",
    "signup",
    "register",
    "session",
    "sessions",
    "password",
    "reset",
    "token",
    "tokens",
}
ADMIN_SEGMENTS = {"admin", "admins", "staff", "manager", "moderator", "root", "superuser"}
SELF_SEGMENTS = {"me", "my", "profile", "account", "accounts"}
RELATIONSHIP_SEGMENTS = {
    "members",
    "member",
    "roles",
    "role",
    "permissions",
    "permission",
    "teams",
    "team",
    "groups",
    "group",
    "orgs",
    "organizations",
    "organization",
    "children",
    "parents",
    "owner",
    "owners",
}
STATE_SEGMENTS = {
    "draft",
    "submit",
    "submitted",
    "approve",
    "approved",
    "reject",
    "rejected",
    "review",
    "reviewed",
    "publish",
    "published",
    "archive",
    "archived",
    "close",
    "closed",
    "open",
    "complete",
    "completed",
}
ACTION_SEGMENTS = {
    "search": "search",
    "query": "search",
    "export": "export",
    "import": "import",
    "upload": "upload",
    "download": "download",
    "submit": "submit",
    "approve": "approve",
    "reject": "reject",
    "review": "review",
    "publish": "publish",
    "archive": "archive",
    "enroll": "enroll",
    "join": "join",
    "leave": "leave",
    "grade": "grade",
    "invite": "invite",
    "assign": "assign",
    "login": "login",
    "logout": "logout",
    "signup": "signup",
    "register": "signup",
}
SENSITIVE_FIELD_MARKERS = {
    "email",
    "phone",
    "address",
    "name",
    "student",
    "grade",
    "score",
    "role",
    "permission",
    "token",
    "secret",
    "file",
    "attachment",
    "submission",
}
OBJECT_ID_NAMES = {
    "id",
    "uuid",
    "user",
    "userid",
    "user_id",
    "accountid",
    "account_id",
    "studentid",
    "student_id",
    "courseid",
    "course_id",
    "assignmentid",
    "assignment_id",
    "submissionid",
    "submission_id",
    "teamid",
    "team_id",
    "orgid",
    "org_id",
    "organizationid",
    "organization_id",
    "fileid",
    "file_id",
}


def build_api_semantic_map(
    endpoints: list[dict[str, Any]],
    *,
    config: ScopeConfig,
    technology_inferences: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    tech_by_origin = {str(item.get("origin") or ""): item for item in technology_inferences or []}
    output: list[dict[str, Any]] = []
    for endpoint in endpoints:
        url = str(endpoint.get("url") or "")
        if not url or not config.scope.decide(url).allowed:
            continue
        semantic = infer_endpoint_semantics(endpoint, tech_by_origin=tech_by_origin)
        if semantic:
            output.append(semantic)
    return sorted(
        dedupe_semantics(output),
        key=lambda item: (float(item.get("risk_weight") or 0), str(item.get("url") or "")),
        reverse=True,
    )


def infer_endpoint_semantics(
    endpoint: dict[str, Any],
    *,
    tech_by_origin: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    url = str(endpoint.get("url") or "")
    parsed = urlparse(url)
    method = str(endpoint.get("method") or "GET").upper()
    segments = split_path_segments(parsed.path)
    semantic_segments = [segment for segment in segments if not is_prefix_segment(segment)]
    params = endpoint_params(endpoint, parsed)
    source_context = (
        endpoint.get("source_context") if isinstance(endpoint.get("source_context"), dict) else {}
    )
    operation_id = str(endpoint.get("operation_id") or "")
    operation_tags = [str(item) for item in endpoint.get("operation_tags") or [] if str(item)]
    operation_summary = str(endpoint.get("operation_summary") or "")
    resource = infer_resource(semantic_segments, params, operation_tags, operation_id)
    action = infer_action(method, semantic_segments, params, operation_id, operation_summary)
    object_ids = object_id_hints(semantic_segments, params)
    auth_guess = infer_auth_guess(semantic_segments, method, object_ids, action, endpoint)
    state_hints = sorted({segment for segment in semantic_segments if segment in STATE_SEGMENTS})
    relationship_hints = sorted(
        {segment for segment in semantic_segments if segment in RELATIONSHIP_SEGMENTS}
    )
    role_hints = sorted({segment for segment in semantic_segments if segment in ADMIN_SEGMENTS})
    data_hints = data_sensitivity_hints(semantic_segments, params, operation_summary)
    risk_questions = build_risk_questions(
        resource=resource,
        action=action,
        auth_guess=auth_guess,
        object_ids=object_ids,
        relationship_hints=relationship_hints,
        state_hints=state_hints,
        data_hints=data_hints,
        method=method,
    )
    origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""
    technology = tech_by_origin.get(origin, {})
    confidence = semantic_confidence(
        endpoint,
        resource=resource,
        action=action,
        object_ids=object_ids,
        operation_id=operation_id,
        source_context=source_context,
    )
    return {
        "semantic_id": stable_id("api_semantic", method, url),
        "url": url,
        "method": method,
        "origin": origin,
        "path": parsed.path or "/",
        "resource": resource,
        "resource_path": resource_path(semantic_segments),
        "action": action,
        "auth_guess": auth_guess,
        "object_id_params": object_ids,
        "relationship_hints": relationship_hints,
        "state_hints": state_hints,
        "role_hints": role_hints,
        "data_sensitivity_hints": data_hints,
        "operation_id": operation_id,
        "operation_tags": operation_tags,
        "operation_summary": operation_summary,
        "source_context": source_context,
        "source": endpoint.get("source") or [],
        "risk_hints": endpoint.get("risk_hints") or [],
        "risk_questions": risk_questions,
        "risk_weight": semantic_risk_weight(
            action=action,
            auth_guess=auth_guess,
            object_ids=object_ids,
            relationship_hints=relationship_hints,
            state_hints=state_hints,
            data_hints=data_hints,
        ),
        "confidence": confidence,
        "technology_context": compact_technology_context(technology),
        "automatic_exploit": False,
        "verification_status": "passive_semantic_inference",
    }


def split_path_segments(path: str) -> list[str]:
    return [normalize_segment(segment) for segment in path.split("/") if normalize_segment(segment)]


def normalize_segment(segment: str) -> str:
    value = segment.strip().strip("{}").strip(":").lower()
    value = re.sub(r"[^a-z0-9_-]+", "_", value).strip("_")
    return value


def is_prefix_segment(segment: str) -> bool:
    return segment in PREFIX_SEGMENTS or bool(VERSION_SEGMENT.match(segment))


def infer_resource(
    segments: list[str],
    params: list[str],
    operation_tags: list[str],
    operation_id: str,
) -> str:
    for tag in operation_tags:
        normalized = normalize_resource_name(tag)
        if normalized:
            return normalized
    candidates = [
        segment
        for segment in segments
        if segment
        and segment not in ACTION_SEGMENTS
        and segment not in AUTH_SEGMENTS
        and segment not in STATE_SEGMENTS
        and not likely_id_segment(segment)
    ]
    if candidates:
        if candidates[-1] in RELATIONSHIP_SEGMENTS and len(candidates) > 1:
            return normalize_resource_name(candidates[-2])
        return normalize_resource_name(candidates[-1])
    for param in params:
        normalized = normalize_param_name(param)
        if normalized.endswith("_id"):
            return normalize_resource_name(normalized[: -len("_id")])
    if operation_id:
        tokens = split_identifier(operation_id)
        for token in reversed(tokens):
            if token not in ACTION_SEGMENTS and token not in AUTH_SEGMENTS:
                return normalize_resource_name(token)
    return "unknown"


def infer_action(
    method: str,
    segments: list[str],
    params: list[str],
    operation_id: str,
    operation_summary: str,
) -> str:
    text = " ".join([*segments, operation_id, operation_summary]).lower()
    for segment in segments:
        if segment in ACTION_SEGMENTS:
            return ACTION_SEGMENTS[segment]
    for keyword, action in ACTION_SEGMENTS.items():
        if keyword in text:
            return action
    if method == "GET":
        return "list" if not has_object_reference(segments, params) else "read"
    if method == "POST":
        return "create"
    if method in {"PUT", "PATCH"}:
        return "update"
    if method == "DELETE":
        return "delete"
    return method.lower()


def infer_auth_guess(
    segments: list[str],
    method: str,
    object_ids: list[str],
    action: str,
    endpoint: dict[str, Any],
) -> str:
    if any(segment in AUTH_SEGMENTS for segment in segments) or action in {
        "login",
        "logout",
        "signup",
    }:
        return "auth_flow"
    if any(segment in ADMIN_SEGMENTS for segment in segments):
        return "admin_or_staff"
    if any(segment in SELF_SEGMENTS for segment in segments):
        return "self"
    if any(segment in RELATIONSHIP_SEGMENTS for segment in segments):
        return "member_or_owner"
    if object_ids:
        return "owner_or_authorized_actor"
    if endpoint.get("requires_auth_guess") is True:
        return "authenticated"
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        return "authenticated"
    return "unknown_or_public"


def object_id_hints(segments: list[str], params: list[str]) -> list[str]:
    hints: list[str] = []
    for segment in segments:
        if likely_id_segment(segment):
            hints.append(segment)
    for param in params:
        normalized = normalize_param_name(param)
        if normalized in OBJECT_ID_NAMES or normalized.endswith("_id"):
            hints.append(normalized)
    return sorted(set(hints))


def data_sensitivity_hints(
    segments: list[str],
    params: list[str],
    operation_summary: str,
) -> list[str]:
    text = " ".join([*segments, *params, operation_summary.lower()])
    hints = sorted(marker for marker in SENSITIVE_FIELD_MARKERS if marker in text)
    return hints[:20]


def build_risk_questions(
    *,
    resource: str,
    action: str,
    auth_guess: str,
    object_ids: list[str],
    relationship_hints: list[str],
    state_hints: list[str],
    data_hints: list[str],
    method: str,
) -> list[str]:
    questions: list[str] = []
    if object_ids:
        questions.append(
            f"Does the server verify ownership/authorization for {resource} identifiers?"
        )
    if action in {"update", "delete", "approve", "reject", "grade", "publish", "archive"}:
        questions.append(f"Is {action} restricted to the expected role and object state?")
    if relationship_hints:
        questions.append(
            "Are membership/relationship checks enforced server-side, not only in the UI?"
        )
    if state_hints or action in {"submit", "approve", "reject", "publish"}:
        questions.append("Does the server enforce valid workflow state transitions?")
    if auth_guess == "admin_or_staff":
        questions.append("Is this admin/staff surface intentionally reachable by this actor?")
    if data_hints and method == "GET":
        questions.append("Does the response expose only fields allowed for the caller?")
    if action in {"upload", "download", "export", "import"}:
        questions.append("Are file/export operations scoped to authorized records only?")
    if not questions:
        questions.append("Is the observed behavior expected for the inferred resource/action?")
    return questions


def semantic_risk_weight(
    *,
    action: str,
    auth_guess: str,
    object_ids: list[str],
    relationship_hints: list[str],
    state_hints: list[str],
    data_hints: list[str],
) -> int:
    score = 10
    if object_ids:
        score += 20
    if action in {"update", "delete", "approve", "reject", "grade", "publish", "archive"}:
        score += 25
    elif action in {"create", "submit", "upload", "download", "export"}:
        score += 18
    elif action in {"read", "list"} and object_ids:
        score += 10
    if relationship_hints:
        score += 12
    if state_hints:
        score += 10
    if auth_guess == "admin_or_staff":
        score += 20
    if data_hints:
        score += min(15, 3 * len(data_hints))
    return max(0, min(100, score))


def semantic_confidence(
    endpoint: dict[str, Any],
    *,
    resource: str,
    action: str,
    object_ids: list[str],
    operation_id: str,
    source_context: dict[str, Any],
) -> float:
    confidence = 0.45
    if resource != "unknown":
        confidence += 0.12
    if action:
        confidence += 0.08
    if object_ids:
        confidence += 0.08
    if operation_id:
        confidence += 0.12
    if source_context:
        confidence += 0.08
    if endpoint.get("params"):
        confidence += 0.04
    return round(min(0.9, confidence), 2)


def endpoint_params(endpoint: dict[str, Any], parsed_url: Any) -> list[str]:
    params = [str(item) for item in endpoint.get("params") or [] if str(item)]
    query_params = sorted(parse_qs(parsed_url.query).keys())
    return sorted(set([*params, *query_params]))


def has_object_reference(segments: list[str], params: list[str]) -> bool:
    return bool(object_id_hints(segments, params))


def likely_id_segment(segment: str) -> bool:
    if segment.isdigit():
        return True
    if segment in OBJECT_ID_NAMES or segment.endswith("_id"):
        return True
    if segment in {"id", "uuid"}:
        return True
    return bool(PATH_PARAM.match(segment) and segment in OBJECT_ID_NAMES)


def normalize_param_name(value: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", value.lower()).strip("_")


def normalize_resource_name(value: str) -> str:
    normalized = normalize_param_name(value)
    if normalized.endswith("ies"):
        return f"{normalized[:-3]}y"
    if normalized.endswith("s") and len(normalized) > 3:
        return normalized[:-1]
    return normalized or "unknown"


def split_identifier(value: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    return [normalize_param_name(item) for item in re.split(r"[_\-\s]+", spaced) if item]


def resource_path(segments: list[str]) -> str:
    relevant = [
        segment
        for segment in segments
        if segment not in AUTH_SEGMENTS and not is_prefix_segment(segment)
    ]
    return "/".join(relevant[:8])


def compact_technology_context(inference: dict[str, Any]) -> dict[str, Any]:
    if not inference:
        return {}
    return {
        "confidence": inference.get("confidence"),
        "technologies": (inference.get("technologies") or [])[:8],
        "api_hints": (inference.get("api_hints") or [])[:8],
    }


def dedupe_semantics(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for record in records:
        semantic_id = str(record.get("semantic_id") or "")
        if not semantic_id or semantic_id in seen:
            continue
        seen.add(semantic_id)
        output.append(record)
    return output


def summarize_semantic_map(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "resources": dict(Counter(str(item.get("resource") or "unknown") for item in records)),
        "actions": dict(Counter(str(item.get("action") or "unknown") for item in records)),
        "auth_guesses": dict(Counter(str(item.get("auth_guess") or "unknown") for item in records)),
        "high_risk_count": sum(1 for item in records if int(item.get("risk_weight") or 0) >= 55),
    }
