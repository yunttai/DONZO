from __future__ import annotations

from typing import Any

from donzo.models import stable_id
from donzo.traffic.redactor import redact_value

AGENT_INTERFACE_NAMES = {
    "api_agent",
    "parameter_agent",
    "dependency_agent",
    "handler_agent",
    "invariant_agent",
    "test_plan_agent",
    "oracle_agent",
    "report_agent",
}


def build_agent_interfaces() -> dict[str, Any]:
    interfaces = [
        agent_interface(
            "api_agent",
            inputs=["api-endpoints.jsonl", "traffic.jsonl", "graphql-operations.jsonl"],
            outputs=["normalized API endpoint facts", "source provenance gaps"],
        ),
        agent_interface(
            "parameter_agent",
            inputs=[
                "parameter-classification.jsonl",
                "request-schemas.jsonl",
                "response-schemas.jsonl",
            ],
            outputs=["field semantic review", "parameter risk notes"],
        ),
        agent_interface(
            "dependency_agent",
            inputs=["api-dependency-graph.json", "api-sequences.jsonl", "business-flows.jsonl"],
            outputs=["dependency confidence review", "missing preconditions"],
        ),
        agent_interface(
            "handler_agent",
            inputs=["handler-hypotheses.jsonl"],
            outputs=["backend check hypotheses", "missing validation/authz checks"],
        ),
        agent_interface(
            "invariant_agent",
            inputs=["security-invariants.jsonl", "business-state-invariants.jsonl", "actors.jsonl"],
            outputs=["invariant quality review", "actor-aware invariant gaps"],
        ),
        agent_interface(
            "test_plan_agent",
            inputs=["manual-test-plans.jsonl", "business-mutation-plans.jsonl"],
            outputs=["safe manual plan review", "oracle readiness notes"],
        ),
        agent_interface(
            "oracle_agent",
            inputs=["oracle-templates.jsonl", "manual-feedback.jsonl", "feedback-graph.json"],
            outputs=["oracle confidence updates", "manual evidence requirements"],
        ),
        agent_interface(
            "report_agent",
            inputs=["report-drafts.jsonl", "evidence index"],
            outputs=["report quality review", "reproducibility gaps"],
        ),
    ]
    return {
        "schema_version": 1,
        "agent_interfaces": interfaces,
        "policy": {
            "deterministic_first": True,
            "json_schema_validated": True,
            "evidence_link_required": True,
            "redaction_required": True,
            "may_invent_endpoints_or_fields": False,
        },
    }


def build_deterministic_agent_runs(
    *,
    api_endpoint_models: list[dict[str, Any]] | None = None,
    parameter_classifications: list[dict[str, Any]] | None = None,
    dependency_graph: dict[str, Any] | None = None,
    handler_hypotheses: list[dict[str, Any]] | None = None,
    security_invariants: list[dict[str, Any]] | None = None,
    safe_manual_test_plans: list[dict[str, Any]] | None = None,
    oracle_templates: list[dict[str, Any]] | None = None,
    report_drafts: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    runs = [
        deterministic_run("api_agent", "api_endpoint_model", api_endpoint_models or []),
        deterministic_run(
            "parameter_agent", "parameter_classification", parameter_classifications or []
        ),
        deterministic_run(
            "dependency_agent", "dependency_graph", [dependency_graph] if dependency_graph else []
        ),
        deterministic_run("handler_agent", "handler_hypothesis", handler_hypotheses or []),
        deterministic_run("invariant_agent", "security_invariant", security_invariants or []),
        deterministic_run("test_plan_agent", "manual_test_plan", safe_manual_test_plans or []),
        deterministic_run("oracle_agent", "oracle_template", oracle_templates or []),
        deterministic_run("report_agent", "report_draft", report_drafts or []),
    ]
    return [run for run in runs if validate_agent_run(run)["valid"]]


def agent_interface(name: str, *, inputs: list[str], outputs: list[str]) -> dict[str, Any]:
    return {
        "agent": name,
        "input_artifacts": inputs,
        "output_contract": {
            "format": "json",
            "required_fields": [
                "agent_run_id",
                "agent",
                "subject_type",
                "verdict",
                "confidence",
                "evidence_refs",
                "redacted",
            ],
            "must_not_invent_endpoints_or_fields": True,
        },
        "expected_outputs": outputs,
        "safety": {
            "automatic_exploit": False,
            "external_llm_optional": True,
            "schema_validation_required": True,
        },
    }


def deterministic_run(
    agent: str, subject_type: str, records: list[dict[str, Any]]
) -> dict[str, Any]:
    evidence_refs = collect_evidence_refs(records)
    return {
        "agent_run_id": stable_id(
            "deterministic_agent_run", agent, subject_type, len(records), evidence_refs[:10]
        ),
        "agent": agent,
        "subject_type": subject_type,
        "verdict": "needs_more_evidence" if records else "no_input",
        "confidence": 0.62 if records else 0.0,
        "summary": f"Deterministic {agent} reviewed {len(records)} {subject_type} record(s).",
        "evidence_refs": evidence_refs,
        "observations": deterministic_observations(agent, records),
        "redacted": True,
        "external_llm_called": False,
        "policy": {
            "no_endpoint_invention": True,
            "no_field_invention": True,
            "manual_review_required": True,
        },
    }


def deterministic_observations(agent: str, records: list[dict[str, Any]]) -> list[str]:
    if not records:
        return ["No input artifacts were available."]
    if agent == "dependency_agent":
        graph = records[0] if records else {}
        summary = graph.get("summary") if isinstance(graph, dict) else {}
        return [f"graph nodes={summary.get('node_count', 0)} edges={summary.get('edge_count', 0)}"]
    return [f"{agent} input_count={len(records)}"]


def collect_evidence_refs(records: list[dict[str, Any]]) -> list[str]:
    refs: list[str] = []
    keys = (
        "endpoint_id",
        "classification_id",
        "graph_id",
        "hypothesis_id",
        "invariant_id",
        "test_id",
        "oracle_template_id",
        "report_draft_id",
    )
    for record in records[:100]:
        clean = redact_value(record)
        for key in keys:
            if isinstance(clean, dict) and clean.get(key):
                refs.append(f"{key}:{clean[key]}")
                break
    return refs


def validate_agent_run(record: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    if record.get("agent") not in AGENT_INTERFACE_NAMES:
        errors.append("agent must be a known deterministic interface")
    if not str(record.get("agent_run_id") or ""):
        errors.append("agent_run_id is required")
    if not str(record.get("subject_type") or ""):
        errors.append("subject_type is required")
    if not isinstance(record.get("evidence_refs"), list):
        errors.append("evidence_refs must be an array")
    if record.get("redacted") is not True:
        errors.append("redacted must be true")
    if record.get("external_llm_called") is not False:
        errors.append("deterministic interface must not call an external LLM")
    return {"valid": not errors, "errors": errors}
