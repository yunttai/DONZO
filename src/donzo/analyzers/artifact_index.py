from __future__ import annotations

from pathlib import Path
from typing import Any


def build_api_artifact_index(
    *,
    output_dir: Path,
    api_endpoint_models: list[dict[str, Any]],
    traffic: list[dict[str, Any]],
    request_schemas: list[dict[str, Any]],
    response_schemas: list[dict[str, Any]],
    parameter_classifications: list[dict[str, Any]],
    schema_diffs: list[dict[str, Any]],
    dependency_graph: dict[str, Any],
    handler_hypotheses: list[dict[str, Any]],
    security_invariants: list[dict[str, Any]],
    manual_test_plans: list[dict[str, Any]],
    oracle_templates: list[dict[str, Any]],
) -> dict[str, Any]:
    endpoint_ids = [str(item.get("endpoint_id") or "") for item in api_endpoint_models]
    return {
        "artifact_index_version": 1,
        "output_dir": str(output_dir),
        "counts": {
            "api_endpoint_models": len(api_endpoint_models),
            "traffic": len(traffic),
            "request_schemas": len(request_schemas),
            "response_schemas": len(response_schemas),
            "parameter_classifications": len(parameter_classifications),
            "schema_diffs": len(schema_diffs),
            "dependency_edges": len(dependency_graph.get("edges") or []),
            "handler_hypotheses": len(handler_hypotheses),
            "security_invariants": len(security_invariants),
            "manual_test_plans": len(manual_test_plans),
            "oracle_templates": len(oracle_templates),
        },
        "artifacts": {
            "traffic": "traffic.jsonl",
            "request_schemas": "request-schemas.jsonl",
            "response_schemas": "response-schemas.jsonl",
            "api_endpoints": "api-endpoints.jsonl",
            "parameter_classification": "parameter-classification.jsonl",
            "schema_diff": "schema-diff.jsonl",
            "api_dependency_graph": "api-dependency-graph.json",
            "api_sequences": "api-sequences.jsonl",
            "state_transitions": "state-transitions.jsonl",
            "handler_hypotheses": "handler-hypotheses.jsonl",
            "security_invariants": "security-invariants.jsonl",
            "manual_test_plans": "manual-test-plans.jsonl",
            "oracle_templates": "oracle-templates.jsonl",
        },
        "endpoint_artifacts": [
            endpoint_artifact_record(
                endpoint,
                request_schemas=request_schemas,
                response_schemas=response_schemas,
                parameter_classifications=parameter_classifications,
                schema_diffs=schema_diffs,
                handler_hypotheses=handler_hypotheses,
                security_invariants=security_invariants,
                manual_test_plans=manual_test_plans,
            )
            for endpoint in api_endpoint_models
        ],
        "endpoint_ids": endpoint_ids,
    }


def endpoint_artifact_record(
    endpoint: dict[str, Any],
    *,
    request_schemas: list[dict[str, Any]],
    response_schemas: list[dict[str, Any]],
    parameter_classifications: list[dict[str, Any]],
    schema_diffs: list[dict[str, Any]],
    handler_hypotheses: list[dict[str, Any]],
    security_invariants: list[dict[str, Any]],
    manual_test_plans: list[dict[str, Any]],
) -> dict[str, Any]:
    endpoint_id = str(endpoint.get("endpoint_id") or "")
    return {
        "endpoint_id": endpoint_id,
        "method": endpoint.get("method"),
        "origin": endpoint.get("origin"),
        "path_template": endpoint.get("path_template"),
        "related_artifacts": {
            "request_schema_ids": ids_for_endpoint(request_schemas, endpoint_id, "schema_id"),
            "response_schema_ids": ids_for_endpoint(response_schemas, endpoint_id, "schema_id"),
            "parameter_classification_ids": ids_for_endpoint(
                parameter_classifications,
                endpoint_id,
                "classification_id",
            ),
            "schema_diff_ids": [
                str(item.get("schema_diff_id") or "")
                for item in schema_diffs
                if item.get("read_endpoint") == endpoint_id
                or item.get("write_endpoint") == endpoint_id
            ],
            "handler_hypothesis_ids": ids_for_endpoint(
                handler_hypotheses,
                endpoint_id,
                "hypothesis_id",
            ),
            "security_invariant_ids": ids_for_endpoint(
                security_invariants,
                endpoint_id,
                "invariant_id",
            ),
            "manual_test_plan_ids": ids_for_endpoint(manual_test_plans, endpoint_id, "test_id"),
        },
    }


def ids_for_endpoint(records: list[dict[str, Any]], endpoint_id: str, id_field: str) -> list[str]:
    return [
        str(item.get(id_field) or "")
        for item in records
        if str(item.get("endpoint_id") or "") == endpoint_id and str(item.get(id_field) or "")
    ]
