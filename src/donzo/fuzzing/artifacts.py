from __future__ import annotations

from pathlib import Path
from typing import Any

from donzo.fuzzing.candidate_selector import build_fuzz_candidates
from donzo.fuzzing.fuzz_plan import build_fuzz_oracle_templates, build_fuzz_plans
from donzo.fuzzing.models import ARTIFACT_PATHS
from donzo.fuzzing.probe_generator import build_safe_probes
from donzo.storage.jsonl import write_jsonl


def build_fuzz_artifacts(
    *,
    api_endpoint_models: list[dict[str, Any]],
    parameter_classifications: list[dict[str, Any]] | None = None,
    schema_diffs: list[dict[str, Any]] | None = None,
    actor_model: dict[str, Any] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    candidates = build_fuzz_candidates(
        api_endpoint_models,
        parameter_classifications=parameter_classifications,
        schema_diffs=schema_diffs,
        actor_model=actor_model,
    )
    plans = build_fuzz_plans(candidates, actor_model=actor_model)
    probes = build_safe_probes(plans)
    templates = build_fuzz_oracle_templates(plans)
    return {
        "fuzz_candidates": candidates,
        "fuzz_plan": plans,
        "safe_probes": probes,
        "probe_plan": probes,
        "oracle_templates": templates,
        "baseline_results": [],
        "fuzz_results": [],
        "probe_results": [],
        "oast_interactions": [],
        "state_readback_results": [],
        "readback_results": [],
        "oracle_verdicts": [],
        "false_positive_analysis": [],
        "confirmed_findings": [],
        "regression_cases": [],
    }


def write_fuzz_artifacts(
    output_dir: Path,
    artifacts: dict[str, list[dict[str, Any]]],
    *,
    include_execution_placeholders: bool = True,
) -> None:
    write_jsonl(
        output_dir / "planning" / "fuzz-candidates.jsonl", artifacts.get("fuzz_candidates", [])
    )
    for key, relative_path in ARTIFACT_PATHS.items():
        if not include_execution_placeholders and key not in {
            "fuzz_plan",
            "safe_probes",
            "oracle_templates",
        }:
            continue
        write_jsonl(output_dir / relative_path, artifacts.get(key, []))
