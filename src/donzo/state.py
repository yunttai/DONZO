from __future__ import annotations

from pathlib import Path
from typing import Any

from donzo.models import now_utc, stable_id
from donzo.runner import CommandPlan
from donzo.storage.jsonl import write_json


def build_run_state(
    *,
    program: str,
    scope_file: str,
    profile: str,
    execute: bool,
    output_dir: Path,
    plans: list[CommandPlan],
    tool_preflight: dict[str, Any],
) -> dict[str, Any]:
    started_at = now_utc()
    return {
        "run_id": stable_id("run", program, scope_file, profile, output_dir, started_at),
        "program": program,
        "scope_file": scope_file,
        "profile": profile,
        "execute": execute,
        "status": "initialized",
        "phase": "preflight",
        "started_at": started_at,
        "updated_at": started_at,
        "completed_at": None,
        "tool_preflight_ok": bool(tool_preflight.get("ok")),
        "tool_preflight_path": str(output_dir / "tool-preflight.json"),
        "plans": [plan_state(item) for item in plans],
        "counters": {},
        "artifacts": {
            "plan": str(output_dir / "plan.json"),
            "tool_preflight": str(output_dir / "tool-preflight.json"),
            "summary": str(output_dir / "summary.json"),
            "report": str(output_dir / "report.md"),
        },
        "error": None,
    }


def plan_state(plan: CommandPlan) -> dict[str, Any]:
    return {
        "name": plan.name,
        "allowed": plan.allowed,
        "dry_run": plan.dry_run,
        "output_path": str(plan.output_path),
        "reasons": plan.reasons,
    }


def transition_run_state(
    state: dict[str, Any],
    *,
    status: str,
    phase: str,
    counters: dict[str, Any] | None = None,
    artifacts: dict[str, Any] | None = None,
    error: str | None = None,
    completed: bool = False,
) -> dict[str, Any]:
    updated = dict(state)
    updated["status"] = status
    updated["phase"] = phase
    updated["updated_at"] = now_utc()
    if completed:
        updated["completed_at"] = updated["updated_at"]
    if counters is not None:
        updated["counters"] = counters
    if artifacts:
        merged = dict(updated.get("artifacts") or {})
        merged.update(artifacts)
        updated["artifacts"] = merged
    if error:
        updated["error"] = error
    return updated


def write_run_state(output_dir: Path, state: dict[str, Any]) -> None:
    write_json(output_dir / "state.json", state)
