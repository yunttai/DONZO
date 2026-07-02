from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from donzo.config import ScopeConfig
from donzo.scope import ScopeDecision


@dataclass(frozen=True)
class CommandPlan:
    name: str
    argv: list[str]
    output_path: Path
    allowed: bool
    dry_run: bool
    reasons: list[str] = field(default_factory=list)
    target_decisions: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "argv": self.argv,
            "output_path": str(self.output_path),
            "allowed": self.allowed,
            "dry_run": self.dry_run,
            "reasons": self.reasons,
            "target_decisions": self.target_decisions,
        }


@dataclass(frozen=True)
class CommandResult:
    plan: CommandPlan
    returncode: int | None
    stdout_path: str | None = None
    stderr_path: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan": self.plan.to_dict(),
            "returncode": self.returncode,
            "stdout_path": self.stdout_path,
            "stderr_path": self.stderr_path,
            "error": self.error,
        }


def build_command_plan(
    *,
    config: ScopeConfig,
    name: str,
    argv: list[str],
    output_path: Path,
    targets: list[str] | None = None,
    required_policy_flag: str | None = None,
    test_type: str | None = None,
    dry_run: bool = True,
) -> CommandPlan:
    reasons: list[str] = []
    decisions: list[ScopeDecision] = []
    if config.mode != "authorized-only":
        reasons.append("mode_not_authorized_only")
    if required_policy_flag and not config.policy.is_enabled(required_policy_flag):
        reasons.append(f"disabled_by_scan_policy:{required_policy_flag}")
    if test_type and not config.policy.is_test_type_allowed(test_type):
        reasons.append(f"blocked_test_type:{test_type}")
    for target in targets or []:
        decision = config.scope.decide(target)
        decisions.append(decision)
        if not decision.allowed:
            reasons.append(f"target_not_allowed:{target}")
    return CommandPlan(
        name=name,
        argv=argv,
        output_path=output_path,
        allowed=not reasons,
        dry_run=dry_run,
        reasons=reasons or ["allowed"],
        target_decisions=[
            {
                "target": decision.target,
                "allowed": decision.allowed,
                "reasons": decision.reasons,
                "matched_in_scope": decision.matched_in_scope,
                "matched_out_of_scope": decision.matched_out_of_scope,
            }
            for decision in decisions
        ],
    )


def run_command_plan(
    plan: CommandPlan,
    *,
    execute: bool = False,
    timeout_seconds: float = 60,
) -> CommandResult:
    if not plan.allowed:
        return CommandResult(plan=plan, returncode=None, error="command plan is not allowed")
    if plan.dry_run or not execute:
        return CommandResult(plan=plan, returncode=None, error="dry_run")

    plan.output_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path = plan.output_path.with_suffix(plan.output_path.suffix + ".stderr")
    try:
        completed = subprocess.run(
            plan.argv,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except OSError as exc:
        return CommandResult(plan=plan, returncode=None, error=str(exc))
    except subprocess.TimeoutExpired:
        return CommandResult(plan=plan, returncode=None, error="timeout")

    plan.output_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")
    return CommandResult(
        plan=plan,
        returncode=completed.returncode,
        stdout_path=str(plan.output_path),
        stderr_path=str(stderr_path),
        error=None if completed.returncode == 0 else "nonzero_exit",
    )
