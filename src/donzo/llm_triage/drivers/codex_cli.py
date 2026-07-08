from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from donzo.config import LLMConfig, LLMDriverConfig
from donzo.llm_triage.drivers.base import (
    LLMCallError,
    LLMSchemaError,
    TribunalDriver,
    validate_verdict_mapping,
    verdict_from_mapping,
)
from donzo.llm_triage.schema import (
    FINDING_VERDICT_JSON_SCHEMA,
    EvidencePack,
    FindingVerdict,
)


@dataclass(frozen=True)
class CodexPreflight:
    command: str
    version: str
    doctor: str


@dataclass(frozen=True)
class CodexJobPaths:
    output_dir: Path
    job_dir: Path
    workspace_dir: Path
    evidence_path: Path
    schema_path: Path
    prompt_path: Path
    stdout_path: Path
    stderr_path: Path
    verdict_path: Path
    audit_path: Path
    cache_path: Path


class CodexCliDriver(TribunalDriver):
    name = "codex_cli"

    def __init__(self, config: LLMConfig, *, allow_external_llm: bool = False) -> None:
        self.config = config
        self.allow_external_llm = allow_external_llm
        self.driver_config = driver_config(config)

    def judge(self, evidence_pack: EvidencePack) -> FindingVerdict:
        if not self.allow_external_llm:
            raise LLMCallError("external LLM execution was not explicitly allowed")
        if not self.driver_config.enabled:
            raise LLMCallError("codex_cli driver is disabled")
        if not self.driver_config.json_schema_required:
            raise LLMCallError("codex_cli requires json_schema_required=true")

        cache_key = stable_hash(
            {
                "driver": self.name,
                "model": self.driver_config.model,
                "schema": FINDING_VERDICT_JSON_SCHEMA,
                "evidence_pack": evidence_pack.to_dict(),
            }
        )
        paths = build_job_paths(self.driver_config.output_dir, cache_key)
        if verdict := load_cached_verdict(paths.cache_path):
            return verdict

        initial_prompt = build_prompt(evidence_pack)
        write_job_inputs(paths, evidence_pack, initial_prompt)
        try:
            preflight = self.preflight()
        except LLMCallError as exc:
            append_audit(
                paths.audit_path,
                audit_record(
                    status="failed",
                    attempt=0,
                    paths=paths,
                    preflight=CodexPreflight(
                        command=self.driver_config.command or "codex",
                        version="",
                        doctor="",
                    ),
                    stage="finding_triage",
                    input_payload=evidence_pack.to_dict(),
                    prompt_hash=stable_hash({"prompt": initial_prompt}),
                    started_at=now_iso(),
                    error=str(exc),
                ),
            )
            raise

        last_call_error: LLMCallError | None = None
        last_schema_error: LLMSchemaError | None = None
        for attempt in range(1, self.driver_config.max_attempts + 1):
            prompt = build_prompt(
                evidence_pack,
                repair_error=str(last_schema_error) if last_schema_error else "",
            )
            paths.prompt_path.write_text(prompt, encoding="utf-8")
            prompt_hash = stable_hash({"prompt": prompt})
            started_at = now_iso()
            try:
                data = self.run_attempt(paths, prompt, preflight.command)
                validate_verdict_mapping(data)
            except LLMSchemaError as exc:
                last_schema_error = exc
                append_audit(
                    paths.audit_path,
                    audit_record(
                        status="schema_invalid",
                        attempt=attempt,
                        paths=paths,
                        preflight=preflight,
                        stage="finding_triage",
                        input_payload=evidence_pack.to_dict(),
                        prompt_hash=prompt_hash,
                        started_at=started_at,
                        error=str(exc),
                    ),
                )
                continue
            except LLMCallError as exc:
                last_call_error = exc
                append_audit(
                    paths.audit_path,
                    audit_record(
                        status="failed",
                        attempt=attempt,
                        paths=paths,
                        preflight=preflight,
                        stage="finding_triage",
                        input_payload=evidence_pack.to_dict(),
                        prompt_hash=prompt_hash,
                        started_at=started_at,
                        error=str(exc),
                    ),
                )
                continue

            verdict = verdict_from_mapping(data)
            paths.cache_path.parent.mkdir(parents=True, exist_ok=True)
            paths.cache_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            append_audit(
                paths.audit_path,
                audit_record(
                    status="succeeded",
                    attempt=attempt,
                    paths=paths,
                    preflight=preflight,
                    stage="finding_triage",
                    input_payload=evidence_pack.to_dict(),
                    prompt_hash=prompt_hash,
                    started_at=started_at,
                    error=None,
                ),
            )
            return verdict

        if last_schema_error is not None:
            raise LLMSchemaError(
                "codex_cli output failed schema validation after "
                f"{self.driver_config.max_attempts} attempt(s): {last_schema_error}"
            )
        if last_call_error is not None:
            raise LLMCallError(
                "codex_cli execution failed after "
                f"{self.driver_config.max_attempts} attempt(s): {last_call_error}"
            )
        raise LLMCallError("codex_cli execution failed without an error detail")

    def structured_json(
        self,
        *,
        stage: str,
        payload: dict[str, Any],
        output_schema: dict[str, Any],
        prompt: str,
    ) -> dict[str, Any]:
        if not self.allow_external_llm:
            raise LLMCallError("external LLM execution was not explicitly allowed")
        if not self.driver_config.enabled:
            raise LLMCallError("codex_cli driver is disabled")
        if not self.driver_config.json_schema_required:
            raise LLMCallError("codex_cli requires json_schema_required=true")

        cache_key = stable_hash(
            {
                "driver": self.name,
                "stage": stage,
                "model": self.driver_config.model,
                "schema": output_schema,
                "payload": payload,
            }
        )
        paths = build_job_paths(self.driver_config.output_dir, cache_key)
        if cached := load_cached_json(paths.cache_path, output_schema):
            return cached

        initial_prompt = build_structured_prompt(stage, prompt, payload=payload)
        write_structured_inputs(paths, payload, output_schema, initial_prompt)
        try:
            preflight = self.preflight()
        except LLMCallError as exc:
            append_audit(
                paths.audit_path,
                audit_record(
                    status="failed",
                    attempt=0,
                    paths=paths,
                    preflight=CodexPreflight(
                        command=self.driver_config.command or "codex",
                        version="",
                        doctor="",
                    ),
                    stage=stage,
                    input_payload=payload,
                    prompt_hash=stable_hash({"prompt": initial_prompt}),
                    started_at=now_iso(),
                    error=str(exc),
                ),
            )
            raise

        last_call_error: LLMCallError | None = None
        last_schema_error: LLMSchemaError | None = None
        for attempt in range(1, self.driver_config.max_attempts + 1):
            stage_prompt = build_structured_prompt(
                stage,
                prompt,
                payload=payload,
                repair_error=str(last_schema_error) if last_schema_error else "",
            )
            paths.prompt_path.write_text(stage_prompt, encoding="utf-8")
            prompt_hash = stable_hash({"prompt": stage_prompt})
            started_at = now_iso()
            try:
                data = self.run_structured_attempt(
                    paths,
                    stage_prompt,
                    preflight.command,
                    output_schema,
                )
            except LLMSchemaError as exc:
                last_schema_error = exc
                append_audit(
                    paths.audit_path,
                    audit_record(
                        status="schema_invalid",
                        attempt=attempt,
                        paths=paths,
                        preflight=preflight,
                        stage=stage,
                        input_payload=payload,
                        prompt_hash=prompt_hash,
                        started_at=started_at,
                        error=str(exc),
                    ),
                )
                continue
            except LLMCallError as exc:
                last_call_error = exc
                append_audit(
                    paths.audit_path,
                    audit_record(
                        status="failed",
                        attempt=attempt,
                        paths=paths,
                        preflight=preflight,
                        stage=stage,
                        input_payload=payload,
                        prompt_hash=prompt_hash,
                        started_at=started_at,
                        error=str(exc),
                    ),
                )
                continue

            paths.cache_path.parent.mkdir(parents=True, exist_ok=True)
            paths.cache_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            append_audit(
                paths.audit_path,
                audit_record(
                    status="succeeded",
                    attempt=attempt,
                    paths=paths,
                    preflight=preflight,
                    stage=stage,
                    input_payload=payload,
                    prompt_hash=prompt_hash,
                    started_at=started_at,
                    error=None,
                ),
            )
            return data

        if last_schema_error is not None:
            raise LLMSchemaError(
                f"{stage} output failed schema validation after "
                f"{self.driver_config.max_attempts} attempt(s): {last_schema_error}"
            )
        if last_call_error is not None:
            raise LLMCallError(
                f"{stage} execution failed after "
                f"{self.driver_config.max_attempts} attempt(s): {last_call_error}"
            )
        raise LLMCallError(f"{stage} execution failed without an error detail")

    def preflight(self) -> CodexPreflight:
        command = resolve_command(self.driver_config.command)
        version = run_preflight_command([command, "--version"], "codex --version")
        doctor = run_preflight_command([command, "doctor"], "codex doctor", required=False)
        return CodexPreflight(command=command, version=version, doctor=doctor)

    def run_attempt(
        self,
        paths: CodexJobPaths,
        prompt: str,
        command: str,
    ) -> dict[str, Any]:
        args = build_codex_exec_args(command, paths, self.driver_config)
        try:
            completed = subprocess.run(
                args,
                input=prompt,
                text=True,
                capture_output=True,
                timeout=self.driver_config.timeout_seconds,
                check=False,
            )
        except OSError as exc:
            raise LLMCallError(f"codex_cli execution failed: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise LLMCallError("codex_cli execution timed out") from exc

        paths.stdout_path.write_text(completed.stdout, encoding="utf-8")
        paths.stderr_path.write_text(completed.stderr, encoding="utf-8")
        if completed.returncode != 0:
            message = completed.stderr.strip() or completed.stdout.strip()
            raise LLMCallError(f"codex_cli returned {completed.returncode}: {message}")
        return load_verdict_output(paths.verdict_path, completed.stdout)

    def run_structured_attempt(
        self,
        paths: CodexJobPaths,
        prompt: str,
        command: str,
        output_schema: dict[str, Any],
    ) -> dict[str, Any]:
        args = build_codex_exec_args(command, paths, self.driver_config)
        try:
            completed = subprocess.run(
                args,
                input=prompt,
                text=True,
                capture_output=True,
                timeout=self.driver_config.timeout_seconds,
                check=False,
            )
        except OSError as exc:
            raise LLMCallError(f"codex_cli execution failed: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise LLMCallError("codex_cli execution timed out") from exc

        paths.stdout_path.write_text(completed.stdout, encoding="utf-8")
        paths.stderr_path.write_text(completed.stderr, encoding="utf-8")
        if completed.returncode != 0:
            message = completed.stderr.strip() or completed.stdout.strip()
            raise LLMCallError(f"codex_cli returned {completed.returncode}: {message}")
        return load_structured_output(paths.verdict_path, completed.stdout, output_schema)


def driver_config(config: LLMConfig) -> LLMDriverConfig:
    configured = (config.drivers or {}).get("codex_cli")
    if configured is not None:
        return configured
    return LLMDriverConfig(enabled=False, command="codex")


def resolve_command(command: str) -> str:
    configured = command.strip() or "codex"
    codex_bin = os.environ.get("CODEX_BIN")
    if codex_bin and Path(codex_bin).expanduser().exists():
        return str(Path(codex_bin).expanduser())
    if Path(configured).expanduser().exists():
        return str(Path(configured).expanduser())
    resolved = shutil.which(configured)
    if resolved:
        return resolved
    if codex_bin:
        raise LLMCallError(
            f"codex_cli command not found: {configured}; CODEX_BIN is invalid: {codex_bin}"
        )
    raise LLMCallError(f"codex_cli command not found: {configured}")


def run_preflight_command(args: list[str], label: str, *, required: bool = True) -> str:
    try:
        completed = subprocess.run(
            args,
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
    except OSError as exc:
        raise LLMCallError(f"{label} failed: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise LLMCallError(f"{label} timed out") from exc
    output = (completed.stdout.strip() or completed.stderr.strip()).strip()
    if completed.returncode != 0:
        if not required:
            return f"{label} returned {completed.returncode}: {output}"
        raise LLMCallError(f"{label} returned {completed.returncode}: {output}")
    return output


def build_codex_exec_args(
    command: str,
    paths: CodexJobPaths,
    config: LLMDriverConfig,
) -> list[str]:
    args = [
        command,
        "exec",
        "--cd",
        str(paths.workspace_dir),
        "--sandbox",
        config.sandbox,
        "--output-schema",
        str(paths.schema_path),
        "--output-last-message",
        str(paths.verdict_path),
        "--skip-git-repo-check",
    ]
    if config.json_events:
        args.append("--json")
    if config.ignore_user_config:
        args.append("--ignore-user-config")
    if config.ignore_rules:
        args.append("--ignore-rules")
    if config.strict_config:
        args.append("--strict-config")
    if config.model and config.model != "default":
        args.extend(["--model", config.model])
    if config.model_reasoning_effort:
        args.extend(
            [
                "--config",
                f'model_reasoning_effort="{config.model_reasoning_effort}"',
            ]
        )
    args.append("-")
    return args


def build_job_paths(output_dir: str, cache_key: str) -> CodexJobPaths:
    root = Path(output_dir)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    job_id = f"{timestamp}-{cache_key[:12]}-{uuid.uuid4().hex[:8]}"
    job_dir = root / "jobs" / job_id
    workspace_dir = job_dir / "workspace"
    return CodexJobPaths(
        output_dir=root,
        job_dir=job_dir,
        workspace_dir=workspace_dir,
        evidence_path=workspace_dir / "evidence_pack.redacted.json",
        schema_path=workspace_dir / "schema.json",
        prompt_path=job_dir / "prompt.md",
        stdout_path=job_dir / "stdout.jsonl",
        stderr_path=job_dir / "stderr.txt",
        verdict_path=job_dir / "verdict.json",
        audit_path=root / "audit.jsonl",
        cache_path=root / "cache" / f"{cache_key}.json",
    )


def write_job_inputs(paths: CodexJobPaths, evidence_pack: EvidencePack, prompt: str) -> None:
    paths.workspace_dir.mkdir(parents=True, exist_ok=True)
    paths.evidence_path.write_text(
        json.dumps(evidence_pack.to_dict(), ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    paths.schema_path.write_text(
        json.dumps(FINDING_VERDICT_JSON_SCHEMA, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    paths.prompt_path.write_text(prompt, encoding="utf-8")


def write_structured_inputs(
    paths: CodexJobPaths,
    payload: dict[str, Any],
    output_schema: dict[str, Any],
    prompt: str,
) -> None:
    paths.workspace_dir.mkdir(parents=True, exist_ok=True)
    paths.evidence_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    paths.schema_path.write_text(
        json.dumps(output_schema, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    paths.prompt_path.write_text(prompt, encoding="utf-8")


def load_cached_verdict(path: Path) -> FindingVerdict | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        validate_verdict_mapping(data)
    except (OSError, json.JSONDecodeError, LLMSchemaError):
        return None
    return verdict_from_mapping(data)


def load_cached_json(path: Path, output_schema: dict[str, Any]) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        validate_json_schema(data, output_schema)
    except (OSError, json.JSONDecodeError, LLMSchemaError):
        return None
    return data


def load_verdict_output(path: Path, stdout: str) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8").strip() if path.exists() else stdout.strip()
    if not raw:
        raise LLMSchemaError("codex_cli did not write a verdict JSON object")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = extract_json_object(raw)
    if not isinstance(data, dict):
        raise LLMSchemaError("codex_cli verdict JSON was not an object")
    validate_verdict_mapping(data)
    return data


def load_structured_output(
    path: Path,
    stdout: str,
    output_schema: dict[str, Any],
) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8").strip() if path.exists() else stdout.strip()
    if not raw:
        raise LLMSchemaError("codex_cli did not write a JSON object")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = extract_json_object(raw)
    if not isinstance(data, dict):
        raise LLMSchemaError("codex_cli JSON output was not an object")
    validate_json_schema(data, output_schema)
    return data


def build_prompt(evidence_pack: EvidencePack, *, repair_error: str = "") -> str:
    repair = ""
    if repair_error:
        repair = (
            "\nPrevious output failed local schema validation. "
            f"Repair the final JSON only. Error: {repair_error}\n"
        )
    return (
        "You are DONZO's mandatory external LLM security judge for authorized "
        "black-box bug bounty triage.\n\n"
        "Read ./evidence_pack.redacted.json. Return only the JSON object required "
        "by ./schema.json. The CLI invocation also enforces --output-schema.\n\n"
        "Do not run scans or commands. Do not suggest exploit execution, secret "
        "validation, subdomain takeover claims, destructive testing, credential "
        "attacks, or automatic report submission. If evidence is insufficient, "
        "use needs_manual_review or likely_false_positive.\n"
        f"{repair}\n"
        "Evidence pack summary:\n"
        f"{json.dumps(evidence_pack.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)}\n"
    )


def build_structured_prompt(
    stage: str,
    prompt: str,
    *,
    payload: dict[str, Any],
    repair_error: str = "",
) -> str:
    repair = ""
    if repair_error:
        repair = (
            "\nPrevious output failed local schema validation. "
            f"Repair the final JSON only. Error: {repair_error}\n"
        )
    return (
        f"You are DONZO's mandatory external LLM stage: {stage}.\n\n"
        "Read ./evidence_pack.redacted.json. Return only the JSON object required "
        "by ./schema.json. The CLI invocation also enforces --output-schema.\n\n"
        "Do not run scans or commands. Do not suggest exploit execution, secret "
        "validation, subdomain takeover claims, destructive testing, credential "
        "attacks, or automatic report submission. Keep outputs suitable for human "
        "manual review.\n"
        f"{repair}\n"
        f"{prompt}\n\n"
        "Redacted input payload:\n"
        f"{json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)}\n"
    )


def validate_json_schema(data: dict[str, Any], output_schema: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(output_schema).iter_errors(data),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        path = ".".join(str(item) for item in first.absolute_path) or "<root>"
        raise LLMSchemaError(f"structured output schema invalid at {path}: {first.message}")


def extract_json_object(text: str) -> dict[str, Any]:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise LLMSchemaError("codex_cli response did not contain a JSON object")
    try:
        data = json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise LLMSchemaError(f"codex_cli response was not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise LLMSchemaError("codex_cli response JSON was not an object")
    return data


def audit_record(
    *,
    status: str,
    attempt: int,
    paths: CodexJobPaths,
    preflight: CodexPreflight,
    stage: str,
    input_payload: dict[str, Any],
    prompt_hash: str,
    started_at: str,
    error: str | None,
) -> dict[str, Any]:
    stdout_events = parse_jsonl_events(paths.stdout_path)
    return {
        "job_id": paths.job_dir.name,
        "stage": stage,
        "driver": "codex_cli",
        "status": status,
        "attempt": attempt,
        "started_at": started_at,
        "finished_at": now_iso(),
        "input_hash": stable_hash({"input": input_payload}),
        "prompt_hash": prompt_hash,
        "schema_hash": stable_hash(FINDING_VERDICT_JSON_SCHEMA),
        "model": driver_model_label(preflight),
        "codex_version": preflight.version,
        "codex_doctor": preflight.doctor,
        "command": "codex exec --json --sandbox read-only --output-schema",
        "job_dir": str(paths.job_dir),
        "stdout_jsonl_path": str(paths.stdout_path),
        "stderr_path": str(paths.stderr_path),
        "final_output_path": str(paths.verdict_path),
        "thread_id": stdout_events.get("thread_id"),
        "usage": stdout_events.get("usage"),
        "error": error,
    }


def append_audit(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
        handle.write("\n")
    record_sqlite_job(path.with_name("jobs.sqlite"), record)


def record_sqlite_job(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS llm_jobs (
                job_id TEXT PRIMARY KEY,
                stage TEXT NOT NULL,
                input_hash TEXT NOT NULL,
                prompt_hash TEXT NOT NULL,
                schema_hash TEXT NOT NULL,
                model TEXT,
                codex_version TEXT,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                verdict_path TEXT,
                error_message TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS llm_attempts (
                attempt_id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL,
                attempt INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                stdout_jsonl_path TEXT,
                stderr_path TEXT,
                final_output_path TEXT,
                thread_id TEXT,
                usage_json TEXT,
                error_type TEXT,
                error_message TEXT,
                FOREIGN KEY(job_id) REFERENCES llm_jobs(job_id)
            )
            """
        )
        connection.execute(
            """
            INSERT INTO llm_jobs (
                job_id,
                stage,
                input_hash,
                prompt_hash,
                schema_hash,
                model,
                codex_version,
                status,
                attempts,
                created_at,
                updated_at,
                verdict_path,
                error_message
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(job_id) DO UPDATE SET
                prompt_hash = excluded.prompt_hash,
                status = excluded.status,
                attempts = excluded.attempts,
                updated_at = excluded.updated_at,
                verdict_path = excluded.verdict_path,
                error_message = excluded.error_message
            """,
            (
                record["job_id"],
                record["stage"],
                record["input_hash"],
                record["prompt_hash"],
                record["schema_hash"],
                record["model"],
                record["codex_version"],
                record["status"],
                int(record["attempt"]),
                record["started_at"],
                record["finished_at"],
                record["final_output_path"],
                record["error"],
            ),
        )
        connection.execute(
            """
            INSERT OR REPLACE INTO llm_attempts (
                attempt_id,
                job_id,
                attempt,
                started_at,
                finished_at,
                stdout_jsonl_path,
                stderr_path,
                final_output_path,
                thread_id,
                usage_json,
                error_type,
                error_message
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"{record['job_id']}:{record['attempt']}:{record['status']}",
                record["job_id"],
                int(record["attempt"]),
                record["started_at"],
                record["finished_at"],
                record["stdout_jsonl_path"],
                record["stderr_path"],
                record["final_output_path"],
                record["thread_id"],
                json.dumps(record["usage"], sort_keys=True) if record["usage"] else None,
                record["status"],
                record["error"],
            ),
        )


def parse_jsonl_events(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    thread_id = None
    usage = None
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        thread_id = thread_id or event.get("thread_id") or event.get("threadId")
        if event.get("type") == "thread.started" and isinstance(event.get("thread"), dict):
            thread_id = thread_id or event["thread"].get("id")
        usage = event.get("usage") or usage
        if isinstance(event.get("turn"), dict):
            usage = event["turn"].get("usage") or usage
    return {"thread_id": thread_id, "usage": usage}


def stable_hash(data: Any) -> str:
    encoded = json.dumps(data, ensure_ascii=False, sort_keys=True, default=str).encode()
    return sha256(encoded).hexdigest()


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def driver_model_label(preflight: CodexPreflight) -> str:
    return preflight.version.splitlines()[0] if preflight.version else "codex_cli"
