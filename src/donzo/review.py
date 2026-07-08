from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from donzo.storage.jsonl import load_json_records, write_json

IMPORTANT_ARTIFACTS = (
    "report.md",
    "summary.json",
    "verification-summary.json",
    "verification-debug.md",
    "review.md",
    "review-queue.json",
    "llm-triage-queue.json",
    "ranked.jsonl",
    "clusters.jsonl",
    "cluster-evidence-packs.jsonl",
    "llm-triage-input-packs.jsonl",
    "candidates-verified.jsonl",
    "candidates-filtered.jsonl",
    "verification-probes.jsonl",
    "removed-out-of-scope.json",
)


def write_review_artifacts(run_dir: Path, *, limit: int = 10) -> dict[str, str]:
    summary = build_run_review_summary(run_dir)
    queue = build_review_queue(run_dir, include_filtered=True, limit=limit)
    triage_queue = build_llm_triage_queue(run_dir, limit=limit)
    review_markdown = render_run_review_markdown(summary, queue, triage_queue)
    debug_markdown = render_verification_debug_markdown(run_dir, limit=limit)

    write_json(run_dir / "review-summary.json", summary)
    write_json(run_dir / "review-queue.json", queue)
    write_json(run_dir / "llm-triage-queue.json", triage_queue)
    (run_dir / "review.md").write_text(review_markdown, encoding="utf-8")
    (run_dir / "verification-debug.md").write_text(debug_markdown, encoding="utf-8")
    summary["artifacts"] = existing_artifacts(run_dir)
    write_json(run_dir / "review-summary.json", summary)
    return {
        "review_summary": str(run_dir / "review-summary.json"),
        "review_queue": str(run_dir / "review-queue.json"),
        "llm_triage_queue": str(run_dir / "llm-triage-queue.json"),
        "review_markdown": str(run_dir / "review.md"),
        "verification_debug": str(run_dir / "verification-debug.md"),
    }


def build_run_review_summary(run_dir: Path) -> dict[str, Any]:
    summary = load_json_object(run_dir / "summary.json")
    verification = load_json_object(run_dir / "verification-summary.json")
    recon_result = load_json_object(run_dir / "recon-result.json")
    tool_preflight = load_json_object(run_dir / "tool-preflight.json")
    ranked = load_records_if_exists(run_dir / "ranked.jsonl")
    verified = load_records_if_exists(run_dir / "candidates-verified.jsonl")
    filtered = load_records_if_exists(run_dir / "candidates-filtered.jsonl")
    clusters = load_records_if_exists(run_dir / "clusters.jsonl")

    results = summary.get("results") if isinstance(summary.get("results"), list) else []
    skipped_optional = [
        command_result_name(item)
        for item in results
        if item.get("skipped") or item.get("error") == "optional_tool_missing"
    ]
    failed_commands = [
        {
            "name": command_result_name(item),
            "error": item.get("error"),
            "returncode": item.get("returncode"),
        }
        for item in results
        if item.get("error")
        and not item.get("skipped")
        and item.get("error") != "optional_tool_missing"
    ]

    status = review_status(summary, ranked, verified, filtered)
    return {
        "run_dir": str(run_dir),
        "program": recon_result.get("program") or "",
        "profile": summary.get("profile") or "",
        "scope_file": recon_result.get("scope_file") or "",
        "status": status,
        "counts": {
            "assets": int(summary.get("assets") or 0),
            "services": int(summary.get("services") or 0),
            "endpoints": int(summary.get("endpoints") or 0),
            "raw_candidates": int(summary.get("candidates") or 0),
            "reviewable_candidates": int(summary.get("reviewable_candidates") or 0),
            "filtered_candidates": int(summary.get("filtered_candidates") or 0),
            "ranked": len(ranked),
            "clusters": len(clusters),
            "removed": int(summary.get("removed") or 0),
        },
        "verification": verification,
        "filter_reason_counts": verification.get("filter_reason_counts") or {},
        "tool_preflight": {
            "ok": bool(tool_preflight.get("ok", True)),
            "missing_count": int(tool_preflight.get("missing_count") or 0),
            "tool_count": int(tool_preflight.get("tool_count") or 0),
            "skipped_optional": [name for name in skipped_optional if name],
            "failed_commands": failed_commands,
        },
        "artifacts": existing_artifacts(run_dir),
        "recommended_next_steps": recommended_next_steps(status, skipped_optional, filtered),
    }


def build_review_queue(
    run_dir: Path,
    *,
    include_filtered: bool = False,
    limit: int = 20,
) -> dict[str, Any]:
    ranked = load_records_if_exists(run_dir / "ranked.jsonl")
    clusters = load_records_if_exists(run_dir / "clusters.jsonl")
    filtered = load_records_if_exists(run_dir / "candidates-filtered.jsonl")
    packs = load_records_if_exists(run_dir / "cluster-evidence-packs.jsonl")
    pack_by_cluster = {
        str((pack.get("cluster") or {}).get("cluster_id") or ""): pack for pack in packs
    }

    entries: list[dict[str, Any]] = []
    for cluster in clusters[:limit]:
        cluster_id = str(cluster.get("cluster_id") or "")
        pack = pack_by_cluster.get(cluster_id)
        entries.append(
            {
                "kind": "cluster",
                "priority": cluster.get("priority") or "P3",
                "title": cluster.get("title") or "Candidate Cluster",
                "cluster_id": cluster_id,
                "candidate_type": cluster.get("cluster_type") or "",
                "count": int(cluster.get("count") or 0),
                "risk_score": int(cluster.get("risk_score") or 0),
                "targets": cluster.get("targets") or [],
                "evidence_pack": pack_path(run_dir, pack) if pack else None,
                "action": "manual_verify_cluster",
            }
        )

    remaining = max(0, limit - len(entries))
    for record in ranked[:remaining]:
        entries.append(review_entry_from_record(record, kind="candidate"))

    filtered_examples: list[dict[str, Any]] = []
    if include_filtered:
        filtered_examples = filtered_debug_examples(filtered, per_reason=3)

    return {
        "run_dir": str(run_dir),
        "reviewable_count": len(entries),
        "entries": entries[:limit],
        "filtered_examples": filtered_examples if include_filtered else [],
        "filter_reason_counts": dict(sorted(filter_reason_counter(filtered).items())),
    }


def build_llm_triage_queue(run_dir: Path, *, limit: int = 20) -> dict[str, Any]:
    pack_file = run_dir / "llm-triage-input-packs.jsonl"
    if not pack_file.exists():
        pack_file = run_dir / "cluster-evidence-packs.jsonl"
    packs = load_records_if_exists(pack_file)
    recon_result = load_json_object(run_dir / "recon-result.json")
    scope_file = str(recon_result.get("scope_file") or "")
    queue: list[dict[str, Any]] = []
    for pack in packs[:limit]:
        pack_id = str(pack.get("pack_id") or "")
        input_path = pack_path(run_dir, pack) or str(pack_file)
        output_path = run_dir / "llm-triage" / f"{pack_id or 'cluster'}.json"
        queue.append(
            {
                "stage": "cluster_triage",
                "pack_id": pack_id,
                "priority": ((pack.get("cluster") or {}).get("priority") or "P3"),
                "candidate_count": int(pack.get("candidate_count") or 0),
                "input": input_path,
                "output": str(output_path),
                "command": [
                    "donzo",
                    "clusters",
                    "triage",
                    "-c",
                    scope_file,
                    "-i",
                    input_path,
                    "-o",
                    str(output_path),
                    "--allow-external-llm",
                ],
            }
        )
    return {
        "run_dir": str(run_dir),
        "status": "ready" if queue else "empty",
        "reason": "" if queue else "no_llm_triage_input_packs",
        "queue_count": len(queue),
        "queue": queue,
    }


def render_run_review_markdown(
    summary: dict[str, Any],
    queue: dict[str, Any],
    triage_queue: dict[str, Any],
) -> str:
    counts = summary.get("counts") or {}
    lines = [
        "# DONZO Review Summary",
        "",
        f"- Run Dir: {summary.get('run_dir', '')}",
        f"- Program: {summary.get('program', '')}",
        f"- Profile: {summary.get('profile', '')}",
        f"- Status: {summary.get('status', '')}",
        "",
        "## Counts",
        "",
    ]
    for key in (
        "assets",
        "services",
        "endpoints",
        "raw_candidates",
        "reviewable_candidates",
        "filtered_candidates",
        "ranked",
        "clusters",
        "removed",
    ):
        lines.append(f"- {key.replace('_', ' ').title()}: {counts.get(key, 0)}")

    lines.extend(["", "## Next Steps", ""])
    for step in summary.get("recommended_next_steps") or []:
        lines.append(f"- {step}")

    lines.extend(["", "## Manual Review Queue", ""])
    entries = queue.get("entries") or []
    if not entries:
        lines.append("No reviewable candidates are currently queued.")
    for index, entry in enumerate(entries[:10], 1):
        lines.append(
            f"{index}. {entry.get('priority', 'P3')} {entry.get('title', 'Candidate')} "
            f"({entry.get('candidate_type', '')})"
        )
        for target in [str(item) for item in entry.get("targets") or []][:3]:
            lines.append(f"   - {target}")
        if entry.get("evidence_pack"):
            lines.append(f"   - Evidence Pack: {entry['evidence_pack']}")

    lines.extend(["", "## LLM Triage Queue", ""])
    if triage_queue.get("queue"):
        for item in triage_queue["queue"][:10]:
            lines.append(f"- {item.get('pack_id')}: {' '.join(item.get('command') or [])}")
    else:
        lines.append(f"- Empty: {triage_queue.get('reason', '')}")

    lines.extend(["", "## Filter Reasons", ""])
    filter_counts = summary.get("filter_reason_counts") or {}
    if not filter_counts:
        lines.append("- None")
    for reason, count in sorted(filter_counts.items()):
        lines.append(f"- {reason}: {count}")

    lines.extend(["", "## Artifacts", ""])
    for artifact in summary.get("artifacts") or []:
        lines.append(f"- {artifact}")
    lines.append("")
    return "\n".join(lines)


def render_verification_debug_markdown(run_dir: Path, *, limit: int = 10) -> str:
    summary = load_json_object(run_dir / "verification-summary.json")
    filtered = load_records_if_exists(run_dir / "candidates-filtered.jsonl")
    probes = load_records_if_exists(run_dir / "verification-probes.jsonl")
    probe_by_id = {str(item.get("probe_id") or ""): item for item in probes}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in filtered:
        grouped[str(item.get("filter_reason") or "unknown")].append(item)

    lines = [
        "# Verification Debug",
        "",
        f"- Run Dir: {run_dir}",
        f"- Input Candidates: {summary.get('input_candidates', 0)}",
        f"- Reviewable Candidates: {summary.get('reviewable_candidates', 0)}",
        f"- Filtered Candidates: {summary.get('filtered_candidates', 0)}",
        f"- HTTP Probes: {summary.get('probe_count', 0)}",
        "",
        "## Filter Groups",
        "",
    ]
    if not grouped:
        lines.append("No filtered candidates were recorded.")
    for reason, records in sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0])):
        lines.extend([f"### {reason}", "", f"- Count: {len(records)}", ""])
        for record in records[:limit]:
            probe_id = probe_id_from_record(record)
            probe = probe_by_id.get(probe_id, {})
            lines.append(f"- Target: {record.get('target', '')}")
            lines.append(f"  - Type: {record.get('candidate_type', '')}")
            if probe_id:
                lines.append(f"  - Probe: {probe_id}")
            status = probe.get("status_code") or verification_field(record, "status_code")
            if status:
                lines.append(f"  - Status: {status}")
            final_url = probe.get("final_url") or verification_field(record, "final_url")
            if final_url:
                lines.append(f"  - Final URL: {final_url}")
            title = probe.get("title") or verification_field(record, "title")
            if title:
                lines.append(f"  - Title: {title}")
        lines.append("")
    return "\n".join(lines)


def filtered_debug_examples(
    records: list[dict[str, Any]],
    *,
    per_reason: int,
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[str(record.get("filter_reason") or "unknown")].append(record)
    examples: list[dict[str, Any]] = []
    for reason, items in sorted(grouped.items()):
        for record in items[:per_reason]:
            examples.append(
                {
                    "filter_reason": reason,
                    "target": record.get("target") or "",
                    "candidate_type": record.get("candidate_type") or "",
                    "status_code": verification_field(record, "status_code"),
                    "title": verification_field(record, "title"),
                }
            )
    return examples


def review_entry_from_record(record: dict[str, Any], *, kind: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "priority": record.get("priority") or "P3",
        "title": record.get("title") or record.get("candidate_type") or "Candidate",
        "candidate_type": record.get("candidate_type") or "",
        "risk_score": int(record.get("risk_score") or 0),
        "confidence": record.get("confidence") or 0,
        "targets": [record.get("target") or record.get("url") or ""],
        "verification_status": record.get("verification_status") or "needs_manual_review",
        "action": "manual_verify_candidate",
    }


def review_status(
    summary: dict[str, Any],
    ranked: list[dict[str, Any]],
    verified: list[dict[str, Any]],
    filtered: list[dict[str, Any]],
) -> str:
    if ranked or verified:
        return "manual_review_required"
    if filtered or int(summary.get("candidates") or 0):
        return "empty_after_verification"
    return "no_candidates"


def recommended_next_steps(
    status: str,
    skipped_optional: list[str],
    filtered: list[dict[str, Any]],
) -> list[str]:
    steps: list[str] = []
    if status == "manual_review_required":
        steps.append("Open report.md and review the Manual Verification Queue.")
        steps.append("Run cluster triage only on selected evidence packs.")
    elif status == "empty_after_verification":
        steps.append("Open verification-debug.md to confirm why candidates were filtered.")
        steps.append("Inspect candidates-filtered.jsonl if you want raw per-target evidence.")
    else:
        steps.append("Inspect endpoints.jsonl and services.jsonl to confirm target coverage.")
    if skipped_optional:
        steps.append("Optional tools skipped: " + ", ".join(sorted(set(skipped_optional))))
    if filtered:
        steps.append("Use donzo review debug to regenerate a focused filter explanation.")
    return steps


def existing_artifacts(run_dir: Path) -> list[str]:
    return [str(run_dir / name) for name in IMPORTANT_ARTIFACTS if (run_dir / name).exists()]


def pack_path(run_dir: Path, pack: dict[str, Any] | None) -> str | None:
    if not pack:
        return None
    pack_id = str(pack.get("pack_id") or "")
    if not pack_id:
        return None
    for directory in ("llm-triage-input-packs", "cluster-evidence-packs"):
        path = run_dir / directory / f"{pack_id}.json"
        if path.exists():
            return str(path)
    return None


def command_result_name(result: dict[str, Any]) -> str:
    plan = result.get("plan") if isinstance(result.get("plan"), dict) else {}
    return str(plan.get("name") or result.get("name") or "")


def probe_id_from_record(record: dict[str, Any]) -> str:
    evidence = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
    verification = (
        evidence.get("verification") if isinstance(evidence.get("verification"), dict) else {}
    )
    return str(verification.get("probe_id") or "")


def verification_field(record: dict[str, Any], key: str) -> Any:
    evidence = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
    verification = (
        evidence.get("verification") if isinstance(evidence.get("verification"), dict) else {}
    )
    return verification.get(key)


def load_json_object(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    records = load_json_records(path)
    return records[0] if records else {}


def load_records_if_exists(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return load_json_records(path)


def filter_reason_counter(records: list[dict[str, Any]]) -> Counter[str]:
    return Counter(str(item.get("filter_reason") or "unknown") for item in records)
