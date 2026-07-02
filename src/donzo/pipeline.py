from __future__ import annotations

from pathlib import Path
from typing import Any

from donzo.candidates.basic import build_basic_candidates
from donzo.config import ScopeConfig
from donzo.dedupe import dedupe_records
from donzo.evidence import write_evidence_notes
from donzo.models import now_utc
from donzo.normalize.artifacts import (
    normalize_asset_lines,
    normalize_endpoint_records,
    normalize_finding_records,
    normalize_httpx_records,
)
from donzo.parameters import build_parameters_from_endpoints
from donzo.ranking import rank_records
from donzo.reporting.markdown import render_markdown_report
from donzo.runner import CommandPlan, build_command_plan, run_command_plan
from donzo.storage.jsonl import (
    load_json_records,
    load_jsonl_text,
    load_text_lines,
    write_json,
    write_jsonl,
)
from donzo.tools import check_tools, tool_binary


def run_fast_pipeline(
    *,
    config: ScopeConfig,
    output_dir: Path,
    execute: bool = False,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = output_dir / "raw"
    normalized_dir = output_dir / "normalized"
    derived_dir = output_dir / "derived"
    plan = build_fast_recon_plans(config=config, output_dir=output_dir, dry_run=not execute)
    if not execute:
        payload = {
            "profile": "fast",
            "execute": False,
            "plans": [item.to_dict() for item in plan],
        }
        write_json(output_dir / "plan.json", payload)
        return payload

    tool_status = check_tools([item.name for item in plan])
    missing = [item for item in tool_status if not item["available"]]
    if missing:
        payload = {
            "profile": "fast",
            "execute": True,
            "error": "missing_required_tools",
            "tools": tool_status,
            "plans": [item.to_dict() for item in plan],
        }
        write_json(output_dir / "run-error.json", payload)
        return payload

    results = []
    for item in plan:
        results.append(
            run_command_plan(
                item,
                execute=True,
                timeout_seconds=config.rate_limit.timeout_seconds * 30,
            ).to_dict()
        )
        if item.name == "httpx":
            write_live_urls_from_httpx(raw_dir / "httpx.jsonl", derived_dir / "live_urls.txt")

    assets = []
    services = []
    endpoints = []
    findings = []
    removed: list[dict[str, Any]] = []
    for asset_path, source in (
        (raw_dir / "subfinder.txt", "subfinder"),
        (raw_dir / "dnsx.txt", "dnsx"),
    ):
        if asset_path.exists():
            asset_records, removed_assets = normalize_asset_lines(
                load_text_lines(asset_path),
                config=config,
                source=source,
            )
            assets.extend(asset_records)
            removed.extend(removed_assets)
    httpx_path = raw_dir / "httpx.jsonl"
    if httpx_path.exists():
        services, removed_services = normalize_httpx_records(
            load_json_records(httpx_path),
            config=config,
        )
        removed.extend(removed_services)
        endpoints, removed_endpoints = normalize_endpoint_records(
            load_json_records(httpx_path),
            config=config,
            source="httpx",
        )
        removed.extend(removed_endpoints)
    katana_path = raw_dir / "katana.jsonl"
    if katana_path.exists():
        katana_endpoints, katana_removed = normalize_endpoint_records(
            load_json_records(katana_path),
            config=config,
            source="katana",
        )
        endpoints.extend(katana_endpoints)
        removed.extend(katana_removed)
    nuclei_path = raw_dir / "nuclei.jsonl"
    if nuclei_path.exists():
        findings, removed_findings = normalize_finding_records(
            load_json_records(nuclei_path),
            config=config,
        )
        removed.extend(removed_findings)

    assets = dedupe_records(assets)
    endpoints = dedupe_records(endpoints)
    params = dedupe_records(build_parameters_from_endpoints(endpoints))
    candidates = dedupe_records(build_basic_candidates(endpoints))
    findings = dedupe_records(findings)
    ranked = rank_records(candidates + findings)
    evidence_paths = write_evidence_notes(ranked, output_dir / "evidence")
    normalized_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(normalized_dir / "assets.jsonl", assets)
    write_jsonl(normalized_dir / "services.jsonl", services)
    write_jsonl(normalized_dir / "endpoints.jsonl", endpoints)
    write_jsonl(normalized_dir / "params.jsonl", params)
    write_jsonl(normalized_dir / "findings.jsonl", findings)
    write_jsonl(output_dir / "assets.jsonl", assets)
    write_jsonl(output_dir / "services.jsonl", services)
    write_jsonl(output_dir / "endpoints.jsonl", endpoints)
    write_jsonl(output_dir / "params.jsonl", params)
    write_jsonl(output_dir / "candidates.jsonl", candidates)
    write_jsonl(output_dir / "findings.jsonl", findings)
    write_jsonl(output_dir / "ranked.jsonl", ranked)
    write_json(output_dir / "removed-out-of-scope.json", removed)
    write_json(
        output_dir / "recon-result.json",
        {
            "program": config.program_name,
            "scope_file": str(config.source_path),
            "generated_at": now_utc(),
            "assets": assets,
            "services": services,
            "endpoints": endpoints,
            "params": params,
            "findings": findings,
        },
    )
    (output_dir / "report.md").write_text(
        render_markdown_report(
            ranked,
            program=config.program_name,
            profile="fast",
            scope_file=str(config.source_path),
            removed_count=len(removed),
        ),
        encoding="utf-8",
    )
    payload = {
        "profile": "fast",
        "execute": True,
        "results": results,
        "assets": len(assets),
        "services": len(services),
        "endpoints": len(endpoints),
        "params": len(params),
        "candidates": len(candidates),
        "findings": len(findings),
        "ranked": len(ranked),
        "removed": len(removed),
        "evidence_notes": len(evidence_paths),
        "output": str(output_dir),
    }
    write_json(output_dir / "summary.json", payload)
    return payload


def build_fast_recon_plans(
    *,
    config: ScopeConfig,
    output_dir: Path,
    dry_run: bool = True,
) -> list[CommandPlan]:
    raw_dir = output_dir / "raw"
    derived_dir = output_dir / "derived"
    roots = root_domains(config)
    domain_arg = ",".join(roots)
    plans = [
        build_command_plan(
            config=config,
            name="subfinder",
            argv=[tool_binary("subfinder"), "-d", domain_arg, "-silent"],
            output_path=raw_dir / "subfinder.txt",
            targets=roots,
            required_policy_flag="passive_recon",
            dry_run=dry_run,
        ),
        build_command_plan(
            config=config,
            name="dnsx",
            argv=[tool_binary("dnsx"), "-l", str(raw_dir / "subfinder.txt"), "-silent"],
            output_path=raw_dir / "dnsx.txt",
            targets=roots,
            required_policy_flag="active_recon",
            dry_run=dry_run,
        ),
        build_command_plan(
            config=config,
            name="httpx",
            argv=[tool_binary("httpx"), "-l", str(raw_dir / "dnsx.txt"), "-json", "-silent"],
            output_path=raw_dir / "httpx.jsonl",
            targets=roots,
            required_policy_flag="active_recon",
            dry_run=dry_run,
        ),
        build_command_plan(
            config=config,
            name="katana",
            argv=[
                tool_binary("katana"),
                "-list",
                str(derived_dir / "live_urls.txt"),
                "-json",
                "-silent",
                "-depth",
                "2",
            ],
            output_path=raw_dir / "katana.jsonl",
            targets=roots,
            required_policy_flag="crawling",
            dry_run=dry_run,
        ),
    ]
    if config.policy.is_enabled("nuclei_scan"):
        plans.append(
            build_command_plan(
                config=config,
                name="nuclei",
                argv=[
                    tool_binary("nuclei"),
                    "-list",
                    str(derived_dir / "live_urls.txt"),
                    "-jsonl",
                    "-silent",
                    "-severity",
                    "low,medium,high,critical",
                    "-exclude-tags",
                    "dos,intrusive,destructive,bruteforce,fuzz",
                ],
                output_path=raw_dir / "nuclei.jsonl",
                targets=roots,
                required_policy_flag="nuclei_scan",
                dry_run=dry_run,
            )
        )
    return plans


def root_domains(config: ScopeConfig) -> list[str]:
    roots: list[str] = []
    for domain in config.scope.in_scope_domains:
        normalized = domain[2:] if domain.startswith("*.") else domain
        if normalized not in roots:
            roots.append(normalized)
    return roots


def write_live_urls_from_httpx(input_path: Path, output_path: Path) -> None:
    if not input_path.exists():
        return
    urls: list[str] = []
    for record in load_jsonl_text(input_path.read_text(encoding="utf-8")):
        url = str(record.get("url") or record.get("input") or "")
        if url:
            urls.append(url)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")
