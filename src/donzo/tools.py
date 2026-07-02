from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ToolSpec:
    name: str
    binary: str
    version_args: tuple[str, ...] = ("-version",)
    required_for_fast: bool = False


TOOL_SPECS: dict[str, ToolSpec] = {
    "subfinder": ToolSpec("subfinder", "subfinder", required_for_fast=True),
    "dnsx": ToolSpec("dnsx", "dnsx", required_for_fast=True),
    "httpx": ToolSpec("httpx", "httpx", required_for_fast=True),
    "katana": ToolSpec("katana", "katana", required_for_fast=True),
    "nuclei": ToolSpec("nuclei", "nuclei", required_for_fast=False),
}

GO_INSTALL_PACKAGES: dict[str, str] = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
}


def check_tools(names: list[str] | None = None) -> list[dict[str, Any]]:
    selected = names or list(TOOL_SPECS)
    return [check_tool(TOOL_SPECS[name]) for name in selected if name in TOOL_SPECS]


def check_tool(spec: ToolSpec) -> dict[str, Any]:
    result: dict[str, Any] = {
        "name": spec.name,
        "binary": spec.binary,
        "required_for_fast": spec.required_for_fast,
        "available": False,
        "path": None,
        "version": None,
        "error": None,
    }
    candidates = candidate_binaries(spec)
    if not candidates:
        result["error"] = "not_found_on_path"
        return result
    errors: list[str] = []
    for path in candidates:
        checked = check_candidate_binary(spec, path)
        if checked["available"]:
            return checked
        errors.append(f"{path}:{checked['error']}")
        result = checked
    result["error"] = "; ".join(errors) if errors else result["error"]
    return result


def candidate_binaries(spec: ToolSpec) -> list[str]:
    candidates: list[str] = []
    env_path = os.environ.get(f"DONZO_TOOL_{spec.name.upper()}")
    if env_path:
        candidates.append(env_path)
    home = Path.home()
    go_bin = home / "go" / "bin" / executable_name(spec.binary)
    if go_bin.exists():
        candidates.append(str(go_bin))
    path_binary = shutil.which(spec.binary)
    if path_binary:
        candidates.append(path_binary)
    deduped: list[str] = []
    for candidate in candidates:
        if candidate not in deduped:
            deduped.append(candidate)
    return deduped


def executable_name(binary: str) -> str:
    return f"{binary}.exe" if os.name == "nt" and not binary.endswith(".exe") else binary


def check_candidate_binary(spec: ToolSpec, path: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "name": spec.name,
        "binary": spec.binary,
        "required_for_fast": spec.required_for_fast,
        "available": False,
        "path": path,
        "version": None,
        "error": None,
    }
    if not Path(path).exists():
        result["error"] = "path_does_not_exist"
        return result
    try:
        completed = subprocess.run(
            [path, *spec.version_args],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except OSError as exc:
        result["error"] = str(exc)
        return result
    except subprocess.TimeoutExpired:
        result["error"] = "version_timeout"
        return result
    output = completed.stdout.strip() or completed.stderr.strip()
    result["version"] = output.splitlines()[0] if output else ""
    if completed.returncode != 0:
        result["error"] = f"version_returned_{completed.returncode}"
        return result
    result["available"] = True
    return result


def missing_required_fast_tools() -> list[dict[str, Any]]:
    return [
        item
        for item in check_tools()
        if item["required_for_fast"] and not item["available"]
    ]


def tool_binary(name: str) -> str:
    spec = TOOL_SPECS[name]
    status = check_tool(spec)
    if status["available"] and status["path"]:
        return str(status["path"])
    return spec.binary


def install_plan(names: list[str] | None = None) -> list[dict[str, Any]]:
    selected = names or list(GO_INSTALL_PACKAGES)
    plans: list[dict[str, Any]] = []
    for name in selected:
        package = GO_INSTALL_PACKAGES.get(name)
        if not package:
            continue
        plans.append({"name": name, "argv": ["go", "install", package]})
    return plans


def run_install_plan(names: list[str] | None = None) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for plan in install_plan(names):
        try:
            completed = subprocess.run(
                plan["argv"],
                text=True,
                capture_output=True,
                timeout=600,
                check=False,
            )
        except OSError as exc:
            results.append({**plan, "returncode": None, "error": str(exc)})
            continue
        except subprocess.TimeoutExpired:
            results.append({**plan, "returncode": None, "error": "timeout"})
            continue
        results.append(
            {
                **plan,
                "returncode": completed.returncode,
                "stdout": completed.stdout[-4000:],
                "stderr": completed.stderr[-4000:],
                "error": None if completed.returncode == 0 else "nonzero_exit",
            }
        )
    return results
