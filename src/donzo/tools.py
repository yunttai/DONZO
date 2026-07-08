from __future__ import annotations

import os
import shutil
import site
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ToolSpec:
    name: str
    binary: str
    version_args: tuple[str, ...] = ("-version",)
    required_for_fast: bool = False
    required_for_normal: bool = False
    required_for_deep: bool = False


TOOL_SPECS: dict[str, ToolSpec] = {
    "subfinder": ToolSpec(
        "subfinder",
        "subfinder",
        required_for_fast=True,
        required_for_normal=True,
        required_for_deep=True,
    ),
    "dnsx": ToolSpec(
        "dnsx",
        "dnsx",
        required_for_fast=True,
        required_for_normal=True,
        required_for_deep=True,
    ),
    "httpx": ToolSpec(
        "httpx",
        "httpx",
        required_for_fast=True,
        required_for_normal=True,
        required_for_deep=True,
    ),
    "katana": ToolSpec(
        "katana",
        "katana",
        required_for_fast=True,
        required_for_normal=True,
        required_for_deep=True,
    ),
    "gau": ToolSpec(
        "gau",
        "gau",
        version_args=("-h",),
        required_for_normal=True,
        required_for_deep=True,
    ),
    "waybackurls": ToolSpec(
        "waybackurls",
        "waybackurls",
        version_args=("-h",),
        required_for_normal=True,
        required_for_deep=True,
    ),
    "naabu": ToolSpec("naabu", "naabu"),
    "nuclei": ToolSpec("nuclei", "nuclei", required_for_fast=False),
    "amass": ToolSpec("amass", "amass"),
    "bbot": ToolSpec("bbot", "bbot", version_args=("--version",)),
    "uncover": ToolSpec("uncover", "uncover"),
    "alterx": ToolSpec("alterx", "alterx"),
    "tlsx": ToolSpec("tlsx", "tlsx"),
    "waymore": ToolSpec("waymore", "waymore", version_args=("--version",)),
    "paramspider": ToolSpec("paramspider", "paramspider", version_args=("-h",)),
    "kiterunner": ToolSpec("kiterunner", "kr", version_args=("-h",)),
    "gitleaks": ToolSpec("gitleaks", "gitleaks", version_args=("version",)),
    "trufflehog": ToolSpec("trufflehog", "trufflehog", version_args=("--version",)),
    "arjun": ToolSpec("arjun", "arjun", version_args=("-h",)),
    "gf": ToolSpec("gf", "gf", version_args=("-h",)),
    "qsreplace": ToolSpec("qsreplace", "qsreplace", version_args=("-h",)),
    "kxss": ToolSpec("kxss", "kxss", version_args=("-h",)),
}

GO_INSTALL_PACKAGES: dict[str, str] = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "gau": "github.com/lc/gau/v2/cmd/gau@latest",
    "waybackurls": "github.com/tomnomnom/waybackurls@latest",
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "uncover": "github.com/projectdiscovery/uncover/cmd/uncover@latest",
    "alterx": "github.com/projectdiscovery/alterx/cmd/alterx@latest",
    "tlsx": "github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
    "gf": "github.com/tomnomnom/gf@latest",
    "qsreplace": "github.com/tomnomnom/qsreplace@latest",
}

TOOL_PHASES: dict[str, str] = {
    "subfinder": "passive_subdomain_discovery",
    "dnsx": "dns_resolution",
    "httpx": "http_service_probe",
    "katana": "safe_crawling",
    "gau": "archive_url_collection",
    "waybackurls": "archive_url_collection",
    "naabu": "optional_port_enrichment",
    "nuclei": "optional_safe_template_scan",
    "amass": "passive_subdomain_discovery",
    "bbot": "passive_subdomain_discovery",
    "uncover": "passive_asset_discovery",
    "alterx": "asset_expansion",
    "tlsx": "tls_metadata_collection",
    "waymore": "archive_url_collection",
    "paramspider": "parameter_url_collection",
    "kiterunner": "api_route_discovery",
    "gitleaks": "local_secret_pattern_scan",
    "trufflehog": "local_secret_pattern_scan",
    "arjun": "parameter_discovery",
    "gf": "local_pattern_matching",
    "qsreplace": "local_url_transform",
    "kxss": "reflected_parameter_hinting",
}


def check_tools(names: list[str] | None = None) -> list[dict[str, Any]]:
    selected = names or list(TOOL_SPECS)
    return [check_tool(TOOL_SPECS[name]) for name in selected if name in TOOL_SPECS]


def check_tool(spec: ToolSpec) -> dict[str, Any]:
    result: dict[str, Any] = {
        "name": spec.name,
        "binary": spec.binary,
        "required_for_fast": spec.required_for_fast,
        "required_for_normal": spec.required_for_normal,
        "required_for_deep": spec.required_for_deep,
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
    for scripts_dir in user_script_dirs():
        user_binary = scripts_dir / executable_name(spec.binary)
        if user_binary.exists():
            candidates.append(str(user_binary))
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


def user_script_dirs() -> list[Path]:
    base = Path(site.USER_BASE)
    candidates = [base / "bin", base / "Scripts"]
    if os.name == "nt":
        versioned = base / f"Python{sys.version_info.major}{sys.version_info.minor}" / "Scripts"
        candidates.append(versioned)
    return [path for path in candidates if path.exists()]


def go_binary() -> str:
    env_path = os.environ.get("DONZO_GO_BIN")
    if env_path and Path(env_path).exists():
        return env_path
    resolved = shutil.which("go")
    if resolved:
        return resolved
    if os.name == "nt":
        default_path = Path("C:/Program Files/Go/bin/go.exe")
        if default_path.exists():
            return str(default_path)
    return "go"


def check_candidate_binary(spec: ToolSpec, path: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "name": spec.name,
        "binary": spec.binary,
        "required_for_fast": spec.required_for_fast,
        "required_for_normal": spec.required_for_normal,
        "required_for_deep": spec.required_for_deep,
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
    return missing_required_tools("fast")


def missing_required_tools(profile: str) -> list[dict[str, Any]]:
    return [
        item
        for item in check_tools()
        if is_required_for_profile(item, profile) and not item["available"]
    ]


def is_required_for_profile(item: dict[str, Any], profile: str) -> bool:
    if profile == "deep":
        return bool(
            item.get("required_for_fast")
            or item.get("required_for_normal")
            or item.get("required_for_deep")
        )
    if profile == "normal":
        return bool(item.get("required_for_fast") or item.get("required_for_normal"))
    return bool(item.get("required_for_fast"))


def required_tool_names(profile: str) -> list[str]:
    return [
        name
        for name, spec in TOOL_SPECS.items()
        if spec.required_for_fast
        or (profile in {"normal", "deep"} and spec.required_for_normal)
        or (profile == "deep" and spec.required_for_deep)
    ]


def tool_matrix() -> dict[str, Any]:
    return {
        "source": "src/donzo/tools.py",
        "profiles": {
            "fast": {
                "required": required_tool_names("fast"),
                "optional": optional_tool_names("fast"),
            },
            "normal": {
                "required": required_tool_names("normal"),
                "optional": optional_tool_names("normal"),
            },
            "deep": {
                "required": required_tool_names("deep"),
                "optional": optional_tool_names("deep"),
            },
        },
        "tools": [tool_matrix_item(spec) for spec in TOOL_SPECS.values()],
    }


def optional_tool_names(profile: str) -> list[str]:
    names: list[str] = []
    if profile == "normal":
        names.append("naabu")
    if profile in {"fast", "normal"}:
        names.append("nuclei")
    if profile == "deep":
        names.extend(
            [
                "amass",
                "bbot",
                "uncover",
                "alterx",
                "tlsx",
                "waymore",
                "paramspider",
                "kiterunner",
                "gitleaks",
                "trufflehog",
                "arjun",
                "gf",
                "qsreplace",
                "kxss",
                "naabu",
                "nuclei",
            ]
        )
    required = set(required_tool_names(profile))
    return [name for name in names if name in TOOL_SPECS and name not in required]


def tool_matrix_item(spec: ToolSpec) -> dict[str, Any]:
    return {
        "name": spec.name,
        "binary": spec.binary,
        "phase": TOOL_PHASES.get(spec.name, "unknown"),
        "version_args": list(spec.version_args),
        "required_for_fast": spec.required_for_fast,
        "required_for_normal": spec.required_for_normal,
        "required_for_deep": spec.required_for_deep,
        "optional_for_fast": spec.name in optional_tool_names("fast"),
        "optional_for_normal": spec.name in optional_tool_names("normal"),
        "optional_for_deep": spec.name in optional_tool_names("deep"),
        "install_package": GO_INSTALL_PACKAGES.get(spec.name),
        "env_override": f"DONZO_TOOL_{spec.name.upper()}",
    }


def tool_binary(name: str) -> str:
    spec = TOOL_SPECS[name]
    status = check_tool(spec)
    if status["available"] and status["path"]:
        return str(status["path"])
    return spec.binary


def install_plan(names: list[str] | None = None) -> list[dict[str, Any]]:
    selected = names or list(GO_INSTALL_PACKAGES)
    go = go_binary()
    plans: list[dict[str, Any]] = []
    for name in selected:
        package = GO_INSTALL_PACKAGES.get(name)
        if not package:
            continue
        plans.append({"name": name, "argv": [go, "install", package]})
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
