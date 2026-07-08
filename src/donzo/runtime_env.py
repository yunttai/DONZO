from __future__ import annotations

import os
import shutil
import site
import sys
from collections.abc import MutableMapping
from pathlib import Path
from typing import Any

TRUTHY = {"1", "true", "yes", "on"}


def refresh_runtime_env(
    repo_root: Path | None = None,
    *,
    environ: MutableMapping[str, str] | None = None,
    home: Path | None = None,
) -> dict[str, Any]:
    env = environ if environ is not None else os.environ
    if env.get("DONZO_DISABLE_RUNTIME_ENV", "").strip().lower() in TRUTHY:
        return {"disabled": True, "path_added": [], "defaults_set": {}}

    root = repo_root or Path.cwd()
    user_home = home or Path.home()
    path_entries = runtime_path_entries(root, user_home, env)
    added = prepend_path_entries(env, path_entries)

    defaults_set: dict[str, str] = {}
    codex_bin = resolve_preferred_binary("codex", path_entries, env)
    if codex_bin and not command_ref_exists(env.get("CODEX_BIN", ""), env):
        env["CODEX_BIN"] = codex_bin
        defaults_set["CODEX_BIN"] = codex_bin

    go_bin = resolve_preferred_binary("go", path_entries, env)
    if go_bin and not command_ref_exists(env.get("DONZO_GO_BIN", ""), env):
        env["DONZO_GO_BIN"] = go_bin
        defaults_set["DONZO_GO_BIN"] = go_bin

    return {"disabled": False, "path_added": added, "defaults_set": defaults_set}


def runtime_path_entries(
    repo_root: Path,
    home: Path,
    environ: MutableMapping[str, str] | None = None,
) -> list[Path]:
    env = environ if environ is not None else os.environ
    candidates: list[Path] = []

    if os.name == "nt":
        candidates.extend([repo_root / ".venv" / "Scripts"])
    else:
        candidates.extend([repo_root / ".venv-wsl" / "bin", repo_root / ".venv" / "bin"])

    candidates.extend(
        [
            home / ".donzo" / "node" / "bin",
            home / ".local" / "bin",
            home / ".donzo" / "tools" / "bin",
            home / "go" / "bin",
            home / ".donzo" / "go" / "bin",
        ]
    )
    candidates.extend(user_script_dirs())

    if os.name == "nt":
        appdata = env.get("APPDATA")
        if appdata:
            candidates.append(Path(appdata) / "npm")
        program_files = env.get("ProgramFiles")
        if program_files:
            candidates.append(Path(program_files) / "nodejs")

    return existing_unique_dirs(candidates)


def prepend_path_entries(env: MutableMapping[str, str], entries: list[Path]) -> list[str]:
    current = env.get("PATH", "")
    parts = [part for part in current.split(os.pathsep) if part]
    normalized = {normalize_path(part) for part in parts}
    added: list[str] = []
    for entry in reversed(entries):
        value = str(entry)
        key = normalize_path(value)
        if key in normalized:
            continue
        parts.insert(0, value)
        normalized.add(key)
        added.insert(0, value)
    env["PATH"] = os.pathsep.join(parts)
    return added


def resolve_preferred_binary(
    name: str,
    preferred_dirs: list[Path],
    env: MutableMapping[str, str],
) -> str | None:
    for directory in preferred_dirs:
        for filename in binary_names(name):
            candidate = directory / filename
            if candidate.exists() and candidate.is_file():
                return str(candidate)
    resolved = shutil.which(name, path=env.get("PATH", ""))
    return resolved


def command_ref_exists(value: str | None, env: MutableMapping[str, str]) -> bool:
    if not value:
        return False
    ref = value.strip()
    if not ref:
        return False
    expanded = Path(ref).expanduser()
    if expanded.exists():
        return True
    return shutil.which(ref, path=env.get("PATH", "")) is not None


def binary_names(name: str) -> list[str]:
    if os.name == "nt":
        return [f"{name}.cmd", f"{name}.exe", f"{name}.bat", name]
    return [name]


def user_script_dirs() -> list[Path]:
    base = Path(site.USER_BASE)
    candidates = [base / "bin", base / "Scripts"]
    if os.name == "nt":
        version = f"Python{sys.version_info.major}{sys.version_info.minor}"
        candidates.append(base / version / "Scripts")
    return existing_unique_dirs(candidates)


def existing_unique_dirs(paths: list[Path]) -> list[Path]:
    result: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        try:
            resolved = path.expanduser()
        except RuntimeError:
            continue
        if not resolved.exists() or not resolved.is_dir():
            continue
        key = normalize_path(str(resolved))
        if key in seen:
            continue
        seen.add(key)
        result.append(resolved)
    return result


def normalize_path(path: str) -> str:
    normalized = os.path.normpath(os.path.expanduser(path))
    return os.path.normcase(normalized)
