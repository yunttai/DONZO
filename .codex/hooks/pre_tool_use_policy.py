from __future__ import annotations

import re

from _policy_common import deny, load_payload, payload_text

DESTRUCTIVE_PATTERNS = (
    r"\brm\s+-rf\b",
    r"\bdel\s+/[sq]\b",
    r"\brmdir\s+/s\b",
    r"\bRemove-Item\b.*\b-Recurse\b",
    r"\bgit\s+reset\s+--hard\b",
    r"\bgit\s+checkout\s+--\b",
    r"\bformat\b",
    r"\bdd\s+if=",
    r"\bcurl\b.*\|\s*(sh|bash|powershell|pwsh)\b",
    r"\bwget\b.*\|\s*(sh|bash|powershell|pwsh)\b",
)

RECON_TOOLS = (
    "subfinder",
    "dnsx",
    "httpx",
    "naabu",
    "katana",
    "nuclei",
    "amass",
    "bbot",
    "uncover",
    "gau",
    "waybackurls",
    "waymore",
    "ffuf",
    "feroxbuster",
    "arjun",
    "dalfox",
    "interactsh",
    "nmap",
    "masscan",
    "zap-baseline",
)


def has_scope_argument(command: str) -> bool:
    lowered = command.lower()
    return any(marker in lowered for marker in ("--scope", " scope.", "scope.yaml", "-c "))


def main() -> None:
    command = payload_text(load_payload())
    lowered = command.lower()
    for pattern in DESTRUCTIVE_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE | re.DOTALL):
            deny(f"Blocked dangerous command pattern: {pattern}")

    if any(
        re.search(rf"\b{re.escape(tool)}\b", lowered) for tool in RECON_TOOLS
    ) and not has_scope_argument(command):
        deny("Recon or scan command detected without an explicit scope file/argument.")


if __name__ == "__main__":
    main()
