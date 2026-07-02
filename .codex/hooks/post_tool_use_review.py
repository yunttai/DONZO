from __future__ import annotations

from pathlib import Path

from _policy_common import deny, find_secret_patterns, iter_text_files

SCAN_ROOTS = (Path("findings"), Path("reports"), Path("artifacts"))


def main() -> None:
    flagged: list[str] = []
    for root in SCAN_ROOTS:
        for path in iter_text_files(root):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if find_secret_patterns(text):
                flagged.append(str(path))
    if flagged:
        deny("Secret-like material found in generated artifacts:\n" + "\n".join(flagged))


if __name__ == "__main__":
    main()
