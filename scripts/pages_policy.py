#!/usr/bin/env python3
"""Fail-closed, offline GitHub Pages policy check for QSOLKCB/RHEL-LAB.

GitHub's automatic Pages workflow cannot be disabled by a pull request.
The repository administrator must delete the Pages site through Settings.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


class PolicyError(ValueError):
    """Pages state unknown or repository policy violated."""


PUBLISH_MARKERS = (
    re.compile(r"\bactions/(?:deploy-pages|upload-pages-artifact)@", re.I),
    re.compile(r"\bpeaceiris/actions-gh-pages@", re.I),
    re.compile(r"(?m)^\s*pages\s*:\s*write\b", re.I),
    re.compile(r"\bgh-pages\b", re.I),
)


def check(event: object, repository: str, workflows: Path) -> None:
    if repository != "QSOLKCB/RHEL-LAB":
        raise PolicyError("incorrect repository for RHEL-LAB guard")
    if not isinstance(event, dict) or not isinstance(event.get("repository"), dict):
        raise PolicyError("GitHub event missing repository metadata")
    metadata = event["repository"]
    if metadata.get("full_name") != repository:
        raise PolicyError("GitHub event repository identity mismatch")
    if metadata.get("has_pages") is not False:
        raise PolicyError("GitHub Pages is enabled or status missing; set Settings > Pages > Source: Deploy from a branch > Branch: None > Save")
    if not workflows.is_dir() or workflows.is_symlink():
        raise PolicyError("workflow directory missing or unsafe")
    for path in sorted((*workflows.glob("*.yml"), *workflows.glob("*.yaml"))):
        if not path.is_file() or path.is_symlink():
            raise PolicyError(f"unsafe workflow: {path.name!r}")
        active = "\n".join(
            line for line in path.read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("#")
        )
        if any(marker.search(active) for marker in PUBLISH_MARKERS):
            raise PolicyError(f"Pages deployment reference in {path.name!r}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflows", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        with args.event.open(encoding="utf-8") as handle:
            event = json.load(handle)
        check(event, args.repository, args.workflows)
    except (PolicyError, OSError, ValueError) as exc:
        print(f"FAIL: Pages policy: {exc}", file=sys.stderr)
        return 1
    print("PASS: GitHub event declares Pages disabled; no publishing workflow found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
