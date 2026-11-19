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
    # Equivalent YAML permission mappings: block style (including quoted keys
    # and values), plus flow style with a first or later map entry.
    re.compile(r"""(?im)^[ \t]*["']?pages["']?[ \t]*:[ \t]*["']?write["']?(?=[ \t]*(?:#|$))"""),
    re.compile(r"""(?i)[,{][ \t\r\n]*["']?pages["']?[ \t]*:[ \t]*["']?write["']?(?=[ \t]*(?:,|\}|#|$))"""),
    re.compile(r"\bgh-pages\b", re.I),
    re.compile(r"(?im)^[ \t]*permissions[ \t]*:[ \t]*[\"']?write-all[\"']?(?:[ \t]*(?:#.*)?)$"),
    re.compile(r"(?im)^[ \t]*[\"']?[a-z][a-z-]*[\"']?[ \t]*:[ \t]*[\"']?write[\"']?(?:[ \t]*(?:#.*)?)$"),
    # A job may override safe workflow-level permissions with a flow mapping.
    re.compile(
        r"(?ims)^[ \t]*[\"']?permissions[\"']?[ \t]*:[ \t]*\{"
        r"(?=[^}]*[\"']?[a-z][a-z-]*[\"']?[ \t]*:[ \t]*"
        r"[\"']?write[\"']?[ \t]*(?:,|\}))[^}]*\}"),
    re.compile(r"(?i)\b(?:api\.github\.com/repos/[^\s]+/pages|/pages/builds|/pages/deployment)\b"),
)

ALLOWED_ACTIONS = frozenset({
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",  # v7.0.1
    "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",  # v7.0.0
})
USES = re.compile(
    r"(?im)^[ \t]*(?:-[ \t]*)?[\"']?uses[\"']?[ \t]*:[ \t]*([^#\r\n]+)")
# Any flow-style or otherwise unparsed uses key is rejected. Supporting only
# one-key-per-line forms keeps this stdlib-only scanner fail-closed.
USES_KEY = re.compile(
    r"(?im)(?:^[ \t]*(?:-[ \t]*)?|[,{][ \t\r\n]*)"
    r"[\"']?uses[\"']?[ \t]*:")
TOP_LEVEL_READ = re.compile(
    r"(?m)^permissions:[ \t]*(?:\r?\n)[ \t]+contents:[ \t]*[\"']?read[\"']?(?:[ \t]*(?:#.*)?)$")

# The no-Pages guard is deliberately NOT a general-purpose YAML parser.
# Only a single top-level block-style permissions declaration is accepted.
# Every other declaration (job override, flow mapping, folded scalar, quoted
# key, duplicate key, etc.) fails closed. A README or shell script containing
# the literal syntax may also be rejected, which is intentional here.
PERMISSIONS_KEYS = re.compile(
    r"""(?im)(?<![A-Za-z0-9_-])(?:"permissions"|'permissions'|permissions)[ \t]*:""")
TOP_LEVEL_PERMISSIONS_DECL = re.compile(r"(?m)^permissions:[ \t]*(?:#.*)?$")
EXPLICIT_YAML_KEY = re.compile(r"(?m)^[ \t]*(?:-[ \t]*)?\?(?=[ \t]|$)")
YAML_MERGE_KEY = re.compile(r"(?m)(?:^|[ \t,{])(?:<<|['\"]<<['\"])[ \t]*:")
YAML_ANCHOR = re.compile(r"(?m)(?:^|[ \t,:-])[&*][A-Za-z_][A-Za-z0-9_-]*")


def _require_readonly_permissions(source: str, filename: str) -> None:
    """Reject permission grammars that cannot be audited without a YAML parser."""
    declaration = TOP_LEVEL_PERMISSIONS_DECL.search(source)
    occurrences = list(PERMISSIONS_KEYS.finditer(source))
    if (declaration is None or len(occurrences) != 1 or
            declaration.start() != occurrences[0].start()):
        raise PolicyError(
            f"workflow has unsupported, duplicate, or job-level permissions: {filename!r}")
    if TOP_LEVEL_READ.search(source) is None:
        raise PolicyError(
            f"workflow lacks explicit top-level contents: read permissions: {filename!r}")
    if (EXPLICIT_YAML_KEY.search(source) or YAML_MERGE_KEY.search(source)
            or YAML_ANCHOR.search(source)):
        raise PolicyError(f"unsupported YAML key, anchor or merge: {filename!r}")


_YAML_SIMPLE_ESCAPES = {
    "0": "\0",
    "a": "\a",
    "b": "\b",
    "t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
    "e": "\x1b",
    " ": " ",
    '"': '"',
    "/": "/",
    "\\": "\\",
    "N": "\x85",
    "_": "\xa0",
    "L": "\u2028",
    "P": "\u2029",
}
_YAML_HEX_ESCAPES = {"x": 2, "u": 4, "U": 8}


def _canonicalize_yaml_escapes(source: str) -> str:
    """Decode YAML double-quoted escape spellings for fail-closed scanning.

    The scan deliberately canonicalizes escapes wherever they occur rather
    than trying to implement YAML's context-sensitive grammar. This can only
    expose additional publishing markers; ordinary unescaped text is
    unchanged. Backslash pairs are consumed once so escapes are not decoded
    recursively.
    """
    canonical: list[str] = []
    index = 0
    while index < len(source):
        if source[index] != "\\" or index + 1 == len(source):
            canonical.append(source[index])
            index += 1
            continue

        escape = source[index + 1]
        if escape in _YAML_SIMPLE_ESCAPES:
            canonical.append(_YAML_SIMPLE_ESCAPES[escape])
            index += 2
            continue
        if escape in _YAML_HEX_ESCAPES:
            width = _YAML_HEX_ESCAPES[escape]
            digits = source[index + 2:index + 2 + width]
            if len(digits) == width and all(
                    character in "0123456789abcdefABCDEF"
                    for character in digits):
                value = int(digits, 16)
                if value <= 0x10ffff:
                    canonical.append(chr(value))
                    index += 2 + width
                    continue
        if escape in "\r\n":
            index += 2
            if escape == "\r" and index < len(source) \
                    and source[index] == "\n":
                index += 1
            while index < len(source) and source[index] in " \t":
                index += 1
            continue

        canonical.append("\\")
        index += 1
    return "".join(canonical)


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
        canonical = _canonicalize_yaml_escapes(active)
        if any(marker.search(canonical) for marker in PUBLISH_MARKERS):
            raise PolicyError(f"Pages deployment reference in {path.name!r}")
        _require_readonly_permissions(canonical, path.name)
        uses = list(USES.finditer(canonical))
        if USES_KEY.search(USES.sub("", canonical)):
            raise PolicyError(f"unsupported uses representation in {path.name!r}")
        for match in uses:
            action = match.group(1).strip().strip("\"'")
            if action not in ALLOWED_ACTIONS:
                raise PolicyError(
                    f"unapproved local, reusable, or third-party action in {path.name!r}")


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
