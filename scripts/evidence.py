#!/usr/bin/env python3
"""Deterministic SHA-256 file inventory for an operator-controlled evidence directory.

The manifest establishes byte identity only. It is not a signature, chain of custody,
proof of origin, or proof that an experiment executed. No network or guest access.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

SCHEMA = "qsol-rhel-evidence/v1"


class EvidenceError(ValueError):
    """Invalid input, unsafe file type, or a mismatched evidence manifest."""


def _root(path: Path) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise EvidenceError(f"input must be a real directory: {path}")
    return path.resolve()


def inventory(input_dir: Path) -> dict:
    """List relative regular files in stable order; reject symlinks and special files."""
    root = _root(input_dir)
    files = []
    directories = [root]
    while directories:
        directory = directories.pop()
        # pathlib.Path.rglob() may suppress scandir errors on some Python
        # versions. Explicit scandir traversal makes incomplete evidence fatal.
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda entry: entry.name)
        for entry in children:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            if entry.is_symlink():
                raise EvidenceError(f"symlink is not permitted: {relative}")
            if entry.is_dir(follow_symlinks=False):
                directories.append(path)
                continue
            if not entry.is_file(follow_symlinks=False):
                raise EvidenceError(f"non-regular file is not permitted: {relative}")
            digest = hashlib.sha256()
            size = 0
            with path.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
            files.append({"path": relative, "bytes": size, "sha256": digest.hexdigest()})
    files.sort(key=lambda item: item["path"])
    return {"schema": SCHEMA, "algorithm": "sha256", "files": files}


def seal(input_dir: Path, output: Path) -> dict:
    """Write a fresh, deterministic manifest outside the captured directory."""
    root = _root(input_dir)
    target = output.resolve()
    if target == root or root in target.parents:
        raise EvidenceError("manifest must be stored outside the input directory")
    if output.is_symlink():
        raise EvidenceError("manifest output may not be a symlink")
    report = inventory(root)
    # Exclusive creation refuses to replace an existing manifest or symlink.
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return report


def verify(input_dir: Path, manifest: Path) -> dict:
    """Recompute file inventory and fail on any missing, extra or modified file."""
    if manifest.is_symlink() or not manifest.is_file():
        raise EvidenceError("manifest must be an existing regular file (not a symlink)")
    with manifest.open("r", encoding="utf-8") as stream:
        expected = json.load(stream)
    actual = inventory(input_dir)
    if expected != actual:
        raise EvidenceError("manifest mismatch: missing, extra, altered, or invalid files")
    return actual


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    seal_parser = subparsers.add_parser("seal", help="write a fresh SHA-256 manifest")
    seal_parser.add_argument("--input", required=True, type=Path)
    seal_parser.add_argument("--output", required=True, type=Path)
    verify_parser = subparsers.add_parser("verify", help="verify an existing manifest")
    verify_parser.add_argument("--input", required=True, type=Path)
    verify_parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "seal":
            report = seal(args.input, args.output)
        else:
            report = verify(args.input, args.manifest)
    except (EvidenceError, OSError, ValueError, TypeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"PASS: {len(report['files'])} evidence files; {args.command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
