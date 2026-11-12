#!/usr/bin/env python3
"""Deterministic evidence manifests using descriptor-pinned, no-follow traversal.

A SHA-256 manifest describes observed bytes, not signed chain of custody.
Use a quiescent/external snapshot for a point-in-time inventory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

try:
    from . import safe_fs
except ImportError:  # direct invocation: python scripts/evidence.py
    import safe_fs

SCHEMA = "qsol-rhel-evidence/v1"


class EvidenceError(ValueError):
    """Evidence tree changed, file type unsupported, or manifest mismatch."""


def _identity(info: os.stat_result) -> tuple[int, int, int]:
    return info.st_dev, info.st_ino, info.st_mode


def _unchanged(first: os.stat_result, last: os.stat_result) -> bool:
    return (_identity(first) == _identity(last)
            and first.st_size == last.st_size
            and first.st_mtime_ns == last.st_mtime_ns
            and first.st_ctime_ns == last.st_ctime_ns)


def _scan(fd: int, prefix: str, files: list[dict], depth: int = 0) -> None:
    if depth > 256:
        raise EvidenceError("evidence directory nesting exceeds safety limit")
    before_dir = os.fstat(fd)
    with os.scandir(fd) as iterator:
        entries = sorted(iterator, key=lambda entry: entry.name)
    for entry in entries:
        relative = f"{prefix}/{entry.name}" if prefix else entry.name
        observed = entry.stat(follow_symlinks=False)
        if stat.S_ISLNK(observed.st_mode):
            raise EvidenceError(f"symlink is not permitted: {relative!a}")
        # Open relative to the pinned parent. O_NONBLOCK prevents raced FIFOs
        # from blocking; fstat validates the object actually opened.
        child_fd = os.open(entry.name, safe_fs.FILE_READ_FLAGS, dir_fd=fd)
        try:
            opened = os.fstat(child_fd)
            if _identity(observed) != _identity(opened):
                raise EvidenceError(f"evidence entry changed while opening: {relative!a}")
            if stat.S_ISDIR(opened.st_mode):
                _scan(child_fd, relative, files, depth + 1)
            elif stat.S_ISREG(opened.st_mode):
                digest = hashlib.sha256()
                count = 0
                while True:
                    chunk = os.read(child_fd, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    count += len(chunk)
                final = os.fstat(child_fd)
                if not _unchanged(opened, final) or count != final.st_size:
                    raise EvidenceError(f"evidence file changed during hashing: {relative!a}")
                files.append({"path": relative, "bytes": count,
                              "sha256": digest.hexdigest()})
            else:
                raise EvidenceError(f"non-regular file is not permitted: {relative!a}")
        finally:
            os.close(child_fd)
    if not _unchanged(before_dir, os.fstat(fd)):
        raise EvidenceError(f"evidence directory changed during traversal: {prefix!a}")


def _inventory_fd(root_fd: int) -> dict:
    files: list[dict] = []
    _scan(root_fd, "", files)
    files.sort(key=lambda item: item["path"])
    return {"schema": SCHEMA, "algorithm": "sha256", "files": files}


def inventory(input_dir: Path) -> dict:
    """Fail closed on symlink, special file, unreadable subtree, observed race."""
    with safe_fs.directory(input_dir) as root_fd:
        return _inventory_fd(root_fd)


def _manifest_location(manifest: Path) -> tuple[Path, str]:
    value = safe_fs.absolute(manifest)
    if value.name in ("", ".", ".."):
        raise EvidenceError("manifest basename is invalid")
    return value.parent, value.name


def seal(input_dir: Path, output: Path) -> dict:
    """Write manifest with mode 0600 relative to a pinned private directory."""
    parent, name = _manifest_location(output)
    with safe_fs.directory(input_dir) as root_fd:
        st = os.fstat(root_fd)
        root_identity = (st.st_dev, st.st_ino)
        with safe_fs.directory(parent, private=True, forbidden=root_identity) as dest_fd:
            report = _inventory_fd(root_fd)
            fd = os.open(name, safe_fs.FILE_WRITE_FLAGS, 0o600, dir_fd=dest_fd)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                json.dump(report, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            return report


def verify(input_dir: Path, manifest: Path) -> dict:
    """Verify manifest and evidence via pinned FDs, refusing observed changes."""
    parent, name = _manifest_location(manifest)
    with safe_fs.directory(input_dir) as root_fd:
        st = os.fstat(root_fd)
        with safe_fs.directory(parent, private=True,
                               forbidden=(st.st_dev, st.st_ino)) as manifest_fd:
            fd = os.open(name, safe_fs.FILE_READ_FLAGS, dir_fd=manifest_fd)
            try:
                first = os.fstat(fd)
                if not stat.S_ISREG(first.st_mode):
                    raise EvidenceError("manifest must be a regular file")
                with os.fdopen(os.dup(fd), "r", encoding="utf-8") as stream:
                    expected = json.load(stream)
                if not _unchanged(first, os.fstat(fd)):
                    raise EvidenceError("manifest changed while reading")
            finally:
                os.close(fd)
        actual = _inventory_fd(root_fd)
        if expected != actual:
            raise EvidenceError("manifest mismatch: missing, extra, altered or invalid files")
        return actual


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    p_seal = subs.add_parser("seal", help="write a fresh SHA-256 manifest")
    p_seal.add_argument("--input", required=True, type=Path)
    p_seal.add_argument("--output", required=True, type=Path)
    p_verify = subs.add_parser("verify", help="verify existing manifest")
    p_verify.add_argument("--input", required=True, type=Path)
    p_verify.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = seal(args.input, args.output) if args.command == "seal" else verify(args.input, args.manifest)
    except (EvidenceError, safe_fs.UnsafePath, OSError, ValueError, TypeError) as exc:
        # Escape attacker-provided filenames and terminal control characters.
        print("FAIL: " + ascii(str(exc))[1:-1], file=sys.stderr)
        return 1
    print(f"PASS: {len(report['files'])} evidence files; {args.command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
