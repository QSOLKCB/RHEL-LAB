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
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_FILES = 10_000
MAX_MANIFEST_NESTING = 8
MAX_MANIFEST_PATH_CHARS = 4096

_MANIFEST_KEYS = frozenset(("schema", "algorithm", "files"))
_FILE_KEYS = frozenset(("path", "bytes", "sha256"))
_LOWER_HEX = frozenset("0123456789abcdef")
_MAX_JSON_SEPARATORS = MAX_MANIFEST_FILES * 3 + 2
_MAX_JSON_STRING_UNITS = MAX_MANIFEST_PATH_CHARS * 2
_MAX_JSON_SCALAR_CHARS = 128
_READ_CHUNK_BYTES = 64 * 1024


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
    """Inventory a pinned private root, failing closed on unsafe contents."""
    with safe_fs.directory(input_dir, private=True) as root_fd:
        return _inventory_fd(root_fd)


def _manifest_location(manifest: Path) -> tuple[Path, str]:
    value = safe_fs.absolute(manifest)
    if value.name in ("", ".", ".."):
        raise EvidenceError("manifest basename is invalid")
    return value.parent, value.name


def _validate_manifest(document: object) -> dict:
    """Require the exact bounded schema emitted by this module."""
    if not isinstance(document, dict) or set(document) != _MANIFEST_KEYS:
        raise EvidenceError("manifest has an invalid top-level schema")
    if document["schema"] != SCHEMA or document["algorithm"] != "sha256":
        raise EvidenceError("manifest schema or algorithm is unsupported")
    files = document["files"]
    if not isinstance(files, list):
        raise EvidenceError("manifest files must be a list")
    if len(files) > MAX_MANIFEST_FILES:
        raise EvidenceError(f"manifest exceeds {MAX_MANIFEST_FILES} file records")
    for index, record in enumerate(files):
        if not isinstance(record, dict) or set(record) != _FILE_KEYS:
            raise EvidenceError(f"manifest file record {index} has an invalid schema")
        path = record["path"]
        size = record["bytes"]
        digest = record["sha256"]
        if not isinstance(path, str) or not path or len(path) > MAX_MANIFEST_PATH_CHARS:
            raise EvidenceError(f"manifest file record {index} has an invalid path")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise EvidenceError(f"manifest file record {index} has an invalid byte count")
        if (not isinstance(digest, str) or len(digest) != 64
                or any(char not in _LOWER_HEX for char in digest)):
            raise EvidenceError(f"manifest file record {index} has an invalid SHA-256 digest")
    return document


def _preflight_json(document: str) -> None:
    """Bound JSON parser work before deserializing untrusted text."""
    depth = 0
    separators = 0
    scalar_chars = 0
    index = 0
    while index < len(document):
        char = document[index]
        if char == '"':
            scalar_chars = 0
            string_units = 0
            index += 1
            while index < len(document):
                char = document[index]
                if char == '"':
                    break
                if char == "\\":
                    index += 1
                    if index >= len(document):
                        break
                    if document[index] == "u":
                        index += 4
                string_units += 1
                if string_units > _MAX_JSON_STRING_UNITS:
                    raise EvidenceError("manifest JSON string exceeds safety limit")
                index += 1
        elif char in "[{":
            scalar_chars = 0
            depth += 1
            if depth > MAX_MANIFEST_NESTING:
                raise EvidenceError(
                    f"manifest JSON nesting exceeds {MAX_MANIFEST_NESTING} levels")
        elif char in "]}":
            scalar_chars = 0
            if depth:
                depth -= 1
        elif char == ",":
            scalar_chars = 0
            separators += 1
            if separators > _MAX_JSON_SEPARATORS:
                raise EvidenceError("manifest JSON contains too many values")
        elif char == ":" or char.isspace():
            scalar_chars = 0
        else:
            scalar_chars += 1
            if scalar_chars > _MAX_JSON_SCALAR_CHARS:
                raise EvidenceError("manifest JSON scalar exceeds safety limit")
        index += 1


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"manifest contains duplicate key: {key!a}")
        result[key] = value
    return result


def _read_manifest(fd: int, first: os.stat_result) -> dict:
    if first.st_size > MAX_MANIFEST_BYTES:
        raise EvidenceError(
            f"manifest exceeds {MAX_MANIFEST_BYTES}-byte size limit")
    chunks = []
    count = 0
    while count <= MAX_MANIFEST_BYTES:
        chunk = os.read(
            fd, min(_READ_CHUNK_BYTES, MAX_MANIFEST_BYTES + 1 - count))
        if not chunk:
            break
        chunks.append(chunk)
        count += len(chunk)
    if count > MAX_MANIFEST_BYTES:
        raise EvidenceError(
            f"manifest exceeds {MAX_MANIFEST_BYTES}-byte size limit")
    if count != first.st_size or not _unchanged(first, os.fstat(fd)):
        raise EvidenceError("manifest changed while reading")
    try:
        text = b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError("manifest is not valid UTF-8") from exc
    _preflight_json(text)
    try:
        document = json.loads(text, object_pairs_hook=_unique_object)
    except EvidenceError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise EvidenceError("manifest is not valid bounded JSON") from exc
    return _validate_manifest(document)


def _serialize_manifest(report: dict) -> str:
    _validate_manifest(report)
    chunks = []
    byte_count = 1  # Final newline.
    encoder = json.JSONEncoder(indent=2, sort_keys=True)
    for chunk in encoder.iterencode(report):
        byte_count += len(chunk.encode("utf-8"))
        if byte_count > MAX_MANIFEST_BYTES:
            raise EvidenceError(
                f"manifest exceeds {MAX_MANIFEST_BYTES}-byte size limit")
        chunks.append(chunk)
    return "".join(chunks) + "\n"


def seal(input_dir: Path, output: Path) -> dict:
    """Seal private evidence to a 0600 manifest in a private directory."""
    parent, name = _manifest_location(output)
    with safe_fs.directory(input_dir, private=True) as root_fd:
        st = os.fstat(root_fd)
        root_identity = (st.st_dev, st.st_ino)
        with safe_fs.directory(parent, private=True, forbidden=root_identity) as dest_fd:
            report = _inventory_fd(root_fd)
            document = _serialize_manifest(report)
            fd = os.open(name, safe_fs.FILE_WRITE_FLAGS, 0o600, dir_fd=dest_fd)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(document)
                stream.flush()
                os.fsync(stream.fileno())
            return report


def verify(input_dir: Path, manifest: Path) -> dict:
    """Verify private evidence and manifest via pinned file descriptors."""
    parent, name = _manifest_location(manifest)
    with safe_fs.directory(input_dir, private=True) as root_fd:
        st = os.fstat(root_fd)
        with safe_fs.directory(parent, private=True,
                               forbidden=(st.st_dev, st.st_ino)) as manifest_fd:
            fd = os.open(name, safe_fs.FILE_READ_FLAGS, dir_fd=manifest_fd)
            try:
                first = os.fstat(fd)
                if not stat.S_ISREG(first.st_mode):
                    raise EvidenceError("manifest must be a regular file")
                expected = _read_manifest(fd, first)
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
