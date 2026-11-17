"""Bounded, fail-closed disk and installer-media preflight for RHEL-LAB.

No QEMU/libvirt actions here. All QCOW2 reads use a pinned descriptor and
happen BEFORE qemu-img is permitted to inspect any untrusted image.
"""
from __future__ import annotations

import os
import stat

GIB = 1024 ** 3
MAX_DISK_GIB = 64
MAX_ISO_BYTES = 8 * GIB
MIN_FREE_BYTES = 8 * GIB
MAX_QCOW2_OVERHEAD_BYTES = 4 * GIB
QFI_MAGIC = b"QFI\xfb"
# Feature-name table is non-path-bearing. All other extensions are refused.
FEATURE_NAMES_EXTENSION = 0x6803F857


class MediaError(ValueError):
    """Media exceeds an approved budget or uses unsupported QCOW2 semantics."""


def iso_size(fd: int) -> int:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_ISO_BYTES:
        raise MediaError("installer ISO must be regular, nonempty and at most 8 GiB")
    return info.st_size


def require_headroom(fd: int, bytes_needed: int, *, operation: str) -> None:
    """Conservative preflight, not a filesystem quota against later writers."""
    if type(bytes_needed) is not int or not 0 <= bytes_needed <= 2 ** 63:
        raise MediaError("invalid requested storage budget")
    info = os.fstatvfs(fd)
    if info.f_frsize <= 0 or info.f_bavail * info.f_frsize < bytes_needed + MIN_FREE_BYTES:
        raise MediaError(
            f"{operation}: insufficient free storage for worst-case allocation "
            "and 8 GiB reserve")


def maximum_qcow2_file_size(virtual_size: int) -> int:
    if not 16 * GIB <= virtual_size <= MAX_DISK_GIB * GIB:
        raise MediaError("virtual disk exceeds the reviewed 16–64 GiB profile")
    return virtual_size + MAX_QCOW2_OVERHEAD_BYTES


def _field(header: bytes, start: int, length: int) -> int:
    return int.from_bytes(header[start:start + length], "big")


def qcow2_preflight(fd: int, expected_virtual_size: int) -> dict:
    """Reject path-bearing/unsafe QCOW2 metadata before qemu-img info or convert.

    This is a structural gate; qemu-img remains responsible for full format
    verification after the dangerous external-reference cases are excluded.
    """
    max_size = maximum_qcow2_file_size(expected_virtual_size)
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or not 72 <= before.st_size <= max_size:
        raise MediaError("QCOW2 physical file size is invalid or over budget")
    head = os.pread(fd, 104, 0)
    if len(head) < 72 or head[:4] != QFI_MAGIC:
        raise MediaError("QCOW2 magic/header is invalid")
    version = _field(head, 4, 4)
    if version not in (2, 3) or (version == 3 and len(head) < 104):
        raise MediaError("unsupported or truncated QCOW2 version")
    cluster_bits = _field(head, 20, 4)
    if cluster_bits < 9 or cluster_bits > 21:
        raise MediaError("unsupported QCOW2 cluster size")
    cluster_size = 1 << cluster_bits
    if (_field(head, 8, 8) or _field(head, 16, 4)):
        raise MediaError("QCOW2 backing file is forbidden")
    if _field(head, 24, 8) != expected_virtual_size:
        raise MediaError("QCOW2 virtual size differs from approved profile")
    if _field(head, 32, 4):
        raise MediaError("encrypted QCOW2 is not supported")
    if _field(head, 60, 4) or _field(head, 64, 8):
        raise MediaError("QCOW2 internal snapshots are forbidden")
    if version == 3:
        if _field(head, 72, 8):
            # Includes external-data-file, dirty, corrupt and extended-L2 flags.
            raise MediaError("QCOW2 incompatible/external-data features are forbidden")
        if _field(head, 88, 8):
            raise MediaError("QCOW2 autoclear/external-data features are forbidden")
        header_length = _field(head, 100, 4)
        if (header_length < 104 or header_length % 8 or
                header_length + 8 > cluster_size):
            raise MediaError("QCOW2 v3 header length invalid")
    else:
        header_length = 72
    # Parse bounded header-extension descriptors. Do not interpret external
    # names; refuse every path-bearing or unknown extension, even if its
    # corresponding incompatible flag was maliciously omitted.
    cursor = header_length
    while cursor + 8 <= cluster_size:
        extension = os.pread(fd, 8, cursor)
        if len(extension) < 8:
            raise MediaError("truncated QCOW2 header-extension terminator")
        kind = _field(extension, 0, 4)
        length = _field(extension, 4, 4)
        if kind == 0:
            if length:
                raise MediaError("invalid QCOW2 extension terminator")
            break
        if kind != FEATURE_NAMES_EXTENSION:
            raise MediaError("unreviewed/path-bearing QCOW2 header extension")
        cursor += 8 + ((length + 7) // 8) * 8
        if cursor + 8 > cluster_size or cursor > before.st_size:
            raise MediaError("QCOW2 header extension exceeds its cluster")
    else:
        raise MediaError("QCOW2 header extension terminator is missing")
    after = os.fstat(fd)
    ident = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size,
                       s.st_mtime_ns, s.st_ctime_ns)
    if ident(before) != ident(after):
        raise MediaError("QCOW2 changed during header inspection")
    return {"version": version, "virtual_size": expected_virtual_size,
            "physical_size": before.st_size}


def validate_qemu_info(info: object, expected_virtual_size: int) -> None:
    """Validate the complete security-relevant qemu-img info JSON."""
    if not isinstance(info, dict) or info.get("format") != "qcow2":
        raise MediaError("qemu-img did not identify a QCOW2 file")
    size = info.get("virtual-size")
    if type(size) is not int or size != expected_virtual_size:
        raise MediaError("qemu-img reported unexpected virtual size")
    if any(key in info for key in
           ("backing-filename", "full-backing-filename", "backing-image")):
        raise MediaError("qemu-img reported an external backing image")
    if info.get("encrypted") or info.get("snapshots"):
        raise MediaError("encrypted QCOW2 or internal snapshots are forbidden")
    specific = info.get("format-specific", {})
    if not isinstance(specific, dict):
        raise MediaError("invalid format-specific QCOW2 metadata")
    if specific and specific.get("type") != "qcow2":
        raise MediaError("unexpected format-specific disk type")
    details = specific.get("data", {})
    if not isinstance(details, dict):
        raise MediaError("invalid QCOW2 format-specific data")
    if any(details.get(key) for key in
           ("data-file", "data-file-raw", "encrypt", "backing-filename",
            "backing-file", "bitmaps", "snapshots")):
        raise MediaError("qemu-img reported external/encrypted/snapshot data")
