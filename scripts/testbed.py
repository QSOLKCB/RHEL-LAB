#!/usr/bin/env python3
"""Local-only KVM/libvirt testbed. No guest boot, network, or sudo commands."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

SCHEMA = "qsol-rhel-testbed/v1"
REPO = Path(__file__).resolve().parent.parent
URI = "qemu:///session"
PREPARE_TOKEN = "I_AUTHORIZE_LOCAL_VM_PREPARATION"
SNAPSHOT_TOKEN = "I_AUTHORIZE_OFFLINE_SNAPSHOT"
NAME = re.compile(r"rhel-lab-[a-z0-9][a-z0-9-]{0,30}\Z")
LABEL = re.compile(r"[a-z][a-z0-9-]{0,39}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")


class TestbedError(ValueError):
    """Refused unsafe or unsupported operation."""


def _pairs(items: list[tuple[str, object]]) -> dict:
    out = {}
    for key, value in items:
        if key in out:
            raise TestbedError(f"duplicate JSON property: {key}")
        out[key] = value
    return out


def read_config(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        cfg = json.load(stream, object_pairs_hook=_pairs)
    fields = {"schema", "name", "architecture", "network", "vcpus",
              "memory_mib", "disk_gib"}
    if not isinstance(cfg, dict) or set(cfg) != fields:
        raise TestbedError("unsupported configuration schema/fields")
    if cfg["schema"] != SCHEMA or cfg["architecture"] != "x86_64" or cfg["network"] != "none":
        raise TestbedError("only x86_64 and network=none are allowed")
    if not isinstance(cfg["name"], str) or NAME.fullmatch(cfg["name"]) is None:
        raise TestbedError("invalid VM name")
    for field, lower, upper in (("vcpus", 1, 32), ("memory_mib", 1024, 32768),
                                ("disk_gib", 16, 512)):
        if type(cfg[field]) is not int or not lower <= cfg[field] <= upper:
            raise TestbedError(f"{field} must be integer between {lower} and {upper}")
    return cfg


def absolute_path(text: str) -> Path:
    path = Path(text)
    if not path.is_absolute() or ".." in path.parts:
        raise TestbedError("all host paths must be absolute without ..")
    for entry in (path, *path.parents):
        if entry.is_symlink():
            raise TestbedError(f"symlink in host path: {entry}")
    return path.resolve(strict=False)


def state_dir(text: str, *, must_exist: bool = False) -> Path:
    root = absolute_path(text)
    if root == REPO or REPO in root.parents:
        raise TestbedError("state must live outside the Git repository")
    if root.exists():
        if not root.is_dir():
            raise TestbedError("state path is not a directory")
        info = root.stat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise TestbedError("state directory must be user-owned and mode 0700")
    elif must_exist:
        raise TestbedError("state directory not prepared")
    elif not root.parent.is_dir():
        raise TestbedError("state directory parent must already exist")
    return root


def iso_file(text: str) -> Path:
    path = absolute_path(text)
    if path.suffix.lower() != ".iso" or not path.is_file():
        raise TestbedError("ISO must be an existing regular .iso file")
    return path


def paths(root: Path) -> tuple[Path, Path]:
    return root / "disk.qcow2", root / "domain.xml"


def render_xml(cfg: dict, root: Path, iso: Path) -> str:
    disk, _ = paths(root)
    domain = ET.Element("domain", {"type": "kvm"})
    ET.SubElement(domain, "name").text = cfg["name"]
    ET.SubElement(domain, "memory", {"unit": "MiB"}).text = str(cfg["memory_mib"])
    ET.SubElement(domain, "vcpu").text = str(cfg["vcpus"])
    os_node = ET.SubElement(domain, "os")
    ET.SubElement(os_node, "type", {"arch": "x86_64"}).text = "hvm"
    ET.SubElement(os_node, "boot", {"dev": "cdrom"})
    ET.SubElement(os_node, "boot", {"dev": "hd"})
    devices = ET.SubElement(domain, "devices")
    for kind, filename, fmt, target, bus in (
        ("disk", disk, "qcow2", "vda", "virtio"),
        ("cdrom", iso, "raw", "sda", "sata"),
    ):
        node = ET.SubElement(devices, "disk", {"type": "file", "device": kind})
        ET.SubElement(node, "driver", {"name": "qemu", "type": fmt})
        ET.SubElement(node, "source", {"file": str(filename)})
        ET.SubElement(node, "target", {"dev": target, "bus": bus})
        if kind == "cdrom":
            ET.SubElement(node, "readonly")
    serial = ET.SubElement(devices, "serial", {"type": "pty"})
    ET.SubElement(serial, "target", {"port": "0"})
    console = ET.SubElement(devices, "console", {"type": "pty"})
    ET.SubElement(console, "target", {"type": "serial", "port": "0"})
    ET.indent(domain)
    xml = ET.tostring(domain, encoding="unicode") + "\n"
    audit_xml(xml, cfg, root, iso)
    return xml


def audit_xml(xml: str, cfg: dict, root: Path, iso: Path) -> None:
    """Reject interfaces, passthrough, external listeners and unexpected disk paths."""
    domain = ET.fromstring(xml)
    if domain.tag != "domain" or domain.get("type") != "kvm":
        raise TestbedError("domain must use KVM")
    if any("}" in node.tag for node in domain.iter()):
        raise TestbedError("namespaced QEMU overrides or extensions are forbidden")
    if domain.findtext("name") != cfg["name"]:
        raise TestbedError("VM name differs from approved profile")
    devices = domain.find("devices")
    if devices is None:
        raise TestbedError("missing VM devices")
    allowed = {"disk", "serial", "console", "controller", "input", "video",
               "memballoon", "emulator"}
    unexpected = {d.tag for d in devices} - allowed
    if unexpected:
        raise TestbedError(f"unexpected devices: {sorted(unexpected)}")
    if any(b.get("dev") not in {"cdrom", "hd"} for b in domain.findall(".//boot")):
        raise TestbedError("non-disk or network boot is forbidden")
    expected = {"disk": (str(root / "disk.qcow2"), "qcow2"),
                "cdrom": (str(iso), "raw")}
    actual_disks = devices.findall("disk")
    if len(actual_disks) != 2:
        raise TestbedError("expected exactly disk and ISO")
    for item in actual_disks:
        kind = item.get("device")
        if kind not in expected or item.get("type") != "file":
            raise TestbedError("unknown disk/device source")
        file_path, fmt = expected.pop(kind)
        src, driver = item.find("source"), item.find("driver")
        if src is None or src.get("file") != file_path:
            raise TestbedError(f"unsafe {kind} source")
        if driver is None or driver.get("type") != fmt or driver.get("name") != "qemu":
            raise TestbedError(f"unsafe {kind} format")
        if kind == "cdrom" and item.find("readonly") is None:
            raise TestbedError("ISO must remain read-only")
    if expected:
        raise TestbedError("disk or ISO missing")


def local_command(args: list[str], timeout: int = 30) -> str:
    result = subprocess.run(args, check=True, timeout=timeout, capture_output=True, text=True)
    return result.stdout.strip()


def need(command: str) -> None:
    if shutil.which(command) is None:
        raise TestbedError(f"missing local dependency: {command}")


def approve(value: str | None, expected: str) -> None:
    if value != expected:
        raise TestbedError(f"explicit --approve {expected} required")


def plan(cfg: dict, root: Path, iso: Path) -> dict:
    disk, definition = paths(root)
    return {
        "status": "PLANNED_NOT_EXECUTED", "connection": URI, "network": "none",
        "disk": str(disk), "definition": str(definition), "iso": str(iso),
        "size_gib": cfg["disk_gib"], "xml": render_xml(cfg, root, iso),
    }


def prepare(cfg: dict, root: Path, iso: Path, token: str | None) -> dict:
    approve(token, PREPARE_TOKEN)
    need("qemu-img")
    disk, definition = paths(root)
    xml = render_xml(cfg, root, iso)
    if any(path.exists() or path.is_symlink() for path in (disk, definition)):
        raise TestbedError("refusing to replace existing disk/XML")
    if not root.exists():
        root.mkdir(mode=0o700)
    old_umask = os.umask(0o077)
    try:
        local_command(["qemu-img", "create", "-f", "qcow2",
                       str(disk), f"{cfg['disk_gib']}G"], timeout=120)
        fd = os.open(definition, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(xml)
    finally:
        os.umask(old_umask)
    return {"status": "PREPARED_NOT_DEFINED_OR_BOOTED",
            "definition": str(definition), "disk": str(disk),
            "manual_next": f"virsh -c {URI} define {definition}"}


def audit_defined(cfg: dict, root: Path, iso: Path) -> dict:
    need("virsh")
    # Verify stored XML AND current (possibly live/hotplugged) XML.
    for options in (["--inactive"], []):
        xml = local_command(["virsh", "-c", URI, "dumpxml", *options, cfg["name"]])
        audit_xml(xml, cfg, root, iso)
    return {"status": "DOMAIN_XML_AUDITED", "domain": cfg["name"],
            "limitation": "Does not prove host egress isolation or prevent races."}


def hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def snapshot(cfg: dict, root: Path, iso: Path, label: str, sha: str,
             token: str | None) -> dict:
    approve(token, SNAPSHOT_TOKEN)
    if LABEL.fullmatch(label) is None or SHA.fullmatch(sha) is None:
        raise TestbedError("invalid snapshot label or exact Git commit SHA")
    need("qemu-img")
    disk, _ = paths(root)
    if disk.is_symlink() or not disk.is_file():
        raise TestbedError("local disk absent or symlinked")
    folder = root / "snapshots"
    if folder.is_symlink() or (folder.exists() and not folder.is_dir()):
        raise TestbedError("snapshots directory is unsafe")
    dest = folder / f"{label}.qcow2"
    receipt = folder / f"{label}.receipt.json"
    if any(p.exists() or p.is_symlink() for p in (dest, receipt)):
        raise TestbedError("snapshot or receipt already exists")
    audit_defined(cfg, root, iso)
    state = local_command(["virsh", "-c", URI, "domstate", cfg["name"]])
    if state != "shut off":
        raise TestbedError(f"domain is not shut off: {state}")
    metadata = json.loads(local_command(["qemu-img", "info", "--output=json", str(disk)]))
    if metadata.get("format") != "qcow2" or metadata.get("backing-filename"):
        raise TestbedError("only standalone QCOW2 images are supported")
    if not folder.exists():
        folder.mkdir(mode=0o700)
    temporary = folder / f".pending-{secrets.token_hex(16)}.qcow2"
    if temporary.exists():
        raise TestbedError("temporary snapshot name collision")
    # QEMU warns against processing disks being used by another process.
    local_command(["qemu-img", "convert", "-f", "qcow2", "-O", "qcow2",
                   str(disk), str(temporary)], timeout=3600)
    if temporary.is_symlink() or not temporary.is_file():
        raise TestbedError("conversion did not produce a regular disk image")
    digest, size = hash_file(temporary)
    os.link(temporary, dest)  # atomic no-clobber publication
    temporary.unlink()
    report = {
        "schema": "qsol-rhel-snapshot/v1", "domain": cfg["name"],
        "label": label, "source_commit": sha, "sha256": digest,
        "bytes": size, "captured_utc": datetime.now(timezone.utc).isoformat(),
        "claim": "OFFLINE_DISK_COPY_ONLY",
        "limitation": "No guarantee against another process starting/writing this VM.",
    }
    with receipt.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return {"status": "SNAPSHOT_CREATED", "image": str(dest),
            "receipt": str(receipt), "sha256": digest}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="action", required=True)
    for name in ("plan", "prepare", "audit-defined", "snapshot"):
        p = subs.add_parser(name)
        p.add_argument("--config", type=Path, default=REPO / "lab/testbed.json")
        p.add_argument("--lab-root", required=True)
        p.add_argument("--iso", required=True)
        if name in {"prepare", "snapshot"}:
            p.add_argument("--approve")
        if name == "snapshot":
            p.add_argument("--label", required=True)
            p.add_argument("--source-sha", required=True)
    args = parser.parse_args(argv)
    try:
        cfg = read_config(args.config)
        root = state_dir(args.lab_root, must_exist=args.action in {"audit-defined", "snapshot"})
        iso = iso_file(args.iso)
        if args.action == "plan":
            report = plan(cfg, root, iso)
        elif args.action == "prepare":
            report = prepare(cfg, root, iso, args.approve)
        elif args.action == "audit-defined":
            report = audit_defined(cfg, root, iso)
        else:
            report = snapshot(cfg, root, iso, args.label, args.source_sha, args.approve)
    except (TestbedError, OSError, ValueError, subprocess.SubprocessError, ET.ParseError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
