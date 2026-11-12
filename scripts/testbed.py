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

try:
    from . import safe_fs
except ImportError:  # direct invocation
    import safe_fs

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
    return path


def state_dir(text: str, *, must_exist: bool = False) -> Path:
    """Validate trusted ancestors; mutating operations later pin their own FDs."""
    root = absolute_path(text)
    if root == REPO or REPO in root.parents:
        raise TestbedError("state must live outside the Git repository")
    # This closes the lower-trust ancestor boundary even when the root is absent.
    with safe_fs.directory(root.parent):
        pass
    if root.exists():
        with safe_fs.lab_directory(root):
            pass
    elif must_exist:
        raise TestbedError("state directory not prepared")
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
    forbidden = {"interface", "graphics", "hostdev", "filesystem", "redirdev",
                 "channel", "shmem", "smartcard", "tpm", "commandline"}
    if any(node.tag in forbidden for node in domain.iter()):
        raise TestbedError("network, passthrough, or command-line override present")
    os_type = domain.find("os/type")
    if os_type is None or os_type.get("arch") != "x86_64" or os_type.text != "hvm":
        raise TestbedError("unexpected guest architecture or OS type")
    vcpu = domain.findtext("vcpu")
    if vcpu != str(cfg["vcpus"]):
        raise TestbedError("vCPU count does not match the profile")
    memory = domain.find("memory")
    if memory is None:
        raise TestbedError("missing memory configuration")
    memory_bytes = cfg["memory_mib"] * 1024 * 1024
    units = {"MiB": 1024 * 1024, "KiB": 1024}
    if memory.get("unit") not in units or int(memory.text or "0") * units[memory.get("unit")] != memory_bytes:
        raise TestbedError("memory allocation differs from the profile")
    for port in devices.findall("serial") + devices.findall("console"):
        if port.get("type") != "pty":
            raise TestbedError("only local PTY serial/console devices are allowed")
        if any(child.tag not in {"source", "target", "alias", "address"} for child in port):
            raise TestbedError("unexpected serial/console attachment")
        for source in port.findall("source"):
            if set(source.attrib) != {"path"} or not re.fullmatch(r"/dev/pts/[0-9]+", source.get("path", "")):
                raise TestbedError("unexpected PTY source path")
    for item in devices.findall("input"):
        if (item.get("type") not in {"mouse", "tablet", "keyboard"}
                or item.get("bus") not in {None, "ps2", "usb", "virtio"}
                or item.find("source") is not None):
            raise TestbedError("host input passthrough is forbidden")
    for item in devices.findall("video"):
        if item.find(".//acceleration[@accel3d='yes']") is not None:
            raise TestbedError("3D host GPU acceleration is forbidden")
    emulator = devices.find("emulator")
    if emulator is not None and emulator.text not in {
        "/usr/bin/qemu-system-x86_64", "/usr/libexec/qemu-kvm"
    }:
        raise TestbedError("unapproved QEMU emulator executable")
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


def _diagnostic(value: str | bytes | None) -> str:
    """Retain captured negative-result text across subprocess error types."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="backslashreplace")
    return value


def local_command(args: list[str], timeout: int = 30,
                  *, pass_fds: tuple[int, ...] = ()) -> str:
    try:
        result = subprocess.run(args, check=True, timeout=timeout,
                                capture_output=True, text=True, pass_fds=pass_fds)
    except subprocess.CalledProcessError as exc:
        raise TestbedError(
            f"{args[0]} returned exit status {exc.returncode}; "
            f"captured stdout: {_diagnostic(exc.stdout)}; "
            f"captured stderr: {_diagnostic(exc.stderr)}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise TestbedError(
            f"{args[0]} timed out after {exc.timeout}s; "
            f"captured stdout: {_diagnostic(exc.stdout)}; "
            f"captured stderr: {_diagnostic(exc.stderr)}"
        ) from exc
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
    # Keep an operator-owned, private lab FD open across all host mutations.
    # qemu-img receives an inherited FD, never a mutable ancestor pathname.
    with safe_fs.lab_directory(root, create=True) as lab_fd:
        if any(safe_fs.exists_at(lab_fd, name)
               for name in ("disk.qcow2", "domain.xml")):
            raise TestbedError("refusing to replace existing disk/XML")
        disk_fd = os.open("disk.qcow2",
                          safe_fs.FILE_RDWR_CREATE_FLAGS,
                          0o600, dir_fd=lab_fd)
        try:
            local_command(["qemu-img", "create", "-f", "qcow2",
                           f"/proc/self/fd/{disk_fd}", f"{cfg['disk_gib']}G"],
                          timeout=120, pass_fds=(disk_fd,))
        finally:
            os.close(disk_fd)
        fd = os.open("domain.xml", safe_fs.FILE_WRITE_FLAGS, 0o600,
                     dir_fd=lab_fd)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(xml)
            stream.flush()
            os.fsync(stream.fileno())
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


def hash_fd(fd: int) -> tuple[str, int]:
    """Hash a stable, already opened regular descriptor."""
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise TestbedError("snapshot output is not a regular file")
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    count = 0
    for chunk in iter(lambda: os.read(fd, 1024 * 1024), b""):
        digest.update(chunk)
        count += len(chunk)
    after = os.fstat(fd)
    if ((before.st_dev, before.st_ino, before.st_size,
         before.st_mtime_ns, before.st_ctime_ns)
        != (after.st_dev, after.st_ino, after.st_size,
            after.st_mtime_ns, after.st_ctime_ns) or count != after.st_size):
        raise TestbedError("snapshot image changed during hashing")
    return digest.hexdigest(), count


def snapshot(cfg: dict, root: Path, iso: Path, label: str, sha: str,
             token: str | None) -> dict:
    approve(token, SNAPSHOT_TOKEN)
    if LABEL.fullmatch(label) is None or SHA.fullmatch(sha) is None:
        raise TestbedError("invalid snapshot label or exact Git commit SHA")
    need("qemu-img")
    with safe_fs.lab_directory(root) as lab_fd:
        source_fd = safe_fs.regular_at(lab_fd, "disk.qcow2")
        try:
            audit_defined(cfg, root, iso)
            state = local_command(["virsh", "-c", URI, "domstate", cfg["name"]])
            if state != "shut off":
                raise TestbedError(f"domain is not shut off: {state}")
            source_path = f"/proc/self/fd/{source_fd}"
            metadata = json.loads(local_command(
                ["qemu-img", "info", "--output=json", source_path],
                pass_fds=(source_fd,)))
            if metadata.get("format") != "qcow2" or metadata.get("backing-filename"):
                raise TestbedError("only standalone QCOW2 images are supported")
            source_before = os.fstat(source_fd)
            with safe_fs.private_child_directory(lab_fd, "snapshots",
                                                 create=True) as snapshot_fd:
                destination = f"{label}.qcow2"
                receipt_name = f"{label}.receipt.json"
                if (safe_fs.exists_at(snapshot_fd, destination)
                        or safe_fs.exists_at(snapshot_fd, receipt_name)):
                    raise TestbedError("snapshot or receipt already exists")
                temporary = f".pending-{secrets.token_hex(16)}.qcow2"
                temp_fd = os.open(temporary, safe_fs.FILE_RDWR_CREATE_FLAGS,
                                  0o600, dir_fd=snapshot_fd)
                published = False
                try:
                    local_command(["qemu-img", "convert", "-f", "qcow2", "-O", "qcow2",
                                   source_path, f"/proc/self/fd/{temp_fd}"],
                                  timeout=3600, pass_fds=(source_fd, temp_fd))
                    source_after = os.fstat(source_fd)
                    if ((source_before.st_size, source_before.st_mtime_ns, source_before.st_ctime_ns)
                         != (source_after.st_size, source_after.st_mtime_ns, source_after.st_ctime_ns)):
                        raise TestbedError("source disk changed during offline copy")
                    digest, size = hash_fd(temp_fd)
                    report = {
                        "schema": "qsol-rhel-snapshot/v1", "domain": cfg["name"],
                        "label": label, "source_commit": sha, "sha256": digest,
                        "bytes": size, "captured_utc": datetime.now(timezone.utc).isoformat(),
                        "claim": "OFFLINE_DISK_COPY_ONLY",
                        "limitation": "A non-cooperating writer may still change guest state.",
                    }
                    os.link(temporary, destination, src_dir_fd=snapshot_fd,
                            dst_dir_fd=snapshot_fd, follow_symlinks=False)
                    published = True
                    fd = os.open(receipt_name, safe_fs.FILE_WRITE_FLAGS,
                                 0o600, dir_fd=snapshot_fd)
                    with os.fdopen(fd, "w", encoding="utf-8") as stream:
                        json.dump(report, stream, indent=2, sort_keys=True)
                        stream.write("\n")
                        stream.flush()
                        os.fsync(stream.fileno())
                except Exception:
                    if published:
                        os.unlink(destination, dir_fd=snapshot_fd)
                    raise
                finally:
                    os.close(temp_fd)
                    os.unlink(temporary, dir_fd=snapshot_fd)
        finally:
            os.close(source_fd)
    return {"status": "SNAPSHOT_CREATED",
            "image": str(root / "snapshots" / f"{label}.qcow2"),
            "receipt": str(root / "snapshots" / f"{label}.receipt.json"),
            "sha256": digest}


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
    except (TestbedError, safe_fs.UnsafePath, OSError, ValueError, subprocess.SubprocessError, ET.ParseError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
