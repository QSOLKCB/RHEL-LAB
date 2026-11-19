#!/usr/bin/env python3
"""Local-only KVM/libvirt testbed. No guest boot, network, or sudo commands."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import resource
from functools import partial
import re
import secrets
import stat
import subprocess
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from xml.etree import ElementTree as ET

try:
    from . import media_guard, safe_fs
except ImportError:  # direct invocation
    import media_guard
    import safe_fs

SCHEMA = "qsol-rhel-testbed/v1"
REPO = Path(__file__).resolve().parent.parent
URI = "qemu:///session"
PREPARE_TOKEN = "I_AUTHORIZE_LOCAL_VM_PREPARATION"
SNAPSHOT_TOKEN = "I_AUTHORIZE_OFFLINE_SNAPSHOT"
NAME = re.compile(r"rhel-lab-[a-z0-9][a-z0-9-]{0,30}\Z")
LABEL = re.compile(r"[a-z][a-z0-9-]{0,39}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MEDIA_SCHEMA = "qsol-rhel-staged-media/v1"
STAGED_ISO = "installer.iso"
MEDIA_RECEIPT = "installer.iso.receipt.json"
MAX_CONFIG_BYTES = 64 * 1024
HELPER_PATHS = {
    "qemu-img": Path("/usr/bin/qemu-img"),
    "virsh": Path("/usr/bin/virsh"),
}
COMMAND_PATH = "/usr/bin"
MAX_HELPER_OUTPUT = 1024 * 1024


class TestbedError(ValueError):
    """Refused unsafe or unsupported operation."""


@dataclass(frozen=True)
class PinnedHelper:
    """Trusted executable identity held open across every invocation."""

    name: str
    path: Path
    fd: int
    device: int
    inode: int


def _pairs(items: list[tuple[str, object]]) -> dict:
    out = {}
    for key, value in items:
        if key in out:
            raise TestbedError(f"duplicate JSON property: {key}")
        out[key] = value
    return out


def _reject_nonfinite_constant(value: str) -> None:
    raise TestbedError(f"non-finite JSON constant is forbidden: {value}")


def read_config(path: Path) -> dict:
    """Parse a bounded, trusted regular config without following symlinks or FIFOs."""
    with safe_fs.trusted_regular(path) as fd:
        before = os.fstat(fd)
        if before.st_size > MAX_CONFIG_BYTES:
            raise TestbedError("configuration exceeds 64 KiB size limit")
        chunks: list[bytes] = []
        read_count = 0
        while read_count <= MAX_CONFIG_BYTES:
            chunk = os.read(fd, min(4096, MAX_CONFIG_BYTES + 1 - read_count))
            if not chunk:
                break
            chunks.append(chunk)
            read_count += len(chunk)
        if read_count > MAX_CONFIG_BYTES:
            raise TestbedError("configuration exceeds 64 KiB size limit")
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size,
                              s.st_mtime_ns, s.st_ctime_ns)
        if read_count != before.st_size or identity(before) != identity(after):
            raise TestbedError("configuration changed while reading")
    try:
        cfg = json.loads(b"".join(chunks).decode("utf-8"),
                         object_pairs_hook=_pairs,
                         parse_constant=_reject_nonfinite_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise TestbedError("configuration is not valid bounded UTF-8 JSON") from exc
    fields = {"schema", "name", "architecture", "network", "vcpus",
              "memory_mib", "disk_gib"}
    if not isinstance(cfg, dict) or set(cfg) != fields:
        raise TestbedError("unsupported configuration schema/fields")
    if cfg["schema"] != SCHEMA or cfg["architecture"] != "x86_64" or cfg["network"] != "none":
        raise TestbedError("only x86_64 and network=none are allowed")
    if not isinstance(cfg["name"], str) or NAME.fullmatch(cfg["name"]) is None:
        raise TestbedError("invalid VM name")
    for field, lower, upper in (("vcpus", 1, 32), ("memory_mib", 1024, 32768),
                                ("disk_gib", 16, media_guard.MAX_DISK_GIB)):
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
    if path.suffix.lower() != ".iso":
        raise TestbedError("ISO must be an existing regular .iso file")
    with safe_fs.trusted_regular(path) as fd:
        media_guard.iso_size(fd)
    return path


def paths(root: Path) -> tuple[Path, Path]:
    return root / "disk.qcow2", root / "domain.xml"


def staged_iso(root: Path) -> Path:
    return root / STAGED_ISO


def render_xml(cfg: dict, root: Path) -> str:
    disk, _ = paths(root)
    iso = staged_iso(root)
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
    audit_xml(xml, cfg, root)
    return xml


_DOMAIN_XML_SHAPE = {
    ("domain",): (
        {"type", "id"},
        {"name", "uuid", "memory", "currentMemory", "vcpu", "os", "features",
         "cpu", "clock", "on_poweroff", "on_reboot", "on_crash", "pm", "devices",
         "seclabel"},
    ),
    ("domain", "name"): (set(), set()),
    ("domain", "uuid"): (set(), set()),
    ("domain", "memory"): ({"unit"}, set()),
    ("domain", "currentMemory"): ({"unit"}, set()),
    ("domain", "vcpu"): ({"placement", "current"}, set()),
    ("domain", "os"): (set(), {"type", "boot"}),
    ("domain", "os", "type"): ({"arch", "machine"}, set()),
    ("domain", "os", "boot"): ({"dev"}, set()),
    ("domain", "features"): (set(), {"acpi", "apic"}),
    ("domain", "features", "acpi"): (set(), set()),
    ("domain", "features", "apic"): (set(), set()),
    ("domain", "cpu"): ({"mode", "match", "check", "migratable"},
                         {"model", "vendor", "feature", "topology"}),
    ("domain", "cpu", "model"): ({"fallback"}, set()),
    ("domain", "cpu", "vendor"): (set(), set()),
    ("domain", "cpu", "feature"): ({"policy", "name"}, set()),
    ("domain", "cpu", "topology"): (
        {"sockets", "dies", "clusters", "cores", "threads"}, set()),
    ("domain", "clock"): ({"offset"}, {"timer"}),
    ("domain", "clock", "timer"): (
        {"name", "tickpolicy", "present", "track", "mode", "frequency"}, {"catchup"}),
    ("domain", "clock", "timer", "catchup"): ({"threshold", "slew", "limit"}, set()),
    ("domain", "on_poweroff"): (set(), set()),
    ("domain", "on_reboot"): (set(), set()),
    ("domain", "on_crash"): (set(), set()),
    ("domain", "pm"): (set(), {"suspend-to-mem", "suspend-to-disk"}),
    ("domain", "pm", "suspend-to-mem"): ({"enabled"}, set()),
    ("domain", "pm", "suspend-to-disk"): ({"enabled"}, set()),
    ("domain", "seclabel"): ({"type", "model", "relabel"}, {"label", "imagelabel"}),
    ("domain", "seclabel", "label"): (set(), set()),
    ("domain", "seclabel", "imagelabel"): (set(), set()),
    ("domain", "devices"): (
        set(), {"disk", "serial", "console", "controller", "input", "video",
                "memballoon", "emulator"}),
    ("domain", "devices", "disk"): (
        {"type", "device"},
        {"driver", "source", "target", "readonly", "alias", "address", "backingStore"}),
    ("domain", "devices", "disk", "driver"): ({"name", "type"}, set()),
    ("domain", "devices", "disk", "source"): ({"file", "index"}, set()),
    ("domain", "devices", "disk", "target"): ({"dev", "bus"}, set()),
    ("domain", "devices", "disk", "readonly"): (set(), set()),
    ("domain", "devices", "disk", "alias"): ({"name"}, set()),
    ("domain", "devices", "disk", "address"): (
        {"type", "domain", "bus", "slot", "function", "controller", "target", "unit"},
        set()),
    # Libvirt emits an empty marker for a standalone image. Any backing attributes or
    # descendants are rejected by the recursive shape check.
    ("domain", "devices", "disk", "backingStore"): (set(), set()),
    ("domain", "devices", "serial"): (
        {"type"}, {"source", "target", "alias", "address"}),
    ("domain", "devices", "serial", "source"): ({"path"}, set()),
    ("domain", "devices", "serial", "target"): ({"type", "port"}, {"model"}),
    ("domain", "devices", "serial", "target", "model"): ({"name"}, set()),
    ("domain", "devices", "serial", "alias"): ({"name"}, set()),
    ("domain", "devices", "serial", "address"): (
        {"type", "iobase", "irq"}, set()),
    ("domain", "devices", "console"): (
        {"type", "tty"}, {"source", "target", "alias", "address"}),
    ("domain", "devices", "console", "source"): ({"path"}, set()),
    ("domain", "devices", "console", "target"): ({"type", "port"}, set()),
    ("domain", "devices", "console", "alias"): ({"name"}, set()),
    ("domain", "devices", "console", "address"): (
        {"type", "iobase", "irq"}, set()),
    ("domain", "devices", "controller"): (
        {"type", "index", "model", "ports"}, {"model", "target", "alias", "address"}),
    ("domain", "devices", "controller", "model"): ({"name"}, set()),
    ("domain", "devices", "controller", "target"): (
        {"chassis", "port", "busNr", "index", "memReserve"}, set()),
    ("domain", "devices", "controller", "alias"): ({"name"}, set()),
    ("domain", "devices", "controller", "address"): (
        {"type", "domain", "bus", "slot", "function", "controller", "target", "unit",
         "port", "multifunction"}, set()),
    ("domain", "devices", "input"): ({"type", "bus"}, {"alias", "address"}),
    ("domain", "devices", "input", "alias"): ({"name"}, set()),
    ("domain", "devices", "input", "address"): (
        {"type", "domain", "bus", "slot", "function", "controller", "port"}, set()),
    ("domain", "devices", "video"): (set(), {"model", "alias", "address"}),
    ("domain", "devices", "video", "model"): (
        {"type", "ram", "vram", "vgamem", "heads", "primary"}, set()),
    ("domain", "devices", "video", "alias"): ({"name"}, set()),
    ("domain", "devices", "video", "address"): (
        {"type", "domain", "bus", "slot", "function"}, set()),
    ("domain", "devices", "memballoon"): ({"model"}, {"alias", "address", "stats"}),
    ("domain", "devices", "memballoon", "alias"): ({"name"}, set()),
    ("domain", "devices", "memballoon", "address"): (
        {"type", "domain", "bus", "slot", "function"}, set()),
    ("domain", "devices", "memballoon", "stats"): ({"period"}, set()),
    ("domain", "devices", "emulator"): (set(), set()),
}


def _audit_xml_shape(node: ET.Element, path: tuple[str, ...] = ("domain",)) -> None:
    """Fail closed on XML outside the reviewed libvirt-normalized profile."""
    allowed_attributes, allowed_children = _DOMAIN_XML_SHAPE[path]
    unexpected_attributes = set(node.attrib) - allowed_attributes
    if unexpected_attributes:
        raise TestbedError(
            f"unexpected attributes on {'/'.join(path)}: {sorted(unexpected_attributes)}")
    for child in node:
        if child.tag not in allowed_children:
            raise TestbedError(f"unexpected XML element: {'/'.join((*path, child.tag))}")
        _audit_xml_shape(child, (*path, child.tag))


def _single(parent: ET.Element, tag: str, *, required: bool = True) -> ET.Element | None:
    matches = parent.findall(tag)
    if len(matches) > 1 or required and len(matches) != 1:
        raise TestbedError(f"expected {'one' if required else 'at most one'} {tag} element")
    return matches[0] if matches else None


def _memory_matches(node: ET.Element | None, expected_bytes: int) -> bool:
    if node is None:
        return False
    units = {"MiB": 1024 * 1024, "KiB": 1024}
    unit = node.get("unit")
    return unit in units and int(node.text or "0") * units[unit] == expected_bytes


def audit_xml(xml: str, cfg: dict, root: Path) -> None:
    """Require the complete domain tree to match the reviewed offline profile."""
    domain = ET.fromstring(xml)
    if domain.tag != "domain" or domain.get("type") != "kvm":
        raise TestbedError("domain must use KVM")
    if any("}" in node.tag or any("}" in name for name in node.attrib)
           for node in domain.iter()):
        raise TestbedError("namespaced QEMU overrides or extensions are forbidden")
    _audit_xml_shape(domain)
    if domain.get("id") is not None and not domain.get("id", "").isdigit():
        raise TestbedError("invalid active domain identifier")
    name = _single(domain, "name")
    if name is None or name.text != cfg["name"]:
        raise TestbedError("VM name differs from approved profile")
    uuid = _single(domain, "uuid", required=False)
    if uuid is not None and re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", uuid.text or "") is None:
        raise TestbedError("invalid libvirt domain UUID")
    os_node = _single(domain, "os")
    if os_node is None:
        raise TestbedError("missing VM operating-system profile")
    os_type = _single(os_node, "type")
    if os_type is None or os_type.get("arch") != "x86_64" or os_type.text != "hvm":
        raise TestbedError("unexpected guest architecture or OS type")
    if os_type.get("machine") is not None and re.fullmatch(
            r"[A-Za-z0-9_.+-]+", os_type.get("machine", "")) is None:
        raise TestbedError("invalid normalized machine type")
    boots = os_node.findall("boot")
    if len(boots) != 2 or {boot.get("dev") for boot in boots} != {"cdrom", "hd"}:
        raise TestbedError("only CD-ROM and disk boot are allowed")
    vcpu = _single(domain, "vcpu")
    if vcpu is None or vcpu.text != str(cfg["vcpus"]):
        raise TestbedError("vCPU count does not match the profile")
    if vcpu.get("placement") not in {None, "static"}:
        raise TestbedError("unexpected vCPU placement")
    if vcpu.get("current") not in {None, str(cfg["vcpus"])}:
        raise TestbedError("active vCPU count does not match the profile")
    memory_bytes = cfg["memory_mib"] * 1024 * 1024
    if not _memory_matches(_single(domain, "memory"), memory_bytes):
        raise TestbedError("memory allocation differs from the profile")
    current_memory = _single(domain, "currentMemory", required=False)
    if current_memory is not None and not _memory_matches(current_memory, memory_bytes):
        raise TestbedError("current memory differs from the profile")
    for singleton in ("features", "cpu", "clock", "on_poweroff", "on_reboot",
                      "on_crash", "pm"):
        _single(domain, singleton, required=False)
    for action, expected_action in (("on_poweroff", "destroy"),
                                    ("on_reboot", "restart"),
                                    ("on_crash", "destroy")):
        node = domain.find(action)
        if node is not None and node.text != expected_action:
            raise TestbedError(f"unexpected {action} policy")
    for suspend in domain.findall("pm/*"):
        if suspend.get("enabled") != "no":
            raise TestbedError("invalid power-management policy")
    clock = domain.find("clock")
    if clock is not None and clock.get("offset") != "utc":
        raise TestbedError("only a UTC guest clock is allowed")
    label_models = set()
    for label in domain.findall("seclabel"):
        process_labels = label.findall("label")
        image_labels = label.findall("imagelabel")
        if (label.get("type") != "dynamic" or label.get("relabel") != "yes"
                or label.get("model") not in {"selinux", "dac"}
                or label.get("model") in label_models
                or len(process_labels) > 1 or len(image_labels) > 1
                or len(process_labels) != len(image_labels)):
            raise TestbedError("unapproved domain security label")
        label_models.add(label.get("model"))
        if label.get("model") == "selinux":
            category = r"(?::c[0-9]+,c[0-9]+)?"
            process_pattern = rf"[A-Za-z0-9_]+:[A-Za-z0-9_]+:svirt_t:s0{category}"
            image_pattern = rf"[A-Za-z0-9_]+:[A-Za-z0-9_]+:svirt_image_t:s0{category}"
        else:
            process_pattern = image_pattern = r"\+?[0-9]+:\+?[0-9]+"
        if ((process_labels and re.fullmatch(
                process_pattern, process_labels[0].text or "") is None)
                or (image_labels and re.fullmatch(
                    image_pattern, image_labels[0].text or "") is None)):
            raise TestbedError("invalid dynamic domain security context")
    devices = _single(domain, "devices")
    if devices is None:
        raise TestbedError("missing VM devices")
    if len(devices.findall("serial")) != 1 or len(devices.findall("console")) != 1:
        raise TestbedError("expected exactly one serial device and console")
    if (len(devices.findall("emulator")) > 1 or len(devices.findall("video")) > 1
            or len(devices.findall("memballoon")) > 1):
        raise TestbedError("duplicate emulator, video, or memory balloon device")
    for port in devices.findall("serial") + devices.findall("console"):
        if port.get("type") != "pty":
            raise TestbedError("only local PTY serial/console devices are allowed")
        sources = port.findall("source")
        if len(sources) > 1 or any(
                not re.fullmatch(r"/dev/pts/[0-9]+", source.get("path", ""))
                for source in sources):
            raise TestbedError("unexpected PTY source path")
        if port.get("tty") is not None and (
                len(sources) != 1 or port.get("tty") != sources[0].get("path")):
            raise TestbedError("console TTY differs from its PTY source")
        target = _single(port, "target")
        if target is None or target.get("port") != "0":
            raise TestbedError("unexpected serial/console target")
        if port.tag == "serial" and target.get("type") not in {None, "isa-serial"}:
            raise TestbedError("unexpected serial target type")
        if port.tag == "console" and target.get("type") not in {None, "serial"}:
            raise TestbedError("unexpected console target type")
        model = target.find("model")
        if model is not None and model.get("name") != "isa-serial":
            raise TestbedError("unexpected serial model")
    for item in devices.findall("input"):
        if (item.get("type") not in {"mouse", "tablet", "keyboard"}
                or item.get("bus") not in {None, "ps2", "usb", "virtio"}
                or len(item.findall("alias")) > 1 or len(item.findall("address")) > 1):
            raise TestbedError("host input passthrough is forbidden")
    for item in devices.findall("video"):
        if len(item.findall("model")) != 1:
            raise TestbedError("unexpected video model")
    for item in devices.findall("memballoon"):
        if item.get("model") not in {"virtio", "none"}:
            raise TestbedError("unexpected memory balloon model")
    emulator = devices.find("emulator")
    if emulator is not None and emulator.text not in {
        "/usr/bin/qemu-system-x86_64", "/usr/libexec/qemu-kvm"
    }:
        raise TestbedError("unapproved QEMU emulator executable")
    expected = {"disk": (str(root / "disk.qcow2"), "qcow2", "vda", "virtio"),
                "cdrom": (str(staged_iso(root)), "raw", "sda", "sata")}
    actual_disks = devices.findall("disk")
    if len(actual_disks) != 2:
        raise TestbedError("expected exactly disk and ISO")
    for item in actual_disks:
        kind = item.get("device")
        if kind not in expected or item.get("type") != "file":
            raise TestbedError("unknown disk/device source")
        file_path, fmt, target_name, bus = expected.pop(kind)
        src = _single(item, "source")
        driver = _single(item, "driver")
        target = _single(item, "target")
        if src is None or src.get("file") != file_path:
            raise TestbedError(f"unsafe {kind} source")
        if src.get("index") is not None and not src.get("index", "").isdigit():
            raise TestbedError(f"invalid normalized {kind} source index")
        if driver is None or driver.get("type") != fmt or driver.get("name") != "qemu":
            raise TestbedError(f"unsafe {kind} format")
        if target is None or target.get("dev") != target_name or target.get("bus") != bus:
            raise TestbedError(f"unsafe {kind} target")
        readonly = item.findall("readonly")
        if (kind == "cdrom" and len(readonly) != 1) or (kind == "disk" and readonly):
            raise TestbedError("only the ISO may be read-only")
        for optional in ("alias", "address", "backingStore"):
            if len(item.findall(optional)) > 1:
                raise TestbedError(f"duplicate normalized disk {optional}")
        backing = item.find("backingStore")
        if backing is not None and backing.text and backing.text.strip():
            raise TestbedError("disk backing marker must be empty")
    if expected:
        raise TestbedError("disk or ISO missing")


def _command_environment(helper_name: str) -> dict[str, str]:
    environment = {"PATH": COMMAND_PATH, "LC_ALL": "C"}
    if helper_name == "virsh":
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        runtime_text = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.geteuid()}")
        runtime = Path(runtime_text)
        if not runtime.is_absolute() or ".." in runtime.parts:
            raise TestbedError("XDG_RUNTIME_DIR must be an absolute trusted path")
        with safe_fs.directory(home):
            pass
        with safe_fs.directory(runtime, private=True):
            pass
        environment.update({"HOME": str(home), "XDG_RUNTIME_DIR": str(runtime)})
    return environment


def _executable_by_operator(info: os.stat_result) -> bool:
    if os.geteuid() == 0:
        return bool(info.st_mode & 0o111)
    if info.st_uid == os.geteuid():
        return bool(info.st_mode & stat.S_IXUSR)
    if info.st_gid == os.getegid() or info.st_gid in os.getgroups():
        return bool(info.st_mode & stat.S_IXGRP)
    return bool(info.st_mode & stat.S_IXOTH)


@contextmanager
def pinned_helper(name: str) -> Iterator[PinnedHelper]:
    try:
        path = HELPER_PATHS[name]
    except KeyError as exc:
        raise TestbedError(f"unsupported local dependency: {name}") from exc
    try:
        with safe_fs.trusted_regular(path) as fd:
            info = os.fstat(fd)
            if not _executable_by_operator(info):
                raise TestbedError(f"local dependency is not executable: {path}")
            yield PinnedHelper(name, path, fd, info.st_dev, info.st_ino)
    except FileNotFoundError as exc:
        raise TestbedError(f"missing local dependency: {path}") from exc


def local_command(helper: PinnedHelper, args: list[str], timeout: int = 30,
                  *, pass_fds: tuple[int, ...] = (),
                  file_size_limit: int | None = None) -> str:
    current = os.fstat(helper.fd)
    if (current.st_dev, current.st_ino) != (helper.device, helper.inode):
        raise TestbedError(f"local dependency identity changed: {helper.path}")
    argv = [str(helper.path), *args]
    inherited_fds = tuple(dict.fromkeys((*pass_fds, helper.fd)))
    extra = {}
    if file_size_limit is not None:
        if type(file_size_limit) is not int or file_size_limit <= 0:
            raise TestbedError("invalid subprocess file-size budget")
        # RLIMIT_FSIZE is enforced by the kernel on the child process, not by
        # periodically inspecting a pathname after conversion.
        extra["preexec_fn"] = partial(
            resource.setrlimit, resource.RLIMIT_FSIZE,
            (file_size_limit, file_size_limit))
    # Two independent streams are mandatory: virsh XML, domstate, and qemu-img
    # JSON must never be corrupted by harmless diagnostics on stderr.
    stdout_read, stdout_write = os.pipe()
    try:
        stderr_read, stderr_write = os.pipe()
    except BaseException:
        os.close(stdout_read)
        os.close(stdout_write)
        raise
    captures = {"stdout": bytearray(), "stderr": bytearray()}
    truncation = {"stdout": False, "stderr": False}
    read_errors = []

    def drain_output(fd: int, name: str) -> None:
        try:
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                output = captures[name]
                remaining = MAX_HELPER_OUTPUT - len(output)
                if remaining > 0:
                    output.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncation[name] = True
        except OSError as exc:
            read_errors.append((name, exc))
        finally:
            os.close(fd)

    out_reader = threading.Thread(
        target=drain_output, args=(stdout_read, "stdout"), daemon=True)
    err_reader = threading.Thread(
        target=drain_output, args=(stderr_read, "stderr"), daemon=True)
    try:
        process = subprocess.Popen(
            argv, executable=f"/proc/self/fd/{helper.fd}",
            stdin=subprocess.DEVNULL, stdout=stdout_write, stderr=stderr_write,
            pass_fds=inherited_fds, env=_command_environment(helper.name), **extra)
    except BaseException:
        for fd in (stdout_read, stdout_write, stderr_read, stderr_write):
            os.close(fd)
        raise
    os.close(stdout_write)
    os.close(stderr_write)
    out_reader.start()
    err_reader.start()
    timed_out = None
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        timed_out = exc
        process.kill()
        returncode = process.wait()
    finally:
        # A helper that keeps descendant pipe writers alive must not hang
        # the clean-room CLI indefinitely after its direct child has exited.
        out_reader.join(timeout=5)
        err_reader.join(timeout=5)
    if out_reader.is_alive() or err_reader.is_alive():
        raise TestbedError(f"{helper.path} left output pipes open after exit")
    if read_errors:
        raise TestbedError(f"{helper.path} output capture failed")

    def diagnostic(name: str) -> str:
        value = bytes(captures[name]).decode("utf-8", errors="backslashreplace")
        if truncation[name]:
            value += f"\n[{name} truncated at {MAX_HELPER_OUTPUT} bytes]"
        return value

    stdout = diagnostic("stdout")
    stderr = diagnostic("stderr")
    if timed_out is not None:
        raise TestbedError(
            f"{helper.path} timed out after {timed_out.timeout}s; "
            f"captured stdout: {stdout}; captured stderr: {stderr}") from timed_out
    if returncode != 0:
        raise TestbedError(
            f"{helper.path} returned exit status {returncode}; "
            f"captured stdout: {stdout}; captured stderr: {stderr}")
    return stdout.strip()


def approve(value: str | None, expected: str) -> None:
    if value != expected:
        raise TestbedError(f"explicit --approve {expected} required")


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written == 0:
            raise TestbedError("short write while staging installer ISO")
        view = view[written:]


def _copy_iso(source_fd: int, staged_fd: int) -> tuple[str, int]:
    maximum = media_guard.iso_size(source_fd)
    before = os.fstat(source_fd)
    os.lseek(source_fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    count = 0
    while True:
        chunk = os.read(source_fd, 1024 * 1024)
        if not chunk:
            break
        if count + len(chunk) > maximum:
            raise TestbedError("installer ISO grew beyond its approved size during staging")
        _write_all(staged_fd, chunk)
        digest.update(chunk)
        count += len(chunk)
    os.fsync(staged_fd)
    after = os.fstat(source_fd)
    before_identity = (before.st_dev, before.st_ino, before.st_size,
                       before.st_mtime_ns, before.st_ctime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size,
                      after.st_mtime_ns, after.st_ctime_ns)
    if before_identity != after_identity or count != after.st_size:
        raise TestbedError("installer ISO changed during private staging")
    if os.fstat(staged_fd).st_size != count:
        raise TestbedError("staged installer ISO size differs from source")
    return digest.hexdigest(), count


def _write_json_at(parent_fd: int, name: str, document: dict) -> None:
    fd = os.open(name, safe_fs.FILE_WRITE_FLAGS, 0o600, dir_fd=parent_fd)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def _stage_iso(root: Path, lab_fd: int, source: Path, disk_bytes: int) -> dict:
    staged_fd = -1
    try:
        with safe_fs.trusted_regular(source) as source_fd:
            source_bytes = media_guard.iso_size(source_fd)
            media_guard.require_headroom(
                lab_fd, source_bytes + disk_bytes, operation="ISO and disk preparation")
            staged_fd = os.open(STAGED_ISO, safe_fs.FILE_RDWR_CREATE_FLAGS,
                                0o600, dir_fd=lab_fd)
            os.fchmod(staged_fd, 0o600)
            digest, size = _copy_iso(source_fd, staged_fd)
            staged_info = os.fstat(staged_fd)
    except Exception:
        if staged_fd >= 0:
            os.close(staged_fd)
            if safe_fs.exists_at(lab_fd, STAGED_ISO):
                os.unlink(STAGED_ISO, dir_fd=lab_fd)
        raise
    else:
        os.close(staged_fd)

    report = {
        "schema": MEDIA_SCHEMA,
        "source": str(source),
        "path": str(staged_iso(root)),
        "sha256": digest,
        "bytes": size,
        "device": staged_info.st_dev,
        "inode": staged_info.st_ino,
    }
    try:
        _write_json_at(lab_fd, MEDIA_RECEIPT, report)
        os.fsync(lab_fd)
    except Exception:
        if safe_fs.exists_at(lab_fd, MEDIA_RECEIPT):
            os.unlink(MEDIA_RECEIPT, dir_fd=lab_fd)
        os.unlink(STAGED_ISO, dir_fd=lab_fd)
        raise
    return report


def _read_media_receipt(fd: int, root: Path) -> dict:
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise TestbedError("staged media receipt must be operator-owned and private")
    if info.st_size > 16 * 1024:
        raise TestbedError("staged media receipt is unexpectedly large")
    os.lseek(fd, 0, os.SEEK_SET)
    raw = b""
    while len(raw) <= 16 * 1024:
        chunk = os.read(fd, 4096)
        if not chunk:
            break
        raw += chunk
    document = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    fields = {"schema", "source", "path", "sha256", "bytes", "device", "inode"}
    if not isinstance(document, dict) or set(document) != fields:
        raise TestbedError("unsupported staged media receipt schema/fields")
    if (document["schema"] != MEDIA_SCHEMA
            or not isinstance(document["source"], str)
            or document["path"] != str(staged_iso(root))
            or not isinstance(document["sha256"], str)
            or SHA256.fullmatch(document["sha256"]) is None
            or type(document["bytes"]) is not int or document["bytes"] < 0
            or type(document["device"]) is not int
            or type(document["inode"]) is not int):
        raise TestbedError("invalid staged media receipt")
    return document


def _hash_stable_fd(fd: int, label: str,
                    max_bytes: int = media_guard.MAX_ISO_BYTES) -> tuple[str, int]:
    before = os.fstat(fd)
    if before.st_size > max_bytes:
        raise TestbedError(f"{label} exceeds the approved byte budget")
    if not stat.S_ISREG(before.st_mode):
        raise TestbedError(f"{label} is not a regular file")
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    count = 0
    while count <= max_bytes:
        chunk = os.read(fd, min(1024 * 1024, max_bytes + 1 - count))
        if not chunk:
            break
        count += len(chunk)
        if count > max_bytes:
            raise TestbedError(f"{label} exceeds the approved byte budget")
        digest.update(chunk)
    after = os.fstat(fd)
    if ((before.st_dev, before.st_ino, before.st_size,
         before.st_mtime_ns, before.st_ctime_ns)
        != (after.st_dev, after.st_ino, after.st_size,
            after.st_mtime_ns, after.st_ctime_ns) or count != after.st_size):
        raise TestbedError(f"{label} changed during hashing")
    return digest.hexdigest(), count


def verify_staged_iso(root: Path) -> dict:
    """Reopen and verify the private media object immediately before VM use."""
    with safe_fs.lab_directory(root) as lab_fd:
        receipt_fd = safe_fs.regular_at(lab_fd, MEDIA_RECEIPT)
        try:
            receipt = _read_media_receipt(receipt_fd, root)
        finally:
            os.close(receipt_fd)
        iso_fd = safe_fs.regular_at(lab_fd, STAGED_ISO)
        try:
            info = os.fstat(iso_fd)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise TestbedError("staged installer ISO must be operator-owned and private")
            if (info.st_dev, info.st_ino) != (receipt["device"], receipt["inode"]):
                raise TestbedError("staged installer ISO identity differs from receipt")
            digest, size = _hash_stable_fd(iso_fd, "staged installer ISO")
        finally:
            os.close(iso_fd)
    if digest != receipt["sha256"] or size != receipt["bytes"]:
        raise TestbedError("staged installer ISO digest or size differs from receipt")
    return receipt


def plan(cfg: dict, root: Path, iso: Path) -> dict:
    disk, definition = paths(root)
    return {
        "status": "PLANNED_NOT_EXECUTED", "connection": URI, "network": "none",
        "disk": str(disk), "definition": str(definition), "iso": str(iso),
        "staged_iso": str(staged_iso(root)),
        "size_gib": cfg["disk_gib"], "xml": render_xml(cfg, root),
    }


def prepare(cfg: dict, root: Path, iso: Path, token: str | None) -> dict:
    approve(token, PREPARE_TOKEN)
    iso = iso_file(str(iso))
    disk, definition = paths(root)
    xml = render_xml(cfg, root)
    # Keep an operator-owned, private lab FD open across all host mutations.
    # qemu-img receives an inherited FD, never a mutable ancestor pathname.
    with pinned_helper("qemu-img") as qemu_img, \
            safe_fs.lab_directory(root, create=True) as lab_fd:
        if any(safe_fs.exists_at(lab_fd, name) for name in
               ("disk.qcow2", "domain.xml", STAGED_ISO, MEDIA_RECEIPT)):
            raise TestbedError("refusing to replace existing lab state")
        disk_bytes = cfg["disk_gib"] * media_guard.GIB
        media = _stage_iso(root, lab_fd, iso, disk_bytes)
        disk_fd = os.open("disk.qcow2",
                          safe_fs.FILE_RDWR_CREATE_FLAGS,
                          0o600, dir_fd=lab_fd)
        try:
            local_command(qemu_img, ["create", "-f", "qcow2",
                          f"/proc/self/fd/{disk_fd}", f"{cfg['disk_gib']}G"],
                          timeout=120, pass_fds=(disk_fd,),
                          file_size_limit=media_guard.maximum_qcow2_file_size(disk_bytes))
            media_guard.qcow2_preflight(disk_fd, disk_bytes)
        finally:
            os.close(disk_fd)
        fd = os.open("domain.xml", safe_fs.FILE_WRITE_FLAGS, 0o600,
                     dir_fd=lab_fd)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(xml)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(lab_fd)
    return {"status": "PREPARED_NOT_DEFINED_OR_BOOTED",
            "definition": str(definition), "disk": str(disk),
            "iso": media["path"], "iso_sha256": media["sha256"],
            "manual_next": ("run scripts/testbed.py verify-media --lab-root "
                            f"{root} immediately before manual libvirt use")}


def verify_media(root: Path) -> dict:
    media = verify_staged_iso(root)
    return {"status": "STAGED_ISO_VERIFIED", "iso": media["path"],
            "iso_sha256": media["sha256"], "bytes": media["bytes"],
            "manual_next": f"/usr/bin/virsh -c {URI} define {root / 'domain.xml'}"}


def _audit_defined(cfg: dict, root: Path, virsh: PinnedHelper) -> dict:
    verify_staged_iso(root)
    # Verify stored XML AND current (possibly live/hotplugged) XML.
    for options in (["--inactive"], []):
        xml = local_command(
            virsh, ["-c", URI, "dumpxml", *options, cfg["name"]])
        audit_xml(xml, cfg, root)
    return {"status": "DOMAIN_XML_AUDITED", "domain": cfg["name"],
            "limitation": "Does not prove host egress isolation or prevent races."}


def audit_defined(cfg: dict, root: Path) -> dict:
    with pinned_helper("virsh") as virsh:
        return _audit_defined(cfg, root, virsh)


def hash_fd(fd: int, max_bytes: int) -> tuple[str, int]:
    """Hash a stable, already opened regular descriptor within its output cap."""
    return _hash_stable_fd(fd, "snapshot output", max_bytes)


def snapshot(cfg: dict, root: Path, label: str, sha: str,
             token: str | None) -> dict:
    approve(token, SNAPSHOT_TOKEN)
    if LABEL.fullmatch(label) is None or SHA.fullmatch(sha) is None:
        raise TestbedError("invalid snapshot label or exact Git commit SHA")
    with pinned_helper("qemu-img") as qemu_img, \
            pinned_helper("virsh") as virsh, \
            safe_fs.lab_directory(root) as lab_fd:
        source_fd = safe_fs.private_regular_at(lab_fd, "disk.qcow2")
        try:
            _audit_defined(cfg, root, virsh)
            state = local_command(
                virsh, ["-c", URI, "domstate", cfg["name"]])
            if state != "shut off":
                raise TestbedError(f"domain is not shut off: {state}")
            disk_bytes = cfg["disk_gib"] * media_guard.GIB
            output_cap = media_guard.maximum_qcow2_file_size(disk_bytes)
            media_guard.qcow2_preflight(source_fd, disk_bytes)
            source_path = f"/proc/self/fd/{source_fd}"
            metadata = json.loads(local_command(
                qemu_img, ["info", "--output=json", source_path],
                pass_fds=(source_fd,)))
            media_guard.validate_qemu_info(metadata, disk_bytes)
            # Another process may rewrite source metadata without changing its
            # descriptor identity; do not proceed if the header drifted.
            media_guard.qcow2_preflight(source_fd, disk_bytes)
            source_before = os.fstat(source_fd)
            with safe_fs.private_child_directory(lab_fd, "snapshots",
                                                 create=True) as snapshot_fd:
                destination = f"{label}.qcow2"
                receipt_name = f"{label}.receipt.json"
                if (safe_fs.exists_at(snapshot_fd, destination)
                        or safe_fs.exists_at(snapshot_fd, receipt_name)):
                    raise TestbedError("snapshot or receipt already exists")
                media_guard.require_headroom(
                    snapshot_fd, output_cap, operation="offline snapshot")
                temporary = f".pending-{secrets.token_hex(16)}.qcow2"
                temp_fd = os.open(temporary, safe_fs.FILE_RDWR_CREATE_FLAGS,
                                  0o600, dir_fd=snapshot_fd)
                published = False
                try:
                    local_command(qemu_img,
                                  ["convert", "-f", "qcow2", "-O", "qcow2",
                                   source_path, f"/proc/self/fd/{temp_fd}"],
                                  timeout=3600, pass_fds=(source_fd, temp_fd),
                                  file_size_limit=output_cap)
                    source_after = os.fstat(source_fd)
                    if ((source_before.st_size, source_before.st_mtime_ns, source_before.st_ctime_ns)
                         != (source_after.st_size, source_after.st_mtime_ns, source_after.st_ctime_ns)):
                        raise TestbedError("source disk changed during offline copy")
                    media_guard.qcow2_preflight(temp_fd, disk_bytes)
                    digest, size = hash_fd(temp_fd, output_cap)
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
                    os.fsync(snapshot_fd)
                except Exception:
                    if published:
                        os.unlink(destination, dir_fd=snapshot_fd)
                        os.fsync(snapshot_fd)
                    raise
                finally:
                    os.close(temp_fd)
                    os.unlink(temporary, dir_fd=snapshot_fd)
                    os.fsync(snapshot_fd)
        finally:
            os.close(source_fd)
    return {"status": "SNAPSHOT_CREATED",
            "image": str(root / "snapshots" / f"{label}.qcow2"),
            "receipt": str(root / "snapshots" / f"{label}.receipt.json"),
            "sha256": digest}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="action", required=True)
    for name in ("plan", "prepare", "verify-media", "audit-defined", "snapshot"):
        p = subs.add_parser(name)
        p.add_argument("--config", type=Path, default=REPO / "lab/testbed.json")
        p.add_argument("--lab-root", required=True)
        if name in {"plan", "prepare"}:
            p.add_argument("--iso", required=True)
        if name in {"prepare", "snapshot"}:
            p.add_argument("--approve")
        if name == "snapshot":
            p.add_argument("--label", required=True)
            p.add_argument("--source-sha", required=True)
    args = parser.parse_args(argv)
    try:
        cfg = read_config(args.config)
        root = state_dir(args.lab_root,
                         must_exist=args.action in {"verify-media", "audit-defined", "snapshot"})
        if args.action == "plan":
            iso = iso_file(args.iso)
            report = plan(cfg, root, iso)
        elif args.action == "prepare":
            iso = iso_file(args.iso)
            report = prepare(cfg, root, iso, args.approve)
        elif args.action == "verify-media":
            report = verify_media(root)
        elif args.action == "audit-defined":
            report = audit_defined(cfg, root)
        else:
            report = snapshot(cfg, root, args.label, args.source_sha, args.approve)
    except (TestbedError, safe_fs.UnsafePath, OSError, ValueError, subprocess.SubprocessError, ET.ParseError) as exc:
        # Escape untrusted control characters before writing to the terminal.
        print("FAIL: " + ascii(str(exc))[1:-1], file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
