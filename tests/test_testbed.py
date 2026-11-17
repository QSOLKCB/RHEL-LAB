"""Safe, mocked testbed tests. No virsh, qemu-img, KVM, root or network use."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree as ET

from scripts import testbed as t
from scripts import safe_fs


class TestbedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "vm-state"
        self.iso = self.base / "rhel.iso"
        self.iso.write_bytes(b"fixture, not installation media")
        self.iso.chmod(0o600)
        self.helper_dir = self.base / "helpers"
        self.helper_dir.mkdir(mode=0o700)
        self.helper_paths = {}
        for name in ("qemu-img", "virsh"):
            helper = self.helper_dir / name
            helper.write_bytes(b"mock executable")
            helper.chmod(0o700)
            self.helper_paths[name] = helper
        self.cfg = {
            "schema": t.SCHEMA, "name": "rhel-lab-offline-01",
            "architecture": "x86_64", "network": "none",
            "vcpus": 2, "memory_mib": 4096, "disk_gib": 48,
        }
        self.config_path = self.base / "config.json"
        self.write_config()

    def write_config(self):
        self.config_path.write_text(json.dumps(self.cfg), encoding="utf-8")

    def test_valid_profile(self):
        self.assertEqual(t.read_config(self.config_path), self.cfg)

    def test_unknown_fields_fail_closed(self):
        self.cfg["external_network"] = True
        self.write_config()
        with self.assertRaises(t.TestbedError):
            t.read_config(self.config_path)

    def test_no_network_allowed(self):
        self.cfg["network"] = "nat"
        self.write_config()
        with self.assertRaises(t.TestbedError):
            t.read_config(self.config_path)

    def test_bool_not_accepted_as_integer(self):
        self.cfg["vcpus"] = True
        self.write_config()
        with self.assertRaises(t.TestbedError):
            t.read_config(self.config_path)

    def test_duplicate_json_property_rejected(self):
        self.config_path.write_text('{"name":"a","name":"b"}')
        with self.assertRaises(t.TestbedError):
            t.read_config(self.config_path)

    def test_main_escapes_terminal_controls_in_config_error(self):
        from contextlib import redirect_stderr
        from io import StringIO
        key = r"bad\u001b[2J\n\u001b]52;c;value\u0007"
        self.config_path.write_text(
            f'{{"{key}":1,"{key}":2}}', encoding="utf-8")
        errors = StringIO()
        with redirect_stderr(errors):
            status = t.main([
                "plan", "--config", str(self.config_path),
                "--lab-root", str(self.root), "--iso", str(self.iso),
            ])
        self.assertEqual(status, 1)
        self.assertEqual(
            errors.getvalue(),
            "FAIL: duplicate JSON property: "
            "bad\\x1b[2J\\n\\x1b]52;c;value\\x07\n",
        )

    def test_main_preserves_plain_failure_diagnostic(self):
        from contextlib import redirect_stderr
        from io import StringIO
        self.cfg["network"] = "nat"
        self.write_config()
        errors = StringIO()
        with redirect_stderr(errors):
            status = t.main([
                "plan", "--config", str(self.config_path),
                "--lab-root", str(self.root), "--iso", str(self.iso),
            ])
        self.assertEqual(status, 1)
        self.assertEqual(
            errors.getvalue(),
            "FAIL: only x86_64 and network=none are allowed\n",
        )

    def test_xml_is_serial_only(self):
        xml = t.render_xml(self.cfg, self.root)
        self.assertIn("rhel-lab-offline-01", xml)
        self.assertNotIn("<interface", xml)
        self.assertNotIn("<graphics", xml)
        self.assertIn(str(t.staged_iso(self.root)), xml)
        t.audit_xml(xml, self.cfg, self.root)

    def test_interface_injection_rejected(self):
        xml = t.render_xml(self.cfg, self.root)
        xml = xml.replace("</devices>", "<interface type='network' /></devices>")
        with self.assertRaises(t.TestbedError):
            t.audit_xml(xml, self.cfg, self.root)

    def test_tcp_serial_listener_rejected(self):
        xml = t.render_xml(self.cfg, self.root)
        xml = xml.replace('<serial type="pty">', '<serial type="tcp">')
        with self.assertRaises(t.TestbedError):
            t.audit_xml(xml, self.cfg, self.root)

    def test_input_passthrough_rejected(self):
        xml = t.render_xml(self.cfg, self.root)
        xml = xml.replace("</devices>", '<input type="passthrough" bus="virtio" /></devices>')
        with self.assertRaises(t.TestbedError):
            t.audit_xml(xml, self.cfg, self.root)

    def test_unapproved_emulator_rejected(self):
        xml = t.render_xml(self.cfg, self.root)
        xml = xml.replace("</devices>", "<emulator>/tmp/untrusted-qemu</emulator></devices>")
        with self.assertRaises(t.TestbedError):
            t.audit_xml(xml, self.cfg, self.root)

    def test_changed_resource_limits_rejected(self):
        xml = t.render_xml(self.cfg, self.root)
        xml = xml.replace("<vcpu>2</vcpu>", "<vcpu>32</vcpu>")
        with self.assertRaises(t.TestbedError):
            t.audit_xml(xml, self.cfg, self.root)

    def test_libvirt_kib_memory_normalization_allowed(self):
        xml = t.render_xml(self.cfg, self.root)
        xml = xml.replace('<memory unit="MiB">4096</memory>',
                          '<memory unit="KiB">4194304</memory>')
        t.audit_xml(xml, self.cfg, self.root)

    def test_reviewed_libvirt_normalization_allowed(self):
        domain = ET.fromstring(t.render_xml(self.cfg, self.root))
        domain.set("id", "7")
        ET.SubElement(domain, "uuid").text = "12345678-1234-4234-8234-123456789abc"
        ET.SubElement(domain, "currentMemory", {"unit": "KiB"}).text = "4194304"
        domain.find("vcpu").set("placement", "static")
        domain.find("os/type").set("machine", "pc-q35-rhel9.6.0")
        features = ET.SubElement(domain, "features")
        ET.SubElement(features, "acpi")
        ET.SubElement(features, "apic")
        cpu = ET.SubElement(domain, "cpu", {"mode": "custom", "match": "exact",
                                             "check": "none"})
        ET.SubElement(cpu, "model", {"fallback": "forbid"}).text = "qemu64"
        clock = ET.SubElement(domain, "clock", {"offset": "utc"})
        ET.SubElement(clock, "timer", {"name": "rtc", "tickpolicy": "catchup"})
        ET.SubElement(domain, "on_poweroff").text = "destroy"
        ET.SubElement(domain, "on_reboot").text = "restart"
        ET.SubElement(domain, "on_crash").text = "destroy"
        pm = ET.SubElement(domain, "pm")
        ET.SubElement(pm, "suspend-to-mem", {"enabled": "no"})
        ET.SubElement(pm, "suspend-to-disk", {"enabled": "no"})
        seclabel = ET.SubElement(domain, "seclabel", {
            "type": "dynamic", "model": "selinux", "relabel": "yes"})
        ET.SubElement(seclabel, "label").text = "system_u:system_r:svirt_t:s0:c1,c2"
        ET.SubElement(seclabel, "imagelabel").text = "system_u:object_r:svirt_image_t:s0:c1,c2"
        devices = domain.find("devices")
        for index, disk in enumerate(devices.findall("disk"), start=1):
            disk.find("source").set("index", str(index))
            ET.SubElement(disk, "backingStore")
            ET.SubElement(disk, "alias", {"name": f"disk{index}"})
        serial = devices.find("serial")
        ET.SubElement(serial, "source", {"path": "/dev/pts/7"})
        serial.find("target").set("type", "isa-serial")
        ET.SubElement(serial.find("target"), "model", {"name": "isa-serial"})
        console = devices.find("console")
        console.set("tty", "/dev/pts/7")
        ET.SubElement(console, "source", {"path": "/dev/pts/7"})
        controller = ET.SubElement(devices, "controller", {
            "type": "sata", "index": "0"})
        ET.SubElement(controller, "alias", {"name": "sata0"})
        input_device = ET.SubElement(devices, "input", {"type": "mouse", "bus": "ps2"})
        ET.SubElement(input_device, "alias", {"name": "input0"})
        video = ET.SubElement(devices, "video")
        ET.SubElement(video, "model", {"type": "vga", "vram": "16384", "heads": "1"})
        balloon = ET.SubElement(devices, "memballoon", {"model": "virtio"})
        ET.SubElement(balloon, "stats", {"period": "10"})
        ET.SubElement(devices, "emulator").text = "/usr/libexec/qemu-kvm"
        t.audit_xml(ET.tostring(domain, encoding="unicode"), self.cfg, self.root)

    def test_network_disk_backing_rejected(self):
        xml = t.render_xml(self.cfg, self.root)
        backing = ("<backingStore type='network'><format type='qcow2'/>"
                   "<source protocol='nbd' name='remote'><host name='example.invalid' "
                   "port='10809'/></source></backingStore>")
        xml = xml.replace("</disk>", backing + "</disk>", 1)
        with self.assertRaises(t.TestbedError):
            t.audit_xml(xml, self.cfg, self.root)

    def test_disk_security_extensions_rejected(self):
        for extension in (
            "<mirror type='network'/>",
            "<dataStore type='network'/>",
            "<auth username='attacker'/>",
            "<reservations managed='yes'/>",
            "<encryption format='luks'/>",
        ):
            with self.subTest(extension=extension):
                xml = t.render_xml(self.cfg, self.root)
                xml = xml.replace("</disk>", extension + "</disk>", 1)
                with self.assertRaises(t.TestbedError):
                    t.audit_xml(xml, self.cfg, self.root)

    def test_host_backed_boot_elements_rejected(self):
        for extension in (
            "<loader>/tmp/untrusted-firmware.fd</loader>",
            "<nvram>/tmp/untrusted-vars.fd</nvram>",
            "<kernel>/tmp/untrusted-kernel</kernel>",
            "<initrd>/tmp/untrusted-initrd</initrd>",
        ):
            with self.subTest(extension=extension):
                xml = t.render_xml(self.cfg, self.root)
                xml = xml.replace("</os>", extension + "</os>")
                with self.assertRaises(t.TestbedError):
                    t.audit_xml(xml, self.cfg, self.root)

    def test_unapproved_domain_semantics_rejected(self):
        for extension in (
            "<memoryBacking><source type='file'/></memoryBacking>",
            "<seclabel type='static' model='selinux' relabel='no'>"
            "<label>unconfined_u:unconfined_r:unconfined_t:s0</label></seclabel>",
            "<seclabel type='dynamic' model='selinux' relabel='yes'>"
            "<label>unconfined_u:unconfined_r:unconfined_t:s0</label>"
            "<imagelabel>unconfined_u:object_r:svirt_image_t:s0</imagelabel></seclabel>",
        ):
            with self.subTest(extension=extension):
                xml = t.render_xml(self.cfg, self.root)
                xml = xml.replace("</domain>", extension + "</domain>")
                with self.assertRaises(t.TestbedError):
                    t.audit_xml(xml, self.cfg, self.root)

    def test_video_render_node_rejected(self):
        xml = t.render_xml(self.cfg, self.root)
        video = ("<video><model type='virtio'><acceleration accel3d='yes' "
                 "rendernode='/dev/dri/renderD128'/></model></video>")
        xml = xml.replace("</devices>", video + "</devices>")
        with self.assertRaises(t.TestbedError):
            t.audit_xml(xml, self.cfg, self.root)

    def test_file_path_substitution_rejected(self):
        xml = t.render_xml(self.cfg, self.root)
        xml = xml.replace(str(self.root / "disk.qcow2"), "/tmp/other.qcow2")
        with self.assertRaises(t.TestbedError):
            t.audit_xml(xml, self.cfg, self.root)

    def test_iso_path_substitution_rejected(self):
        xml = t.render_xml(self.cfg, self.root)
        xml = xml.replace(str(t.staged_iso(self.root)), str(self.iso))
        with self.assertRaises(t.TestbedError):
            t.audit_xml(xml, self.cfg, self.root)

    def test_qemu_extension_rejected(self):
        xml = t.render_xml(self.cfg, self.root)
        xml = xml.replace("</domain>",
              '<commandline xmlns="http://libvirt.org/schemas/domain/qemu" /></domain>')
        with self.assertRaises(t.TestbedError):
            t.audit_xml(xml, self.cfg, self.root)

    def test_symlink_state_root_rejected(self):
        self.root.mkdir()
        alias = self.base / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(t.TestbedError):
            t.state_dir(str(alias))

    def test_state_inside_repo_rejected(self):
        with self.assertRaises(t.TestbedError):
            t.state_dir(str(t.REPO / "local"))

    def test_group_writable_iso_is_rejected(self):
        self.iso.chmod(0o660)
        with self.assertRaises(safe_fs.UnsafePath):
            t.iso_file(str(self.iso))

    def test_iso_under_writable_ancestor_is_rejected(self):
        shared = self.base / "shared-media"
        shared.mkdir(mode=0o700)
        media = shared / "rhel.iso"
        media.write_bytes(b"untrusted fixture")
        shared.chmod(0o777)
        with self.assertRaises(safe_fs.UnsafePath):
            t.iso_file(str(media))

    def test_plan_is_pure(self):
        with patch.object(t, "local_command", side_effect=AssertionError("execution forbidden")):
            result = t.plan(self.cfg, self.root, self.iso)
        self.assertEqual(result["status"], "PLANNED_NOT_EXECUTED")
        self.assertFalse(self.root.exists())

    def test_failed_subprocess_retains_stderr_and_stdout(self):
        failure = subprocess.CalledProcessError(7, ["virsh", "domstate"],
                                               output="partial output",
                                               stderr="permission denied")
        with patch.dict(t.HELPER_PATHS, self.helper_paths, clear=True), \
                t.pinned_helper("virsh") as virsh, \
                patch.object(t.subprocess, "run", side_effect=failure):
            with self.assertRaises(t.TestbedError) as caught:
                t.local_command(virsh, ["domstate"])
        self.assertIn("partial output", str(caught.exception))
        self.assertIn("permission denied", str(caught.exception))
        self.assertIn("exit status 7", str(caught.exception))

    def test_timeout_preserves_partial_diagnostics(self):
        failure = subprocess.TimeoutExpired(["qemu-img", "convert"], 3,
                                           output=b"partial\\xff",
                                           stderr=b"disk full")
        with patch.dict(t.HELPER_PATHS, self.helper_paths, clear=True), \
                t.pinned_helper("qemu-img") as qemu_img, \
                patch.object(t.subprocess, "run", side_effect=failure):
            with self.assertRaises(t.TestbedError) as caught:
                t.local_command(qemu_img, ["convert"])
        self.assertIn("timed out", str(caught.exception))
        self.assertIn("disk full", str(caught.exception))

    def test_helper_ignores_path_and_executes_pinned_descriptor(self):
        attacker = self.base / "attacker"
        attacker.mkdir(mode=0o700)
        (attacker / "virsh").write_bytes(b"attacker controlled")
        replacement = self.helper_dir / "replacement"
        result = Mock(stdout="shut off\n")
        data_fd = os.open(self.iso, os.O_RDONLY)
        try:
            with patch.dict(t.HELPER_PATHS, self.helper_paths, clear=True), \
                    patch.dict(os.environ, {"PATH": str(attacker)}), \
                    t.pinned_helper("virsh") as virsh:
                original = os.fstat(virsh.fd)
                self.helper_paths["virsh"].rename(replacement)
                self.helper_paths["virsh"].write_bytes(b"replacement executable")
                self.helper_paths["virsh"].chmod(0o700)
                with patch.object(t.subprocess, "run", return_value=result) as run:
                    output = t.local_command(
                        virsh, ["domstate"], pass_fds=(data_fd,))
                    self.assertEqual(output, "shut off")
                argv = run.call_args.args[0]
                options = run.call_args.kwargs
                self.assertEqual(
                    argv, [str(self.helper_paths["virsh"]), "domstate"])
                self.assertEqual(
                    options["executable"], f"/proc/self/fd/{virsh.fd}")
                self.assertIn(virsh.fd, options["pass_fds"])
                self.assertIn(data_fd, options["pass_fds"])
                self.assertEqual(options["env"]["PATH"], t.COMMAND_PATH)
                self.assertNotIn(str(attacker), options["env"]["PATH"])
                self.assertEqual(
                    (os.fstat(virsh.fd).st_dev, os.fstat(virsh.fd).st_ino),
                    (original.st_dev, original.st_ino))
        finally:
            os.close(data_fd)

    def test_helper_under_writable_ancestor_is_rejected(self):
        shared = self.base / "shared-helpers"
        shared.mkdir(mode=0o700)
        helper = shared / "virsh"
        helper.write_bytes(b"untrusted executable")
        helper.chmod(0o700)
        shared.chmod(0o777)
        with patch.dict(t.HELPER_PATHS, {"virsh": helper}, clear=True):
            with self.assertRaises(safe_fs.UnsafePath):
                with t.pinned_helper("virsh"):
                    self.fail("writable helper ancestor was accepted")

    def test_symlinked_helper_is_rejected(self):
        alias = self.helper_dir / "virsh-link"
        alias.symlink_to(self.helper_paths["virsh"])
        with patch.dict(t.HELPER_PATHS, {"virsh": alias}, clear=True):
            with self.assertRaises(OSError):
                with t.pinned_helper("virsh"):
                    self.fail("symlinked helper was accepted")

    def test_prepare_requires_operator_approval(self):
        with self.assertRaises(t.TestbedError):
            t.prepare(self.cfg, self.root, self.iso, None)
        self.assertFalse(self.root.exists())

    def test_prepare_never_defines_or_boots_vm(self):
        def fake_qemu(helper, args, timeout=30, pass_fds=()):
            self.assertEqual(helper.path, self.helper_paths["qemu-img"])
            self.assertEqual(args[:3], ["create", "-f", "qcow2"])
            Path(args[3]).write_bytes(b"simulated image")
            return ""
        with patch.dict(t.HELPER_PATHS, self.helper_paths, clear=True), \
                patch.object(t, "local_command", side_effect=fake_qemu):
            receipt = t.prepare(self.cfg, self.root, self.iso, t.PREPARE_TOKEN)
        self.assertEqual(receipt["status"], "PREPARED_NOT_DEFINED_OR_BOOTED")
        self.assertTrue((self.root / "domain.xml").is_file())
        self.assertEqual(os.stat(self.root).st_mode & 0o077, 0)
        staged = t.staged_iso(self.root)
        self.assertEqual(staged.read_bytes(), self.iso.read_bytes())
        self.assertEqual(os.stat(staged).st_mode & 0o777, 0o600)
        definition = (self.root / "domain.xml").read_text(encoding="utf-8")
        self.assertIn(str(staged), definition)
        self.assertNotIn(str(self.iso), definition)
        media_receipt = json.loads(
            (self.root / t.MEDIA_RECEIPT).read_text(encoding="utf-8"))
        expected_digest = hashlib.sha256(self.iso.read_bytes()).hexdigest()
        self.assertEqual(media_receipt["sha256"], expected_digest)
        self.assertEqual(t.verify_media(self.root)["iso_sha256"], expected_digest)
        self.assertIn("verify-media", receipt["manual_next"])
        with self.assertRaises(t.TestbedError):
            t.prepare(self.cfg, self.root, self.iso, t.PREPARE_TOKEN)

    def test_source_replacement_does_not_change_staged_media(self):
        original = self.iso.read_bytes()

        def fake_qemu(helper, args, timeout=30, pass_fds=()):
            self.iso.unlink()
            self.iso.write_bytes(b"replacement media")
            Path(args[3]).write_bytes(b"simulated image")
            return ""

        with patch.dict(t.HELPER_PATHS, self.helper_paths, clear=True), \
                patch.object(t, "local_command", side_effect=fake_qemu):
            t.prepare(self.cfg, self.root, self.iso, t.PREPARE_TOKEN)
        self.assertEqual(t.staged_iso(self.root).read_bytes(), original)
        definition = (self.root / "domain.xml").read_text(encoding="utf-8")
        self.assertIn(str(t.staged_iso(self.root)), definition)
        self.assertNotIn(str(self.iso), definition)

    def test_changed_staged_media_is_rejected(self):
        def fake_qemu(helper, args, timeout=30, pass_fds=()):
            Path(args[3]).write_bytes(b"simulated image")
            return ""

        with patch.dict(t.HELPER_PATHS, self.helper_paths, clear=True), \
                patch.object(t, "local_command", side_effect=fake_qemu):
            t.prepare(self.cfg, self.root, self.iso, t.PREPARE_TOKEN)
        t.staged_iso(self.root).write_bytes(b"changed")
        with self.assertRaises(t.TestbedError):
            t.verify_media(self.root)

    def test_replaced_staged_inode_is_rejected(self):
        def fake_qemu(helper, args, timeout=30, pass_fds=()):
            Path(args[3]).write_bytes(b"simulated image")
            return ""

        with patch.dict(t.HELPER_PATHS, self.helper_paths, clear=True), \
                patch.object(t, "local_command", side_effect=fake_qemu):
            t.prepare(self.cfg, self.root, self.iso, t.PREPARE_TOKEN)
        staged = t.staged_iso(self.root)
        contents = staged.read_bytes()
        staged.rename(self.root / "original-installer.iso")
        staged.write_bytes(contents)
        staged.chmod(0o600)
        with self.assertRaises(t.TestbedError):
            t.verify_media(self.root)

    def test_snapshot_requires_approval(self):
        with self.assertRaises(t.TestbedError):
            t.snapshot(self.cfg, self.root, "baseline", "a" * 40, None)

    def test_snapshot_refuses_live_vm(self):
        self.root.mkdir(mode=0o700)
        (self.root / "disk.qcow2").write_bytes(b"fixture")
        with patch.dict(t.HELPER_PATHS, self.helper_paths, clear=True), \
             patch.object(t, "_audit_defined"), \
             patch.object(t, "local_command", return_value="running"):
            with self.assertRaises(t.TestbedError):
                t.snapshot(self.cfg, self.root, "baseline", "a" * 40,
                           t.SNAPSHOT_TOKEN)
        self.assertFalse((self.root / "snapshots").exists())

    def test_snapshot_rejects_bad_sha(self):
        with self.assertRaises(t.TestbedError):
            t.snapshot(self.cfg, self.root, "baseline", "not-a-sha",
                       t.SNAPSHOT_TOKEN)

    def test_audit_checks_both_live_and_persistent(self):
        safe = t.render_xml(self.cfg, self.root)
        calls = []
        def fake_command(helper, args, timeout=30):
            self.assertEqual(helper.path, self.helper_paths["virsh"])
            calls.append(args)
            return safe
        with patch.dict(t.HELPER_PATHS, self.helper_paths, clear=True), \
             patch.object(t, "verify_staged_iso"), \
             patch.object(t, "local_command", side_effect=fake_command):
            t.audit_defined(self.cfg, self.root)
        self.assertEqual(len(calls), 2)
        self.assertIn("--inactive", calls[0])
        self.assertNotIn("--inactive", calls[1])


    def test_untrusted_parent_writable_by_other_users_is_refused(self):
        shared = self.base / "shared"
        shared.mkdir(mode=0o700)
        shared.chmod(0o777)
        with self.assertRaises(safe_fs.UnsafePath):
            t.state_dir(str(shared / "rhel-lab-attacker"), must_exist=False)

    def test_prepare_pins_created_directory_across_parent_swap(self):
        moved = self.base / "moved"
        attacker = self.base / "outside"
        attacker.mkdir(mode=0o700)

        def raced_qemu(helper, args, timeout=30, pass_fds=()):
            self.assertEqual(args[:3], ["create", "-f", "qcow2"])
            self.assertEqual(len(pass_fds), 1)
            self.root.rename(moved)
            self.root.symlink_to(attacker, target_is_directory=True)
            Path(args[3]).write_bytes(b"simulated image")
            return ""

        with patch.dict(t.HELPER_PATHS, self.helper_paths, clear=True), \
                patch.object(t, "local_command", side_effect=raced_qemu):
            t.prepare(self.cfg, self.root, self.iso, t.PREPARE_TOKEN)
        self.assertTrue((moved / "domain.xml").is_file())
        self.assertTrue((moved / "disk.qcow2").is_file())
        self.assertFalse((attacker / "domain.xml").exists())
        self.assertFalse((attacker / "disk.qcow2").exists())

    def test_snapshot_source_symlink_is_refused(self):
        self.root.mkdir(mode=0o700)
        outside = self.base / "outside.qcow2"
        outside.write_bytes(b"secret")
        (self.root / "disk.qcow2").symlink_to(outside)
        with patch.dict(t.HELPER_PATHS, self.helper_paths, clear=True):
            with self.assertRaises(OSError):
                t.snapshot(self.cfg, self.root, "baseline", "a" * 40,
                           t.SNAPSHOT_TOKEN)

    def test_offline_snapshot_receipt_is_private(self):
        self.root.mkdir(mode=0o700)
        (self.root / "disk.qcow2").write_bytes(b"fake disk")

        def fake_command(helper, args, timeout=30, pass_fds=()):
            if helper.name == "virsh" and args[:1] == ["-c"]:
                return "shut off"
            if helper.name == "qemu-img" and args[:1] == ["info"]:
                self.assertTrue(pass_fds)
                return '{"format":"qcow2"}'
            if helper.name == "qemu-img" and args[:1] == ["convert"]:
                self.assertEqual(len(pass_fds), 2)
                Path(args[-1]).write_bytes(b"converted evidence")
                return ""
            self.fail(f"unexpected command: {helper.name} {args}")

        with patch.dict(t.HELPER_PATHS, self.helper_paths, clear=True), \
             patch.object(t, "_audit_defined"), \
             patch.object(t, "local_command", side_effect=fake_command):
            result = t.snapshot(self.cfg, self.root, "baseline",
                                "a" * 40, t.SNAPSHOT_TOKEN)
        receipt = Path(result["receipt"])
        image = Path(result["image"])
        self.assertTrue(image.is_file())
        self.assertEqual(image.read_bytes(), b"converted evidence")
        self.assertEqual(os.stat(receipt).st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(receipt.read_text())["sha256"], result["sha256"])
        self.assertEqual(json.loads(receipt.read_text())["claim"], "OFFLINE_DISK_COPY_ONLY")



if __name__ == "__main__":
    unittest.main()
