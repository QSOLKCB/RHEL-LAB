"""Safe, mocked testbed tests. No virsh, qemu-img, KVM, root or network use."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import testbed as t


class TestbedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "vm-state"
        self.iso = self.base / "rhel.iso"
        self.iso.write_bytes(b"fixture, not installation media")
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

    def test_xml_is_serial_only(self):
        xml = t.render_xml(self.cfg, self.root, self.iso)
        self.assertIn("rhel-lab-offline-01", xml)
        self.assertNotIn("<interface", xml)
        self.assertNotIn("<graphics", xml)
        t.audit_xml(xml, self.cfg, self.root, self.iso)

    def test_interface_injection_rejected(self):
        xml = t.render_xml(self.cfg, self.root, self.iso)
        xml = xml.replace("</devices>", "<interface type='network' /></devices>")
        with self.assertRaises(t.TestbedError):
            t.audit_xml(xml, self.cfg, self.root, self.iso)

    def test_tcp_serial_listener_rejected(self):
        xml = t.render_xml(self.cfg, self.root, self.iso)
        xml = xml.replace('<serial type="pty">', '<serial type="tcp">')
        with self.assertRaises(t.TestbedError):
            t.audit_xml(xml, self.cfg, self.root, self.iso)

    def test_input_passthrough_rejected(self):
        xml = t.render_xml(self.cfg, self.root, self.iso)
        xml = xml.replace("</devices>", '<input type="passthrough" bus="virtio" /></devices>')
        with self.assertRaises(t.TestbedError):
            t.audit_xml(xml, self.cfg, self.root, self.iso)

    def test_unapproved_emulator_rejected(self):
        xml = t.render_xml(self.cfg, self.root, self.iso)
        xml = xml.replace("</devices>", "<emulator>/tmp/untrusted-qemu</emulator></devices>")
        with self.assertRaises(t.TestbedError):
            t.audit_xml(xml, self.cfg, self.root, self.iso)

    def test_changed_resource_limits_rejected(self):
        xml = t.render_xml(self.cfg, self.root, self.iso)
        xml = xml.replace("<vcpu>2</vcpu>", "<vcpu>32</vcpu>")
        with self.assertRaises(t.TestbedError):
            t.audit_xml(xml, self.cfg, self.root, self.iso)

    def test_libvirt_kib_memory_normalization_allowed(self):
        xml = t.render_xml(self.cfg, self.root, self.iso)
        xml = xml.replace('<memory unit="MiB">4096</memory>',
                          '<memory unit="KiB">4194304</memory>')
        t.audit_xml(xml, self.cfg, self.root, self.iso)

    def test_file_path_substitution_rejected(self):
        xml = t.render_xml(self.cfg, self.root, self.iso)
        xml = xml.replace(str(self.root / "disk.qcow2"), "/tmp/other.qcow2")
        with self.assertRaises(t.TestbedError):
            t.audit_xml(xml, self.cfg, self.root, self.iso)

    def test_qemu_extension_rejected(self):
        xml = t.render_xml(self.cfg, self.root, self.iso)
        xml = xml.replace("</domain>",
              '<commandline xmlns="http://libvirt.org/schemas/domain/qemu" /></domain>')
        with self.assertRaises(t.TestbedError):
            t.audit_xml(xml, self.cfg, self.root, self.iso)

    def test_symlink_state_root_rejected(self):
        self.root.mkdir()
        alias = self.base / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(t.TestbedError):
            t.state_dir(str(alias))

    def test_state_inside_repo_rejected(self):
        with self.assertRaises(t.TestbedError):
            t.state_dir(str(t.REPO / "local"))

    def test_plan_is_pure(self):
        with patch.object(t, "local_command", side_effect=AssertionError("execution forbidden")):
            result = t.plan(self.cfg, self.root, self.iso)
        self.assertEqual(result["status"], "PLANNED_NOT_EXECUTED")
        self.assertFalse(self.root.exists())

    def test_failed_subprocess_retains_stderr_and_stdout(self):
        failure = subprocess.CalledProcessError(7, ["virsh", "domstate"],
                                               output="partial output",
                                               stderr="permission denied")
        with patch.object(t.subprocess, "run", side_effect=failure):
            with self.assertRaises(t.TestbedError) as caught:
                t.local_command(["virsh", "domstate"])
        self.assertIn("partial output", str(caught.exception))
        self.assertIn("permission denied", str(caught.exception))
        self.assertIn("exit status 7", str(caught.exception))

    def test_timeout_preserves_partial_diagnostics(self):
        failure = subprocess.TimeoutExpired(["qemu-img", "convert"], 3,
                                           output=b"partial\\xff",
                                           stderr=b"disk full")
        with patch.object(t.subprocess, "run", side_effect=failure):
            with self.assertRaises(t.TestbedError) as caught:
                t.local_command(["qemu-img", "convert"])
        self.assertIn("timed out", str(caught.exception))
        self.assertIn("disk full", str(caught.exception))

    def test_prepare_requires_operator_approval(self):
        with self.assertRaises(t.TestbedError):
            t.prepare(self.cfg, self.root, self.iso, None)
        self.assertFalse(self.root.exists())

    def test_prepare_never_defines_or_boots_vm(self):
        def fake_qemu(args, timeout=30):
            self.assertEqual(args[:4], ["qemu-img", "create", "-f", "qcow2"])
            Path(args[4]).write_bytes(b"simulated image")
            return ""
        with patch.object(t, "need"), patch.object(t, "local_command", side_effect=fake_qemu):
            receipt = t.prepare(self.cfg, self.root, self.iso, t.PREPARE_TOKEN)
        self.assertEqual(receipt["status"], "PREPARED_NOT_DEFINED_OR_BOOTED")
        self.assertTrue((self.root / "domain.xml").is_file())
        self.assertEqual(os.stat(self.root).st_mode & 0o077, 0)
        with self.assertRaises(t.TestbedError):
            t.prepare(self.cfg, self.root, self.iso, t.PREPARE_TOKEN)

    def test_snapshot_requires_approval(self):
        with self.assertRaises(t.TestbedError):
            t.snapshot(self.cfg, self.root, self.iso, "baseline", "a" * 40, None)

    def test_snapshot_refuses_live_vm(self):
        self.root.mkdir(mode=0o700)
        (self.root / "disk.qcow2").write_bytes(b"fixture")
        with patch.object(t, "need"), patch.object(t, "audit_defined"), \
             patch.object(t, "local_command", return_value="running"):
            with self.assertRaises(t.TestbedError):
                t.snapshot(self.cfg, self.root, self.iso, "baseline", "a" * 40,
                           t.SNAPSHOT_TOKEN)
        self.assertFalse((self.root / "snapshots").exists())

    def test_snapshot_rejects_bad_sha(self):
        with self.assertRaises(t.TestbedError):
            t.snapshot(self.cfg, self.root, self.iso, "baseline", "not-a-sha",
                       t.SNAPSHOT_TOKEN)

    def test_audit_checks_both_live_and_persistent(self):
        safe = t.render_xml(self.cfg, self.root, self.iso)
        calls = []
        def fake_command(args, timeout=30):
            calls.append(args)
            return safe
        with patch.object(t, "need"), patch.object(t, "local_command",
                                                side_effect=fake_command):
            t.audit_defined(self.cfg, self.root, self.iso)
        self.assertEqual(len(calls), 2)
        self.assertIn("--inactive", calls[0])
        self.assertNotIn("--inactive", calls[1])


if __name__ == "__main__":
    unittest.main()
