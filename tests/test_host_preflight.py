"""Safe host preflight checks: no sudo, package mutation, network, or VM."""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "host_preflight.sh"


@unittest.skipIf(os.geteuid() == 0, "preflight deliberately refuses root")
class HostPreflightTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = pathlib.Path(temp.name)
        self.out_parent = self.root / "receipts"

    def invoke(self, *args, success=True):
        run = subprocess.run(["/bin/bash", str(SCRIPT), *args],
                             text=True, capture_output=True, timeout=90,
                             cwd=str(REPO), check=False)
        if success:
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
        else:
            self.assertNotEqual(run.returncode, 0, run.stdout)
        return run

    def before(self):
        result = self.invoke("--phase", "before", "--out-parent", str(self.out_parent),
                             "--repo", str(REPO))
        session_lines = [line.partition(": ")[2] for line in result.stdout.splitlines()
                         if line.startswith("SESSION: ")]
        self.assertEqual(len(session_lines), 1)
        return pathlib.Path(session_lines[0])

    def test_before_after_verify_and_no_clobber(self):
        session = self.before()
        self.assertEqual(session.stat().st_mode & 0o777, 0o700)
        receipt = session / "before.json"
        self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
        before = json.loads(receipt.read_text())
        self.assertEqual(before["phase"], "before")
        self.assertEqual(before["schema"], "qsol-rhel-host-preflight/v1")
        self.assertFalse(before["network_operations"])
        self.assertFalse(before["vm_operations"])
        self.assertIn("kernel", before["system"])
        self.invoke("--phase", "verify", "--session", str(session))
        self.invoke("--phase", "after", "--session", str(session))
        self.invoke("--phase", "verify", "--session", str(session))
        comparison = json.loads((session / "comparison.json").read_text())
        self.assertEqual(comparison["before_sha256"],
                         (session / "before.json.sha256").read_text().split()[0])
        self.assertEqual(comparison["after_sha256"],
                         (session / "after.json.sha256").read_text().split()[0])
        self.invoke("--phase", "after", "--session", str(session), success=False)

    def test_tampered_receipt_fails_closed(self):
        session = self.before()
        receipt = session / "before.json"
        receipt.write_bytes(receipt.read_bytes() + b" ")
        result = self.invoke("--phase", "verify", "--session", str(session),
                             success=False)
        self.assertIn("mismatch", result.stderr)

    def test_symlink_session_rejected(self):
        session = self.before()
        linked = self.root / "linked"
        linked.symlink_to(session, target_is_directory=True)
        result = self.invoke("--phase", "verify", "--session", str(linked),
                             success=False)
        self.assertIn("FAIL:", result.stderr)
