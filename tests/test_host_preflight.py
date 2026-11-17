Failed to create stream fd: Operation not permitted
Failed to create stream fd: Operation not permitted
Failed to create stream fd: Operation not permitted
"""Safe host preflight checks: no sudo, package mutation, network, or VM."""
from __future__ import annotations

import hashlib
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
        """Create a deterministic receipt without inventorying the CI host."""
        self.out_parent.mkdir(parents=True, mode=0o700)
        self.out_parent.chmod(0o700)
        session = self.out_parent / ("a" * 24)
        session.mkdir(mode=0o700)
        record = {
            "schema": "qsol-rhel-host-preflight/v1",
            "phase": "before",
            "session_id": session.name,
            "system": {},
        }
        body = (json.dumps(record, sort_keys=True, indent=2) + "\n").encode()
        digest = hashlib.sha256(body).hexdigest()
        receipt = session / "before.json"
        receipt.write_bytes(body)
        receipt.chmod(0o600)
        checksum = session / "before.json.sha256"
        checksum.write_text(f"{digest}  before.json\n", encoding="ascii")
        checksum.chmod(0o600)
        return session

    def test_verify_prebuilt_receipt_without_collecting_host_state(self):
        session = self.before()
        self.assertEqual(session.stat().st_mode & 0o777, 0o700)
        receipt = session / "before.json"
        self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
        result = self.invoke("--phase", "verify", "--session", str(session))
        self.assertIn("after not captured", result.stdout)

    def test_wrapper_uses_isolated_python(self):
        self.assertIn("/usr/bin/python3 -I -", SCRIPT.read_text(encoding="utf-8"))

    def test_tampered_receipt_fails_closed(self):
        session = self.before()
        receipt = session / "before.json"
        receipt.write_bytes(receipt.read_bytes() + b" ")
        result = self.invoke("--phase", "verify", "--session", str(session),
                             success=False)
        self.assertIn("mismatch", result.stderr)

    def test_symlink_session_rejected(self):
        session = self.before()
        linked = self.root / ("a" * 24)
        linked.symlink_to(session, target_is_directory=True)
        result = self.invoke("--phase", "verify", "--session", str(linked),
                             success=False)
        self.assertIn("FAIL:", result.stderr)
        self.assertNotIn("invalid session ID", result.stderr)
