"""Safe host preflight checks: no sudo, package mutation, network, or VM."""
from __future__ import annotations

import ast
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "host_preflight.sh"



def isolated_repo_identity_functions():
    """Load only the inert metadata parser; never invoke host collection."""
    source = SCRIPT.read_text(encoding="utf-8")
    embedded = source.split("<<'PYTHON'\n", 1)[1].rsplit("\nPYTHON\n", 1)[0]
    parsed = ast.parse(embedded)
    names = {
        "Refusal", "canonical", "check_dir", "directory",
        "_git_text_at", "_git_loose_ref", "_git_packed_ref",
        "_git_head_sha", "repo_state",
    }
    selected = [node for node in parsed.body
                if isinstance(node, (ast.FunctionDef, ast.ClassDef))
                and node.name in names]
    globals_ = {
        "os": os, "stat": stat, "pathlib": pathlib, "re": re,
        "DIR_FLAGS": os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        "READ_FLAGS": os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
    }
    exec(compile(ast.Module(body=selected, type_ignores=[]),
                 "isolated-preflight-identity", "exec"), globals_)
    return globals_


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


    def fake_checkout(self):
        checkout = self.root / "checkout"
        checkout.mkdir(mode=0o700)
        metadata = checkout / ".git"
        metadata.mkdir(mode=0o700)
        ref = metadata / "refs" / "heads"
        ref.mkdir(parents=True, mode=0o700)
        sha = "3" * 40
        (metadata / "HEAD").write_text("ref: refs/heads/main\n")
        (ref / "main").write_text(sha + "\n")
        return checkout, metadata, sha

    def test_git_identity_is_read_without_running_checkout_filters(self):
        api = isolated_repo_identity_functions()
        checkout, metadata, sha = self.fake_checkout()
        marker = self.root / "UNEXPECTED_EXECUTION"
        (metadata / "config").write_text(
            '[filter "attack"]\n'
            f'    clean = /bin/sh -c "touch {marker}"\n'
            '    required = true\n')
        (checkout / ".gitattributes").write_text(
            "* filter=attack\n", encoding="utf-8")
        result = api["repo_state"](checkout)
        self.assertEqual(result["head_sha"], sha)
        self.assertIsNone(result["tracked_changes"])
        self.assertEqual(result["tracked_changes_status"],
                         "not_checked_to_avoid_git_execution")
        self.assertFalse(marker.exists())

    def test_git_identity_ignores_symlinked_metadata(self):
        api = isolated_repo_identity_functions()
        checkout, metadata, _ = self.fake_checkout()
        metadata.rename(self.root / "other-git")
        metadata.symlink_to(self.root / "other-git", target_is_directory=True)
        result = api["repo_state"](checkout)
        self.assertEqual(result["status"], "no_trusted_git_metadata")

    def test_git_metadata_rebind_is_detected(self):
        api = isolated_repo_identity_functions()
        checkout, metadata, _ = self.fake_checkout()
        original = api["_git_head_sha"]
        moved = self.root / "moved-metadata"

        def replace_after_pinned_read(git_fd):
            sha = original(git_fd)
            metadata.rename(moved)
            metadata.mkdir(mode=0o700)
            (metadata / "HEAD").write_text("4" * 40 + "\n")
            return sha

        api["_git_head_sha"] = replace_after_pinned_read
        result = api["repo_state"](checkout)
        self.assertEqual(result["status"], "untrusted_or_unstable_git_metadata")

    def test_packed_git_ref_without_git_execution(self):
        api = isolated_repo_identity_functions()
        checkout, metadata, sha = self.fake_checkout()
        (metadata / "refs" / "heads" / "main").unlink()
        (metadata / "packed-refs").write_text(
            "# pack-refs with: peeled fully-peeled\n"
            + sha + " refs/heads/main\n")
        self.assertEqual(api["repo_state"](checkout)["head_sha"], sha)

    def test_unsafe_git_ref_path_is_refused(self):
        api = isolated_repo_identity_functions()
        checkout, metadata, _ = self.fake_checkout()
        (metadata / "HEAD").write_text("ref: refs/heads/../../tmp\n")
        result = api["repo_state"](checkout)
        self.assertEqual(result["status"], "untrusted_or_unstable_git_metadata")

    def test_symlink_session_rejected(self):
        session = self.before()
        linked = self.root / ("a" * 24)
        linked.symlink_to(session, target_is_directory=True)
        result = self.invoke("--phase", "verify", "--session", str(linked),
                             success=False)
        self.assertIn("FAIL:", result.stderr)
        self.assertNotIn("invalid session ID", result.stderr)
