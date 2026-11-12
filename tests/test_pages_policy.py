"""Pure, offline regression checks for the no-Pages repository policy."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts import pages_policy as policy


class PagesPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.workflows = self.root / "workflows"
        self.workflows.mkdir()
        (self.workflows / "ci.yml").write_text(
            "name: Source checks\npermissions:\n  contents: read\n",
            encoding="utf-8")
        self.event = {"repository": {
            "full_name": "QSOLKCB/RHEL-LAB", "has_pages": False
        }}

    def test_disabled_and_no_publish_workflow(self):
        policy.check(self.event, "QSOLKCB/RHEL-LAB", self.workflows)

    def test_enabled_pages_fails(self):
        self.event["repository"]["has_pages"] = True
        with self.assertRaises(policy.PolicyError):
            policy.check(self.event, "QSOLKCB/RHEL-LAB", self.workflows)

    def test_missing_pages_state_fails_closed(self):
        del self.event["repository"]["has_pages"]
        with self.assertRaises(policy.PolicyError):
            policy.check(self.event, "QSOLKCB/RHEL-LAB", self.workflows)

    def test_string_false_is_not_valid(self):
        self.event["repository"]["has_pages"] = "false"
        with self.assertRaises(policy.PolicyError):
            policy.check(self.event, "QSOLKCB/RHEL-LAB", self.workflows)

    def test_wrong_repository_rejected(self):
        self.event["repository"]["full_name"] = "wrong/repo"
        with self.assertRaises(policy.PolicyError):
            policy.check(self.event, "QSOLKCB/RHEL-LAB", self.workflows)

    def test_pages_write_permission_rejected(self):
        (self.workflows / "bad.yml").write_text(
            "permissions:\n  pages: write\n", encoding="utf-8")
        with self.assertRaises(policy.PolicyError):
            policy.check(self.event, "QSOLKCB/RHEL-LAB", self.workflows)

    def test_deployment_action_rejected(self):
        (self.workflows / "bad.yaml").write_text(
            "steps:\n  - uses: actions/deploy-pages@v4\n", encoding="utf-8")
        with self.assertRaises(policy.PolicyError):
            policy.check(self.event, "QSOLKCB/RHEL-LAB", self.workflows)

    def test_gh_pages_branch_rejected(self):
        (self.workflows / "bad.yml").write_text(
            "run: git push origin HEAD:gh-pages\n", encoding="utf-8")
        with self.assertRaises(policy.PolicyError):
            policy.check(self.event, "QSOLKCB/RHEL-LAB", self.workflows)

    def test_comment_alone_not_a_publishing_workflow(self):
        (self.workflows / "safe.yaml").write_text(
            "# This workflow never calls actions/deploy-pages@v4\nname: Safe\n",
            encoding="utf-8")
        policy.check(self.event, "QSOLKCB/RHEL-LAB", self.workflows)

    def test_cli_fail_closed(self):
        self.event["repository"]["has_pages"] = True
        file = self.root / "event.json"
        file.write_text(json.dumps(self.event), encoding="utf-8")
        self.assertEqual(policy.main([
            "--event", str(file), "--repository", "QSOLKCB/RHEL-LAB",
            "--workflows", str(self.workflows)
        ]), 1)

    def test_missing_workflow_directory_fails(self):
        with self.assertRaises(policy.PolicyError):
            policy.check(self.event, "QSOLKCB/RHEL-LAB",
                         self.root / "missing")


if __name__ == "__main__":
    unittest.main()
