"""No network, privileges, RHEL VM, or third-party test dependencies."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.evidence import EvidenceError, inventory, seal, verify


class EvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.data = self.base / "data"
        self.data.mkdir()
        (self.data / "z.log").write_bytes(b"last\n")
        (self.data / "a.log").write_bytes(b"first\n")
        self.manifest = self.base / "manifest.json"

    def test_deterministic_order(self) -> None:
        first = inventory(self.data)
        self.assertEqual(first, inventory(self.data))
        self.assertEqual([f["path"] for f in first["files"]], ["a.log", "z.log"])
        self.assertEqual(first["files"][0]["bytes"], 6)
        self.assertEqual(len(first["files"][0]["sha256"]), 64)

    def test_roundtrip(self) -> None:
        expected = seal(self.data, self.manifest)
        self.assertEqual(verify(self.data, self.manifest), expected)
        self.assertEqual(json.loads(self.manifest.read_text()), expected)

    def test_mutation_fails(self) -> None:
        seal(self.data, self.manifest)
        (self.data / "a.log").write_bytes(b"other\n")
        with self.assertRaises(EvidenceError):
            verify(self.data, self.manifest)

    def test_added_file_fails(self) -> None:
        seal(self.data, self.manifest)
        (self.data / "extra.log").write_bytes(b"added")
        with self.assertRaises(EvidenceError):
            verify(self.data, self.manifest)

    def test_output_inside_input_fails(self) -> None:
        with self.assertRaises(EvidenceError):
            seal(self.data, self.data / "manifest.json")

    def test_existing_manifest_is_not_overwritten(self) -> None:
        self.manifest.write_text("original")
        with self.assertRaises(FileExistsError):
            seal(self.data, self.manifest)
        self.assertEqual(self.manifest.read_text(), "original")

    def test_symlinked_evidence_is_rejected(self) -> None:
        (self.data / "link.log").symlink_to(self.data / "a.log")
        with self.assertRaises(EvidenceError):
            inventory(self.data)

    def test_symlinked_root_is_rejected(self) -> None:
        alias = self.base / "alias"
        alias.symlink_to(self.data, target_is_directory=True)
        with self.assertRaises(EvidenceError):
            inventory(alias)

    def test_modified_manifest_fails(self) -> None:
        seal(self.data, self.manifest)
        document = json.loads(self.manifest.read_text())
        document["files"][0]["sha256"] = "0" * 64
        self.manifest.write_text(json.dumps(document))
        with self.assertRaises(EvidenceError):
            verify(self.data, self.manifest)

    def test_nested_paths(self) -> None:
        nested = self.data / "sub"
        nested.mkdir()
        (nested / "proof.bin").write_bytes(b"\x00\x01")
        self.assertEqual(inventory(self.data)["files"][-1]["path"], "z.log")
        self.assertIn("sub/proof.bin", [f["path"] for f in inventory(self.data)["files"]])


    def test_unreadable_subdirectory_blocks_seal(self) -> None:
        blocked = self.data / "blocked"
        blocked.mkdir()
        (blocked / "evidence.log").write_bytes(b"secret\\n")
        real_scandir = os.scandir

        def deny(path):
            if Path(path) == blocked:
                raise PermissionError(f"cannot enumerate {path}")
            return real_scandir(path)

        with patch("scripts.evidence.os.scandir", side_effect=deny):
            with self.assertRaises(PermissionError):
                seal(self.data, self.manifest)
        self.assertFalse(self.manifest.exists())

    def test_unreadable_subdirectory_blocks_verify(self) -> None:
        blocked = self.data / "blocked"
        blocked.mkdir()
        evidence = blocked / "evidence.log"
        evidence.write_bytes(b"original\\n")
        seal(self.data, self.manifest)
        evidence.write_bytes(b"modified\\n")
        real_scandir = os.scandir

        def deny(path):
            if Path(path) == blocked:
                raise PermissionError(f"cannot enumerate {path}")
            return real_scandir(path)

        with patch("scripts.evidence.os.scandir", side_effect=deny):
            with self.assertRaises(PermissionError):
                verify(self.data, self.manifest)

    def test_root_enumeration_error_is_not_suppressed(self) -> None:
        with patch("scripts.evidence.os.scandir", side_effect=PermissionError("root blocked")):
            with self.assertRaises(PermissionError):
                inventory(self.data)

    def test_symlinked_directory_is_rejected(self) -> None:
        nested = self.data / "nested"
        nested.mkdir()
        (nested / "proof.bin").write_bytes(b"proof")
        (self.data / "alias").symlink_to(nested, target_is_directory=True)
        with self.assertRaises(EvidenceError):
            inventory(self.data)



if __name__ == "__main__":
    unittest.main()
