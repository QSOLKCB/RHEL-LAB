"""Pure, bounded QCOW2 and media-budget regression tests; no VM execution."""
from __future__ import annotations

import os
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import media_guard as m


class MediaGuardTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.image = self.root / "fixture.qcow2"
        self.expected = 48 * m.GIB
        data = bytearray(512)
        data[0:4] = b"QFI\xfb"
        struct.pack_into(">I", data, 4, 3)
        struct.pack_into(">I", data, 20, 9)
        struct.pack_into(">Q", data, 24, self.expected)
        struct.pack_into(">I", data, 100, 104)
        self.image.write_bytes(data)

    def inspect(self):
        fd = os.open(self.image, os.O_RDONLY)
        try:
            return m.qcow2_preflight(fd, self.expected)
        finally:
            os.close(fd)

    def mutate(self, fmt, offset, number):
        with self.image.open("r+b") as stream:
            stream.seek(offset)
            stream.write(struct.pack(fmt, number))

    def test_clean_standalone_header_passes(self):
        self.assertEqual(self.inspect()["virtual_size"], self.expected)

    def test_external_data_file_bit_fails_before_qemu_info(self):
        self.mutate(">Q", 72, 1 << 2)
        with self.assertRaisesRegex(m.MediaError, "external-data"):
            self.inspect()

    def test_backing_file_offset_is_rejected(self):
        self.mutate(">Q", 8, 4096)
        with self.assertRaisesRegex(m.MediaError, "backing"):
            self.inspect()

    def test_encrypted_qcow2_rejected(self):
        self.mutate(">I", 32, 2)
        with self.assertRaisesRegex(m.MediaError, "encrypted"):
            self.inspect()

    def test_internal_snapshots_rejected(self):
        self.mutate(">I", 60, 1)
        with self.assertRaisesRegex(m.MediaError, "snapshots"):
            self.inspect()

    def test_virtual_size_mismatch_rejected(self):
        self.mutate(">Q", 24, self.expected + m.GIB)
        with self.assertRaisesRegex(m.MediaError, "virtual size"):
            self.inspect()

    def test_path_bearing_extension_rejected_even_if_flag_cleared(self):
        self.mutate(">I", 104, 0x44415441)
        self.mutate(">I", 108, 3)
        with self.assertRaisesRegex(m.MediaError, "path-bearing"):
            self.inspect()

    def test_bad_header_version_rejected(self):
        self.mutate(">I", 4, 99)
        with self.assertRaisesRegex(m.MediaError, "version"):
            self.inspect()

    def test_bad_cluster_size_rejected(self):
        self.mutate(">I", 20, 31)
        with self.assertRaisesRegex(m.MediaError, "cluster"):
            self.inspect()

    def test_invalid_qcow2_info_rejected(self):
        valid = {"format": "qcow2", "virtual-size": self.expected}
        m.validate_qemu_info(valid, self.expected)
        cases = (
            {"format": "qcow2", "virtual-size": self.expected,
             "full-backing-filename": "/tmp/external"},
            {"format": "qcow2", "virtual-size": self.expected,
             "format-specific": {"type": "qcow2", "data": {"data-file": "/tmp/data"}}},
            {"format": "qcow2", "virtual-size": self.expected,
             "snapshots": [{"id": "1"}]},
            {"format": "qcow2", "virtual-size": self.expected + 1},
            {"format": "raw", "virtual-size": self.expected},
        )
        for info in cases:
            with self.subTest(info=info), self.assertRaises(m.MediaError):
                m.validate_qemu_info(info, self.expected)

    def test_iso_zero_and_sparse_oversize_fail_without_copy(self):
        path = self.root / "source.iso"
        path.touch()
        fd = os.open(path, os.O_RDONLY)
        try:
            with self.assertRaisesRegex(m.MediaError, "nonempty"):
                m.iso_size(fd)
        finally:
            os.close(fd)
        with path.open("r+b") as stream:
            stream.truncate(m.MAX_ISO_BYTES + 1)
        fd = os.open(path, os.O_RDONLY)
        try:
            with self.assertRaisesRegex(m.MediaError, "16 GiB"):
                m.iso_size(fd)
        finally:
            os.close(fd)

    def test_headroom_refuses_insufficient_space(self):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            insufficient = SimpleNamespace(f_frsize=4096, f_bavail=1)
            with patch.object(m.os, "fstatvfs", return_value=insufficient):
                with self.assertRaisesRegex(m.MediaError, "insufficient"):
                    m.require_headroom(fd, m.GIB, operation="test")
            enough = SimpleNamespace(f_frsize=4096, f_bavail=10 * m.GIB // 4096)
            with patch.object(m.os, "fstatvfs", return_value=enough):
                m.require_headroom(fd, m.GIB, operation="test")
        finally:
            os.close(fd)

    def test_virtual_disk_upper_bound(self):
        self.assertEqual(m.maximum_qcow2_file_size(64 * m.GIB),
                         68 * m.GIB)
        with self.assertRaises(m.MediaError):
            m.maximum_qcow2_file_size(65 * m.GIB)


if __name__ == "__main__":
    unittest.main()
