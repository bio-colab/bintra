# -*- coding: utf-8 -*-
"""
Tests for BinarySlackInspector, PE Overlays, and Document EOF Padding.
"""

import os
import tempfile
import unittest
from windows_intelligence.evidence_engine.binary_slack_inspector import BinarySlackInspector


class TestBinarySlackInspector(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_entropy_calculation(self):
        """Zero bytes should have 0.0 entropy; random/varied bytes should have high entropy."""
        self.assertEqual(BinarySlackInspector.calculate_entropy(b""), 0.0)
        self.assertEqual(BinarySlackInspector.calculate_entropy(b"\x00" * 100), 0.0)
        # All 256 bytes once has maximal entropy ~ 8.0
        all_bytes = bytes(range(256))
        entropy = BinarySlackInspector.calculate_entropy(all_bytes)
        self.assertAlmostEqual(entropy, 8.0, places=2)

    def test_clean_rtf_document(self):
        """A valid RTF ending strictly at '}' should have no slack."""
        p = os.path.join(self.temp_dir.name, "clean.rtf")
        with open(p, "wb") as f:
            f.write(b"{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Arial;}}\\f0 Clean Document Content.}")

        res = BinarySlackInspector.inspect_file(p)
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["format"], "RTF")
        self.assertFalse(res["has_trailing_slack"])
        self.assertEqual(res["slack_bytes_count"], 0)
        self.assertEqual(res["slack_type"], "CLEAN_EXACT_EOF")

    def test_mfc_trailing_nul_rtf(self):
        """An RTF terminating with \\r\\n}\\r\\n\\x00 (WordPad/MFC) must be classified as MFC_STREAM_NULL_TERMINATOR."""
        p = os.path.join(self.temp_dir.name, "mfc_saved.rtf")
        with open(p, "wb") as f:
            f.write(b"{\\rtf1\\ansi\\deff0\\f0 Content\\par\r\n}\r\n\x00")

        res = BinarySlackInspector.inspect_file(p)
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["format"], "RTF")
        self.assertTrue(res["has_trailing_slack"])
        self.assertEqual(res["slack_type"], "MFC_STREAM_NULL_TERMINATOR")
        self.assertIn("WordPad/MFC", res["diagnostic_note"])

    def test_suspicious_payload_after_rtf_eof(self):
        """An RTF file with suspicious hidden bytes after '}' must be detected as suspicious slack."""
        p = os.path.join(self.temp_dir.name, "suspicious.rtf")
        payload = b"\xde\xad\xbe\xef" * 64
        with open(p, "wb") as f:
            f.write(b"{\\rtf1\\ansi\\deff0\\f0 Normal text.}" + payload)

        res = BinarySlackInspector.inspect_file(p)
        self.assertEqual(res["status"], "ok")
        self.assertTrue(res["has_trailing_slack"])
        self.assertEqual(res["slack_bytes_count"], len(payload))
        self.assertEqual(res["slack_type"], "SUSPICIOUS_UNMAPPED_DOCUMENT_SLACK")

    def test_live_wordpad_exe_inspection(self):
        """Inspect the installed wordpad.exe on Windows for section boundary alignment."""
        target = r"C:\Program Files\Windows NT\Accessories\wordpad.exe"
        if os.path.exists(target):
            res = BinarySlackInspector.inspect_file(target)
            self.assertEqual(res["status"], "ok")
            self.assertIn("PE", res["format"])
            self.assertIn("sections_count", res)
            self.assertGreater(res["file_size"], 0)


if __name__ == "__main__":
    unittest.main()
