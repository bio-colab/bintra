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


    def test_truncated_pe_file_detection(self):
        """A PE file where section headers declare data beyond actual file size must be flagged TRUNCATED."""
        import struct
        pe = bytearray(512)
        pe[0:2] = b"MZ"
        struct.pack_into("<I", pe, 0x3C, 0x80)
        pe[0x80:0x84] = b"PE\x00\x00"
        # 1 section, optional header size 0xF0
        struct.pack_into("<HHIIIHH", pe, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
        struct.pack_into("<H", pe, 0x84 + 20, 0x20B)  # PE32+
        # Section header at offset 0x84 + 24 + 0xF0 = 0x188
        sec_off = 0x84 + 24 + 0xF0
        if sec_off + 40 > len(pe):
            pe.extend(bytearray(sec_off + 40 - len(pe)))
        # raw_size = 0x1000 (4096), raw_ptr = 0x200 (512) -> raw_end = 0x1200 (4608)
        # But physical file will only be 512 bytes!
        struct.pack_into("<IIII", pe, sec_off + 8, 0x1000, 0x1000, 0x1000, 0x200)

        p = os.path.join(self.temp_dir.name, "truncated.exe")
        with open(p, "wb") as f:
            f.write(pe)

        res = BinarySlackInspector.inspect_file(p)
        self.assertEqual(res["status"], "anomaly")
        self.assertTrue(res["is_truncated"])
        self.assertEqual(res["slack_type"], "TRUNCATED_PE_SECTION_OUT_OF_BOUNDS")
        self.assertGreater(res["missing_bytes_count"], 0)

    def test_complex_rtf_with_escaped_braces_and_bin_block(self):
        r"""RTF lexer must not be fooled by \{ or \} or binary \bin blocks containing '}'."""
        rtf_content = (
            b"{\\rtf1\\ansi\\deff0"
            b"{\\fonttbl{\\f0 Courier;}}"
            b"\\f0 Text with literal \\{escaped braces\\} and "
            b"\\bin5 ABC}D"  # 5 raw bytes containing '}' inside binary payload
            b" More normal text.}"
            b"\r\n\x00"  # MFC trailing NUL
        )
        p = os.path.join(self.temp_dir.name, "complex.rtf")
        with open(p, "wb") as f:
            f.write(rtf_content)

        res = BinarySlackInspector.inspect_file(p)
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["format"], "RTF")
        self.assertTrue(res["has_trailing_slack"])
        self.assertEqual(res["slack_type"], "MFC_STREAM_NULL_TERMINATOR")

    def test_json_slack_inspection(self):
        """Verify dedicated JSON document slack inspector for clean EOF, whitespace, and suspicious slack."""
        # 1. Clean JSON
        p_clean = os.path.join(self.temp_dir.name, "clean.json")
        with open(p_clean, "w", encoding="utf-8") as f:
            f.write('{"name": "bintra", "version": "1.1.0", "tools": [1, 2, 3]}')
        res1 = BinarySlackInspector.inspect_file(p_clean)
        self.assertEqual(res1["format"], "JSON")
        self.assertFalse(res1["has_trailing_slack"])
        self.assertEqual(res1["slack_type"], "CLEAN_EXACT_EOF")

        # 2. JSON with trailing whitespace
        p_ws = os.path.join(self.temp_dir.name, "ws.json")
        with open(p_ws, "w", encoding="utf-8") as f:
            f.write('{"status": "ok"}\n\n  \t\n')
        res2 = BinarySlackInspector.inspect_file(p_ws)
        self.assertEqual(res2["format"], "JSON")
        self.assertTrue(res2["has_trailing_slack"])
        self.assertEqual(res2["slack_type"], "TRAILING_WHITESPACE")

        # 3. JSON with suspicious trailing data
        p_susp = os.path.join(self.temp_dir.name, "susp.json")
        with open(p_susp, "w", encoding="utf-8") as f:
            f.write('{"status": "ok"}/*UNMAPPED_PAYLOAD_HERE*/')
        res3 = BinarySlackInspector.inspect_file(p_susp)
        self.assertEqual(res3["format"], "JSON")
        self.assertTrue(res3["has_trailing_slack"])
        self.assertEqual(res3["slack_type"], "SUSPICIOUS_UNMAPPED_DOCUMENT_SLACK")

if __name__ == "__main__":
    unittest.main()
