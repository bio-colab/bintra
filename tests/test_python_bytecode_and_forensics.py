# -*- coding: utf-8 -*-
import os
import py_compile
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from python_intelligence import PythonBytecodeAnalyzer, FrozenPythonDetector
from windows_intelligence.runtime_telemetry.cpython_memory_forensics import CPythonMemoryForensics
from mcp_server import BintraMcpServer


class TestPythonBytecodeAndForensics(unittest.TestCase):
    def test_bytecode_analyzer_on_py_and_pyc(self):
        target_py = os.path.join(os.path.dirname(__file__), "..", "src", "token_telemetry.py")
        res = PythonBytecodeAnalyzer.analyze_file(target_py, limit=10)
        self.assertEqual(res["status"], "ok")
        self.assertGreater(res["code_objects_analyzed"], 1)
        self.assertGreater(res["total_basic_blocks"], 1)
        self.assertTrue(all(len(f["wl_cfg_hash"]) == 24 for f in res["functions"]))

        with tempfile.TemporaryDirectory() as td:
            pyc_path = os.path.join(td, "sample.pyc")
            py_compile.compile(target_py, cfile=pyc_path, doraise=True)
            pyc_res = PythonBytecodeAnalyzer.analyze_file(pyc_path, limit=10)
            self.assertEqual(pyc_res["status"], "ok")
            self.assertEqual(pyc_res["metadata"]["input_type"], "PYC_BYTECODE")
            diff = PythonBytecodeAnalyzer.compare_bytecode(target_py, pyc_path)
            self.assertEqual(diff["modified_count"], 0)

    def test_frozen_python_detector(self):
        synthetic_pe = b"MZ" + b"\x00" * 62 + b"PyInit_myext\x00__pyx_module\x00MEI\x0c\x0b\x0a\x0b\x0e\x08"
        res = FrozenPythonDetector.scan_bytes(synthetic_pe, file_path="myext.pyd")
        self.assertTrue(res["is_frozen_python"])
        self.assertTrue(res["is_pyd_extension"])
        self.assertIn("PYINSTALLER", res["detected_toolchains"])
        self.assertIn("CYTHON", res["detected_toolchains"])

    def test_cpython_memory_forensics_buffers(self):
        # PyASCIIObject: refcnt=1, type=0x7ff600001000, len=5, hash=0x1234, state=(1<<6)|(1<<5)|1 (compact+ascii)
        state = (1 << 6) | (1 << 5) | 1
        ascii_buf = struct.pack("<qQqqII", 1, 0x7FF600001000, 5, 0x1234, state, 0) + b"hello\x00\x00\x00"
        s_res = CPythonMemoryForensics.inspect_pyascii_buffer(ascii_buf, base_address=0x2000)
        self.assertEqual(s_res["status"], "ok")
        self.assertEqual(s_res["value_preview"], "hello")

        # PyLongObject: refcnt=1, type=0x7ff600002000, lv_tag=(1<<3)|0 (1 positive limb), limb=42
        long_buf = struct.pack("<qQQI", 1, 0x7FF600002000, (1 << 3), 42)
        l_res = CPythonMemoryForensics.inspect_pylong_buffer(long_buf, base_address=0x3000)
        self.assertEqual(l_res["decoded_value"], 42)

        # PyDictObject + PyDictKeysObject
        dict_buf = struct.pack("<qQqQQQ", 1, 0x7FF600003000, 1, 0x99, 0x4000, 0)
        keys_hdr = struct.pack("<qBBBBIqq", 1, 3, 0, 0, 0, 1, 4, 1)  # 32B, index_bytes=1
        entry0 = struct.pack("<qQQ", 0xABCD, 0x2000, 0x3000)
        d_res = CPythonMemoryForensics.inspect_pydict_buffer(dict_buf, keys_raw=keys_hdr + b"\x00" + entry0)
        self.assertEqual(d_res["ma_used"], 1)
        self.assertEqual(len(d_res["keys_table"]["entries_parsed"]), 1)
        self.assertEqual(d_res["keys_table"]["entries_parsed"][0]["me_key_ptr"], "0x2000")

    def test_mcp_python_bytecode_tool(self):
        srv = BintraMcpServer()
        target_py = os.path.join(os.path.dirname(__file__), "..", "src", "token_telemetry.py")
        resp = srv.dispatch_tool("bintra_python_bytecode", {"file_path": target_py, "limit": 5})
        self.assertEqual(resp["status"], "ok")


if __name__ == "__main__":
    unittest.main()
