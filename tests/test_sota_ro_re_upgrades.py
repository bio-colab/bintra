import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

import numpy as np

from binary_neural_engine import BinaryFormatInspector, SemanticFunctionMatcher, SensoryCortex
from bintra_engine import SafetensorsHandler, SubspaceAnalyzer
from ghidra_pcode_vectorizer import PcodeFunctionMatcher, PcodeVectorizer
from security.execution_guard import SecurityViolationError
from security.safe_file_access import SafeFileAccess
from security.safe_subprocess import SafeSubprocessBroker
from windows_intelligence.evidence_engine.graph_model import EvidenceEdge, EvidenceGraph, EvidenceNode
from windows_intelligence.runtime_telemetry.minidump_parser import MiniDumpParser


class TestSotaReadOnlyReUpgrades(unittest.TestCase):
    def test_pe_rich_tls_authenticode_and_checksum(self):
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            buf = bytearray(0x400)
            buf[0:2] = b"MZ"
            pe_off = 0x100
            struct.pack_into("<I", buf, 0x3C, pe_off)
            # Rich header at 0x90..0xB0 with xor_key=0x11223344
            xor_key = 0x11223344
            struct.pack_into("<I", buf, 0x90, 0x536E6144 ^ xor_key)  # DanS
            struct.pack_into("<II", buf, 0xA0, ((0x0104 << 16) | 30319) ^ xor_key, 2 ^ xor_key)
            buf[0xA8:0xAC] = b"Rich"
            struct.pack_into("<I", buf, 0xAC, xor_key)

            # PE Header + Optional Header (PE32+)
            buf[pe_off : pe_off + 4] = b"PE\x00\x00"
            struct.pack_into("<HHIIIHH", buf, pe_off + 4, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
            opt_off = pe_off + 24
            struct.pack_into("<H", buf, opt_off, 0x20B)
            struct.pack_into("<Q", buf, opt_off + 24, 0x140000000)  # ImageBase
            struct.pack_into("<I", buf, opt_off + 108, 16)
            # Security directory (index 4 -> opt_off + 112 + 32): file_offset=0x300, size=16
            struct.pack_into("<II", buf, opt_off + 112 + 4 * 8, 0x300, 16)
            # TLS directory (index 9 -> opt_off + 112 + 72): rva=0x1000, size=40
            struct.pack_into("<II", buf, opt_off + 112 + 9 * 8, 0x1000, 40)

            # Section .text at pe_off + 24 + 0xF0 = 0x208 -> va=0x1000, raw_off=0x280, raw_sz=0x80
            sec_off = opt_off + 0xF0
            buf[sec_off : sec_off + 8] = b".text\x00\x00\x00"
            struct.pack_into("<IIIIIIHHI", buf, sec_off + 8, 0x80, 0x1000, 0x80, 0x280, 0, 0, 0, 0, 0x60000020)

            # TLS directory at 0x280 (RVA 0x1000), callback array at RVA 0x1030 -> file_off 0x2B0
            struct.pack_into("<Q", buf, 0x280 + 24, 0x140001030)
            struct.pack_into("<QQ", buf, 0x2B0, 0x140001050, 0)

            # WIN_CERTIFICATE at 0x300
            struct.pack_into("<IHH", buf, 0x300, 16, 0x0200, 0x0002)

            tf.write(buf)
            path = tf.name

        try:
            info = BinaryFormatInspector._parse_pe(path)
            self.assertTrue(info["rich_header"]["present"])
            self.assertEqual(info["rich_header"]["entries"][0]["prod_id"], 0x0104)
            self.assertEqual(info["rich_header"]["entries"][0]["build_number"], 30319)
            self.assertTrue(info["tls"]["present"])
            self.assertEqual(info["tls"]["callbacks"], ["0x140001050"])
            self.assertTrue(info["security_authenticode"]["signed"])
            self.assertEqual(info["security_authenticode"]["certificate_type"], "PKCS_SIGNED_DATA")
            self.assertFalse(info["sections_truncated"])
            chk = BinaryFormatInspector.calculate_pe_checksum(buf, pe_off)
            self.assertIsInstance(chk, int)
            self.assertGreater(chk, 0)
        finally:
            os.unlink(path)

    def test_semantic_matcher_arm64_and_batch(self):
        # ARM64 BL + NOP + RET (non-RET-ending sequence via B)
        # 0x94000001 (BL +4), 0xD503201F (NOP), 0x14000002 (B +8)
        arm64_hex = struct.pack("<III", 0x94000001, 0xD503201F, 0x14000002).hex()
        v1 = SemanticFunctionMatcher.vectorize_function(arm64_hex)
        self.assertGreater(float(np.linalg.norm(v1)), 0.99)
        batch = SemanticFunctionMatcher.match_batch(np.stack([v1]), np.stack([v1]))
        self.assertAlmostEqual(float(batch[0, 0]), 1.0, places=5)

    def test_sensory_cortex_read_only_surface(self):
        res = SensoryCortex.evaluate_all_senses()
        touch = res["senses"]["active_touch"]["telemetry"]
        self.assertTrue(touch["read_only_enforced"])
        self.assertNotIn("supported_weight_operations", touch)

    def test_pcode_vectorizer_copy_and_cfg_topology(self):
        ops = [
            {"opcode": "COPY"},
            {"opcode": "INT_ADD"},
            {"opcode": "CBRANCH"},
            {"opcode": "RETURN"},
        ]
        blocks = [
            {"id": "b0", "out_blocks": ["b1", "b2"]},
            {"id": "b1", "out_blocks": ["b0"]},
            {"id": "b2", "out_blocks": []},
        ]
        res = PcodeVectorizer.vectorize_high_function(ops, blocks)
        self.assertEqual(res["category_histogram"]["SUBPIECE_CAST"], 1)
        self.assertEqual(res["category_histogram"]["ALU_ARITH"], 1)
        self.assertIn("cfg_topology", res)
        v = np.array(res["vector"], dtype=np.float32)
        sim = PcodeFunctionMatcher.match_batch(np.stack([v]), np.stack([v]))
        self.assertAlmostEqual(float(sim[0, 0]), 1.0, places=5)

    def test_minidump_memory_list_and_codeview_pdb(self):
        with tempfile.NamedTemporaryFile(suffix=".dmp", delete=False) as tf:
            # Header (32) + 3 dir entries (36) + ModList (4 + 108 = 112) + MemList (4 + 16 = 20) + ModName + RSDS
            buf = bytearray(512)
            buf[0:4] = b"MDMP"
            struct.pack_into("<II", buf, 4, 0xA793, 3)  # Version, NumStreams=3
            struct.pack_into("<I", buf, 12, 32)  # StreamDirectoryRva=32

            # Stream 4 (ModuleList) at 80, size 112
            struct.pack_into("<III", buf, 32, 4, 112, 80)
            # Stream 5 (MemoryList) at 200, size 20
            struct.pack_into("<III", buf, 44, 5, 20, 200)
            # Stream 7 (SystemInfo) at 230, size 56
            struct.pack_into("<III", buf, 56, 7, 56, 230)

            # SystemInfo: arch=9 (AMD64)
            struct.pack_into("<H", buf, 230, 9)

            # ModuleList: count=1, name_rva=300, cv_size=33, cv_rva=340
            struct.pack_into("<I", buf, 80, 1)
            mod_off = 84
            struct.pack_into("<QIIII", buf, mod_off, 0x7FF700000000, 0x10000, 0x1234, 0, 300)
            struct.pack_into("<IIII", buf, mod_off + 24, 0xFEEF04BD, 0, (1 << 16) | 2, (3 << 16) | 4)
            struct.pack_into("<II", buf, mod_off + 76, 33, 340)

            # ModName at 300 (UTF-16LE "app.exe")
            name_bytes = "app.exe".encode("utf-16-le")
            struct.pack_into("<I", buf, 300, len(name_bytes))
            buf[304 : 304 + len(name_bytes)] = name_bytes

            # RSDS at 340
            buf[340:344] = b"RSDS"
            struct.pack_into("<IHH", buf, 344, 0x11223344, 0x5566, 0x7788)
            buf[352:360] = b"\x99\xaa\xbb\xcc\xdd\xee\xff\x00"
            struct.pack_into("<I", buf, 360, 1)
            buf[364:372] = b"app.pdb\x00"

            # MemoryList at 200: 1 range VA=0x1000, size=8, file_rva=400
            struct.pack_into("<I", buf, 200, 1)
            struct.pack_into("<QII", buf, 204, 0x1000, 8, 400)
            buf[400:408] = b"\x48\x89\x5c\x24\x08\xc3\x90\x90"

            tf.write(buf)
            dmp_path = tf.name

        try:
            parsed = MiniDumpParser.parse_minidump(dmp_path)
            self.assertEqual(parsed["modules"][0]["file_version"], "1.2.3.4")
            self.assertEqual(parsed["modules"][0]["pdb"]["pdb_name"], "app.pdb")
            mem = MiniDumpParser.read_memory_from_dump(dmp_path, parsed, 0x1000, 6)
            self.assertEqual(mem, b"\x48\x89\x5c\x24\x08\xc3")
        finally:
            os.unlink(dmp_path)

    def test_evidence_graph_mermaid_syntax(self):
        g = EvidenceGraph()
        g.add_node("SEC:.text(0)", "PE_SECTION", ".text")
        m = g.to_mermaid()
        self.assertIn(":::secClass", m)
        self.assertNotIn(":;:secClass", m)

    def test_safetensors_bool_and_empty_tensor_guards(self):
        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as tf:
            hdr = json.dumps({"bad": {"dtype": "F32", "shape": [True, 2], "data_offsets": [0, 8]}}).encode("utf-8")
            tf.write(struct.pack("<Q", len(hdr)) + hdr + b"\x00" * 8)
            path = tf.name
        try:
            with self.assertRaises(ValueError):
                SafetensorsHandler.read_header(path)
            self.assertEqual(SubspaceAnalyzer.analyze_sparse_extremes(np.zeros((0, 4), dtype=np.float32)), [])
        finally:
            os.unlink(path)

    def test_safe_subprocess_fail_closed_and_nofollow(self):
        with self.assertRaises(SecurityViolationError):
            SafeSubprocessBroker._resolve_system_exe("nonexistent_bintra_tool_xyz.exe")

        with tempfile.TemporaryDirectory() as td:
            real_f = Path(td) / "real.bin"
            real_f.write_bytes(b"MZ")
            sym_f = Path(td) / "link.bin"
            try:
                os.symlink(real_f, sym_f)
                if hasattr(os, "O_NOFOLLOW"):
                    with self.assertRaises(OSError):
                        os.close(os.open(str(sym_f), os.O_RDONLY | os.O_NOFOLLOW))
            except OSError as err:
                # Gracefully handle Windows hosts lacking SeCreateSymbolicLinkPrivilege
                if getattr(err, "winerror", None) == 1314 or isinstance(err, PermissionError):
                    pass
                else:
                    raise


if __name__ == "__main__":
    unittest.main()
