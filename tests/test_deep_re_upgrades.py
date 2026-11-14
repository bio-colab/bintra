# -*- coding: utf-8 -*-
"""
Automated tests for Bintra v1.1 Deep Reverse Engineering, Ghidra Topology/Data-Flow,
PE Deep Forensics (.pdata, MSVC RTTI, offline PDB), Semantic Diffing, and AI Discoverability.
"""

import json
import os
import struct
import tempfile
import unittest
import uuid

from pe_deep_forensics import PeDeepForensicsInspector, SemanticBinaryDiffer
from ghidra_pcode_vectorizer import WeisfeilerLehmanCfgHasher, GhidraDeepAnalyzer
from ghidra_live_bridge import GhidraLiveBridgeServer
from windows_intelligence.evidence_engine.graph_model import fuse_static_dynamic_ghidra
from mcp_server import BintraMcpServer


def _build_synthetic_pe64_with_forensics(pdb_path: str, guid_bytes: bytes) -> bytes:
    """Builds a minimal valid PE32+ with .text, .rdata (RTTI+Debug), and .pdata."""
    buf = bytearray(0x2000)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    # COFF: AMD64 (0x8664), 3 sections, OptionalHeaderSize=240
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x8664, 3, 0, 0, 0, 240, 0x22)
    opt_off = 0x98
    struct.pack_into("<H", buf, opt_off, 0x20B)  # PE32+
    struct.pack_into("<Q", buf, opt_off + 24, 0x140000000)  # ImageBase
    struct.pack_into("<I", buf, opt_off + 108, 16)  # NumberOfRvaAndSizes
    dd_off = opt_off + 112
    # DataDirectory[3] = Exception (.pdata) at RVA 0x3000, size 12
    struct.pack_into("<II", buf, dd_off + 3 * 8, 0x3000, 12)
    # DataDirectory[6] = Debug at RVA 0x2200, size 28
    struct.pack_into("<II", buf, dd_off + 6 * 8, 0x2200, 28)

    sec_off = opt_off + 240
    # Section 0: .text (VA 0x1000, raw 0x400, size 0x400)
    buf[sec_off:sec_off + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, sec_off + 8, 0x400, 0x1000, 0x400, 0x400, 0, 0, 0, 0, 0x60000020)
    # Section 1: .rdata (VA 0x2000, raw 0x800, size 0x400)
    buf[sec_off + 40:sec_off + 48] = b".rdata\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, sec_off + 48, 0x400, 0x2000, 0x400, 0x800, 0, 0, 0, 0, 0x40000040)
    # Section 2: .pdata (VA 0x3000, raw 0xC00, size 0x400)
    buf[sec_off + 80:sec_off + 88] = b".pdata\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, sec_off + 88, 0x400, 0x3000, 0x400, 0xC00, 0, 0, 0, 0, 0x40000040)

    # .text dummy code
    buf[0x400:0x404] = b"\x48\x83\xEC\x28"

    # .pdata RUNTIME_FUNCTION: Begin=0x1000, End=0x1120, Unwind=0x2020 (in .rdata)
    struct.pack_into("<III", buf, 0xC00, 0x1000, 0x1120, 0x2020)
    # UNWIND_INFO at raw 0x820 (RVA 0x2020): ver=1 | flags=1 (EHANDLER) -> 0x09, prolog=4, codes=0, frame=0
    struct.pack_into("<BBBB", buf, 0x820, 0x09, 4, 0, 0)

    # MSVC RTTI TypeDescriptor at raw 0x840 (RVA 0x2040): 16-byte header + ".?AVEngineCore@Bintra@@\x00"
    td_name = b".?AVEngineCore@Bintra@@\x00"
    buf[0x850:0x850 + len(td_name)] = td_name
    # x64 CompleteObjectLocator at raw 0x880 (RVA 0x2080)
    struct.pack_into("<IIIIII", buf, 0x880, 1, 0, 0, 0x2040, 0x20B0, 0x2080)
    # vftable at raw 0x900 (RVA 0x2100): slot[-1] = COL VA (0x140002080), slot[0] = .text VA (0x140001000)
    struct.pack_into("<QQ", buf, 0x8F8, 0x140002080, 0x140001000)

    # IMAGE_DEBUG_DIRECTORY at raw 0xA00 (RVA 0x2200) -> RSDS at raw 0xA40
    rsds = b"RSDS" + guid_bytes + struct.pack("<I", 1) + pdb_path.encode("utf-8") + b"\x00"
    struct.pack_into("<IIHHIIII", buf, 0xA00, 0, 0, 0, 0, 2, len(rsds), 0x2240, 0xA40)
    buf[0xA40:0xA40 + len(rsds)] = rsds

    return bytes(buf)


def _build_synthetic_msf7_pdb(guid_bytes: bytes) -> bytes:
    """Builds a minimal valid MSF 7.00 PDB with Stream 1 (PDB Info) matching guid_bytes."""
    bs = 512
    # 6 blocks total: 0=superblock, 1=free, 2=dir_map, 3=stream_dir, 4=stream0, 5=stream1
    data = bytearray(bs * 6)
    magic = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
    data[0:len(magic)] = magic
    # Stream directory: 2 streams -> sizes [4, 28], blocks [4], [5]
    sdir = struct.pack("<IIIIII", 2, 4, 28, 4, 5, 0)[:20]
    data[bs * 3:bs * 3 + len(sdir)] = sdir
    # Directory map at block 2 points to block 3
    struct.pack_into("<I", data, bs * 2, 3)
    # Superblock fields at offset 32
    struct.pack_into("<IIIIII", data, 32, bs, 1, 6, len(sdir), 0, 2)
    # Stream 1 (PDB Info) at block 5: Version(4), Sig(4), Age(4), GUID(16)
    struct.pack_into("<III", data, bs * 5, 20000404, 123456, 1)
    data[bs * 5 + 12:bs * 5 + 28] = guid_bytes
    return bytes(data)


class TestDeepReUpgrades(unittest.TestCase):

    def test_pe_deep_forensics_pdata_rtti_and_offline_pdb(self):
        with tempfile.TemporaryDirectory() as tmp:
            pdb_file = os.path.join(tmp, "sample.pdb")
            exe_file = os.path.join(tmp, "sample.exe")
            guid_raw = uuid.UUID("11223344-5566-7788-99AA-BBCCDDEEFF00").bytes_le
            with open(pdb_file, "wb") as f:
                f.write(_build_synthetic_msf7_pdb(guid_raw))
            with open(exe_file, "wb") as f:
                f.write(_build_synthetic_pe64_with_forensics(pdb_file, guid_raw))

            res = PeDeepForensicsInspector().inspect(exe_file)
            self.assertEqual(res["status"], "ok")
            self.assertEqual(res["pdata_functions"]["total_runtime_functions"], 1)
            self.assertEqual(res["pdata_functions"]["functions"][0]["begin_rva"], "0x1000")
            self.assertTrue(res["pdata_functions"]["functions"][0]["unwind_info"]["has_ehandler"])
            self.assertGreaterEqual(res["msvc_rtti"]["type_descriptors_count"], 1)
            self.assertEqual(res["msvc_rtti"]["vftables_count"], 1)
            self.assertEqual(res["msvc_rtti"]["vftables"][0]["demangled_hint"], "class Bintra::EngineCore")
            self.assertTrue(res["pdb_correlation"]["pdb_verification"]["msf_valid"])
            self.assertTrue(res["pdb_correlation"]["pdb_verification"]["guid_match"])

    def test_wl_cfg_hasher_and_semantic_binary_diff(self):
        wl = WeisfeilerLehmanCfgHasher(iterations=2)
        bbs_a = [
            {"id": "0", "successors": ["1", "2"], "pcode_ops": [{"opcode": "INT_EQUAL"}, {"opcode": "CBRANCH"}]},
            {"id": "1", "successors": [], "pcode_ops": [{"opcode": "RETURN"}]},
            {"id": "2", "successors": [], "pcode_ops": [{"opcode": "RETURN"}]},
        ]
        bbs_b_reordered = list(reversed(bbs_a))
        self.assertEqual(wl.compute_wl_hash(bbs_a), wl.compute_wl_hash(bbs_b_reordered))

        base_funcs = [
            {"name": "fn_same", "basic_blocks": bbs_a, "pcode_ops": [{"opcode": "INT_EQUAL"}, {"opcode": "CBRANCH"}, {"opcode": "RETURN"}]},
            {"name": "fn_old", "pcode_ops": [{"opcode": "INT_ADD"}, {"opcode": "RETURN"}]},
        ]
        targ_funcs = [
            {"name": "fn_same_renamed", "basic_blocks": bbs_b_reordered, "pcode_ops": [{"opcode": "INT_EQUAL"}, {"opcode": "CBRANCH"}, {"opcode": "RETURN"}]},
            {"name": "fn_new", "pcode_ops": [{"opcode": "CALL"}, {"opcode": "STORE"}, {"opcode": "RETURN"}]},
        ]
        diff = SemanticBinaryDiffer().diff_function_exports(base_funcs, targ_funcs)
        self.assertEqual(diff["summary"]["identical_count"], 1)
        self.assertEqual(diff["summary"]["added_count"], 1)
        self.assertEqual(diff["summary"]["removed_count"], 1)

    def test_ghidra_deep_analyzer_call_graph_and_data_flow(self):
        export = {
            "program_name": "test.exe",
            "functions": [
                {
                    "name": "main",
                    "entry_point": "0x1000",
                    "callees": ["load_plugin"],
                    "xrefs": [{"from": "0x0800", "to": "0x1000", "type": "UNCONDITIONAL_CALL"}],
                    "pcode_ops": [],
                },
                {
                    "name": "load_plugin",
                    "entry_point": "0x1200",
                    "callees": ["LoadLibraryW"],
                    "signature": "void load_plugin(wchar_t *path)",
                    "local_variables": [{"name": "hMod", "type": "HMODULE", "storage": "RAX"}],
                    "decompiled_c": "void load_plugin(wchar_t *path) { LoadLibraryW(path); }",
                    "pcode_ops": [
                        {"opcode": "COPY", "address": "0x1204", "inputs": ["param_1"], "output": "v_ptr"},
                        {"opcode": "LOAD", "address": "0x1208", "inputs": ["v_ptr"], "output": "v_val"},
                        {"opcode": "CALL", "address": "0x1210", "inputs": ["v_val"], "output": "res", "target_name": "LoadLibraryW"},
                    ],
                },
            ],
        }
        analyzer = GhidraDeepAnalyzer()
        cg = analyzer.build_call_graph_and_xrefs(export, target_function="main", max_depth=3)
        self.assertEqual(cg["functions_indexed"], 2)
        self.assertEqual(len(cg["sensitive_api_reachability"]), 1)
        self.assertEqual(cg["sensitive_api_reachability"][0]["api"], "LoadLibraryW")
        self.assertIn("main", cg["sensitive_api_reachability"][0]["upstream_callers"])

        df = analyzer.slice_data_flow(export["functions"][1], target_var="res")
        self.assertEqual(df["function"], "load_plugin")
        self.assertGreaterEqual(len(df["backward_slice"]), 2)
        self.assertTrue(df["decompiler_summary"]["has_decompiled_c"])

    def test_ghidra_live_bridge_read_queries(self):
        import threading
        srv = GhidraLiveBridgeServer(port=0)
        if not hasattr(srv, "_cache_lock"):
            srv._cache_lock = threading.Lock()
        srv.dispatch_rpc_method("ghidra.push_pcode", {
            "name": "sub_401000",
            "entry_point": "0x401000",
            "callees": ["VirtualAlloc"],
            "decompiled_c": "void sub_401000(void) { VirtualAlloc(0, 4096, 0x3000, 4); }",
            "pcode_ops": [{"opcode": "CALL", "address": "0x401010", "inputs": ["0"], "output": "rax", "target_name": "VirtualAlloc"}],
        })
        cg = srv.dispatch_rpc_method("bintra.query_call_graph", {"target_function": "sub_401000"})
        self.assertEqual(cg["functions_indexed"], 1)
        dc = srv.dispatch_rpc_method("bintra.query_decompiled_c", {"function": "sub_401000"})
        self.assertTrue(dc["has_decompiled_c"])
        df = srv.dispatch_rpc_method("bintra.query_data_flow", {"function": "sub_401000", "target_var": "rax"})
        self.assertEqual(df["function"], "sub_401000")

    def test_mcp_40_tools_capabilities_manifest_and_evidence_fusion(self):
        srv = BintraMcpServer()
        tools = srv.handle_tools_list({})["tools"]
        self.assertEqual(len(tools), 40)

        cap_resp = srv.handle_tools_call({"name": "bintra_list_capabilities", "arguments": {"platform_filter": "cross_platform"}})
        payload = json.loads(cap_resp["content"][0]["text"])
        self.assertEqual(payload["status"], "ok")
        self.assertGreaterEqual(payload["total_tools"], 15)

        fused = fuse_static_dynamic_ghidra(
            pe_forensics={"status": "ok", "sha256": "abc123def456", "file": "a.exe", "pdata_functions": {"total_runtime_functions": 10}, "msvc_rtti": {"vftables_count": 2}, "pdb_correlation": {"pdb_verification": {"guid_match": True}}},
            crash_rca={"exception_code": "0xC0000005", "root_cause_classification": "NULL_DEREF", "culprit_register": "RAX", "fault_address": "0x0", "confidence": 0.9},
            ghidra_call_graph={"status": "ok", "functions_indexed": 5, "call_edges_count": 4, "indirect_calls_count": 0, "sensitive_api_reachability": []},
            ghidra_data_flow={"status": "ok", "function": "sub_1", "sources_count": 1, "sinks_count": 1, "backward_slice": []},
        )
        self.assertEqual(fused["status"], "ok")
        self.assertEqual(len(fused["fused_graph"]["nodes"]), 4)
        self.assertEqual(len(fused["fused_graph"]["edges"]), 4)


if __name__ == "__main__":
    unittest.main()
