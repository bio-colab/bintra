# -*- coding: utf-8 -*-
"""
End-to-End Integration Pipeline Test for Ghidra Static & Semantic Reverse Engineering.
Verifies the complete analytical trajectory:
  1. Ghidra JSON P-Code extraction ingestion
  2. Live Bridge JSON-RPC bidirectional exchange
  3. Inter-procedural Call Graph construction & Sensitive Win32 API Reachability
  4. Intra-procedural SSA Def-Use Data-Flow Slicing (backward and forward)
  5. Weisfeiler-Lehman CFG structural invariant hashing
  6. Multi-Source Evidence Fusion into Unified EvidenceGraph
"""

import os
import sys
import json
import unittest
import tempfile

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from security import ExecutionGuard
from ghidra_pcode_vectorizer import (
    PcodeVectorizer,
    WeisfeilerLehmanCfgHasher,
    GhidraDeepAnalyzer,
    PcodeFunctionMatcher
)
from ghidra_live_bridge import GhidraLiveBridgeServer
from windows_intelligence.evidence_engine.graph_model import fuse_static_dynamic_ghidra
from pe_deep_forensics import SemanticBinaryDiffer


class TestGhidraE2EPipeline(unittest.TestCase):
    """Rigorous end-to-end pipeline integration verification across Ghidra static & semantic subsystems."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.scope = ExecutionGuard.scoped_session(workspace_dir=self.tmp_dir.name)
        self.scope.__enter__()

        # Realistic Ghidra JSON export fixture with interconnected functions
        self.ghidra_export = {
            "program_name": "target_service.exe",
            "image_base": "0x140000000",
            "functions": [
                {
                    "name": "wmain",
                    "entry_point": "0x140001000",
                    "callees": ["init_runtime", "dispatch_worker"],
                    "xrefs": [],
                    "pcode_ops": [
                        {"opcode": "CALL", "address": "0x140001010", "inputs": [], "output": "rax", "target_name": "init_runtime"},
                        {"opcode": "CALL", "address": "0x140001030", "inputs": ["rax"], "output": "rcx", "target_name": "dispatch_worker"},
                        {"opcode": "RETURN", "address": "0x140001040", "inputs": ["rcx"], "output": None},
                    ],
                    "basic_blocks": [
                        {"id": "bb0", "start": "0x140001000", "end": "0x140001040", "successors": []}
                    ],
                    "api_calls": ["init_runtime", "dispatch_worker"],
                    "strings": ["Starting service..."],
                },
                {
                    "name": "init_runtime",
                    "entry_point": "0x140002000",
                    "callees": ["HeapCreate"],
                    "xrefs": [{"from": "0x140001010", "to": "0x140002000", "type": "UNCONDITIONAL_CALL"}],
                    "pcode_ops": [
                        {"opcode": "COPY", "address": "0x140002005", "inputs": ["0x40000"], "output": "init_sz"},
                        {"opcode": "CALL", "address": "0x140002015", "inputs": ["0", "init_sz", "0"], "output": "hHeap", "target_name": "HeapCreate"},
                        {"opcode": "RETURN", "address": "0x140002025", "inputs": ["hHeap"], "output": None},
                    ],
                    "basic_blocks": [
                        {"id": "bb_init", "start": "0x140002000", "end": "0x140002025", "successors": []}
                    ],
                    "api_calls": ["HeapCreate"],
                    "strings": [],
                },
                {
                    "name": "dispatch_worker",
                    "entry_point": "0x140003000",
                    "callees": ["allocate_executable_buffer", "decrypt_payload"],
                    "xrefs": [{"from": "0x140001030", "to": "0x140003000", "type": "UNCONDITIONAL_CALL"}],
                    "pcode_ops": [
                        {"opcode": "CALL", "address": "0x140003020", "inputs": ["0x1000"], "output": "buf_ptr", "target_name": "allocate_executable_buffer"},
                        {"opcode": "CALL", "address": "0x140003040", "inputs": ["buf_ptr"], "output": "status", "target_name": "decrypt_payload"},
                        {"opcode": "RETURN", "address": "0x140003050", "inputs": ["status"], "output": None},
                    ],
                    "basic_blocks": [
                        {"id": "bb_disp", "start": "0x140003000", "end": "0x140003050", "successors": []}
                    ],
                    "api_calls": ["allocate_executable_buffer", "decrypt_payload"],
                    "strings": ["Worker dispatched"],
                },
                {
                    "name": "allocate_executable_buffer",
                    "entry_point": "0x140004000",
                    "signature": "void* allocate_executable_buffer(uint32_t size)",
                    "decompiled_c": "void* allocate_executable_buffer(uint32_t size) {\n    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n}",
                    "local_variables": [
                        {"name": "size", "type": "uint32_t", "storage": "ECX"},
                        {"name": "pMem", "type": "void*", "storage": "RAX"},
                    ],
                    "callees": ["VirtualAlloc"],
                    "xrefs": [{"from": "0x140003020", "to": "0x140004000", "type": "UNCONDITIONAL_CALL"}],
                    "pcode_ops": [
                        {"opcode": "COPY", "address": "0x140004002", "inputs": ["param_1"], "output": "req_size"},
                        {"opcode": "INT_ZEXT", "address": "0x140004006", "inputs": ["req_size"], "output": "z_size"},
                        {"opcode": "COPY", "address": "0x14000400A", "inputs": ["0x3000"], "output": "flAllocationType"},
                        {"opcode": "COPY", "address": "0x14000400F", "inputs": ["0x40"], "output": "flProtect"},
                        {"opcode": "CALL", "address": "0x140004015", "inputs": ["0", "z_size", "flAllocationType", "flProtect"], "output": "pMem", "target_name": "VirtualAlloc"},
                        {"opcode": "RETURN", "address": "0x140004020", "inputs": ["pMem"], "output": None},
                    ],
                    "basic_blocks": [
                        {"id": "bb_alloc", "start": "0x140004000", "end": "0x140004020", "successors": []}
                    ],
                    "api_calls": ["VirtualAlloc"],
                    "strings": [],
                },
                {
                    "name": "decrypt_payload",
                    "entry_point": "0x140005000",
                    "callees": ["CreateFileW"],
                    "xrefs": [{"from": "0x140003040", "to": "0x140005000", "type": "UNCONDITIONAL_CALL"}],
                    "pcode_ops": [
                        {"opcode": "COPY", "address": "0x140005010", "inputs": ["\"payload.bin\""], "output": "fName"},
                        {"opcode": "CALL", "address": "0x140005020", "inputs": ["fName", "0x80000000"], "output": "hFile", "target_name": "CreateFileW"},
                        {"opcode": "RETURN", "address": "0x140005030", "inputs": ["hFile"], "output": None},
                    ],
                    "basic_blocks": [
                        {"id": "bb_dec", "start": "0x140005000", "end": "0x140005030", "successors": []}
                    ],
                    "api_calls": ["CreateFileW"],
                    "strings": ["payload.bin"],
                }
            ]
        }

    def tearDown(self):
        try:
            self.scope.__exit__(None, None, None)
        finally:
            self.tmp_dir.cleanup()

    def test_e2e_ghidra_analysis_pipeline_and_evidence_fusion(self):
        """Executes full end-to-end analytical pipeline from raw Ghidra export to multi-source evidence fusion."""
        analyzer = GhidraDeepAnalyzer()

        # Step 1: Call Graph & Sensitive API Reachability
        cg = analyzer.build_call_graph_and_xrefs(self.ghidra_export, target_function="wmain", max_depth=5)
        self.assertEqual(cg["status"], "ok")
        self.assertEqual(cg["functions_indexed"], 5)
        self.assertGreaterEqual(cg["call_edges_count"], 4)

        # Sensitive Win32 APIs must be identified with full call paths
        sens_apis = {entry["api"]: entry for entry in cg["sensitive_api_reachability"]}
        self.assertIn("VirtualAlloc", sens_apis)
        self.assertIn("CreateFileW", sens_apis)

        # Check call path reachability: dispatch_worker -> allocate_executable_buffer -> VirtualAlloc
        valloc_info = sens_apis["VirtualAlloc"]
        self.assertIn("dispatch_worker", valloc_info["upstream_callers"])
        self.assertEqual(valloc_info["direct_caller"], "allocate_executable_buffer")

        # Step 2: Intra-procedural SSA Def-Use Data Flow Slicing
        alloc_fn = next(f for f in self.ghidra_export["functions"] if f["name"] == "allocate_executable_buffer")
        df_slice = analyzer.slice_data_flow(alloc_fn, target_var="pMem")
        self.assertEqual(df_slice["status"], "ok")
        self.assertEqual(df_slice["function"], "allocate_executable_buffer")
        self.assertGreaterEqual(len(df_slice["backward_slice"]), 3)
        self.assertTrue(df_slice["decompiler_summary"]["has_decompiled_c"])
        self.assertIn("PAGE_EXECUTE_READWRITE", df_slice["decompiler_summary"]["decompiled_c_preview"])

        # Step 3: Weisfeiler-Lehman CFG Isomorphism Hashing
        wl_hasher = WeisfeilerLehmanCfgHasher(iterations=2)
        h1 = wl_hasher.compute_wl_hash(alloc_fn["basic_blocks"], pcode_ops=alloc_fn["pcode_ops"])
        self.assertIsInstance(h1, str)
        self.assertGreaterEqual(len(h1), 16)

        # Step 4: Live Bridge IPC Cache Dispatch
        bridge = GhidraLiveBridgeServer(port=0)
        bridge.dispatch_rpc_method("ghidra.push_pcode", alloc_fn)
        retrieved_cg = bridge.dispatch_rpc_method("bintra.query_call_graph", {"target_function": "allocate_executable_buffer"})
        self.assertEqual(retrieved_cg["status"], "ok")
        retrieved_dc = bridge.dispatch_rpc_method("bintra.query_decompiled_c", {"function": "allocate_executable_buffer"})
        self.assertTrue(retrieved_dc["has_decompiled_c"])

        # Step 5: Multi-Source Evidence Fusion into Unified EvidenceGraph
        fused = fuse_static_dynamic_ghidra(
            pe_forensics={
                "status": "ok",
                "sha256": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
                "file": "target_service.exe",
                "pdata_functions": {"total_runtime_functions": 5},
                "msvc_rtti": {"vftables_count": 1},
                "pdb_correlation": {"pdb_verification": {"guid_match": True, "age_match": True, "is_exact_match": True}},
            },
            crash_rca={
                "exception_code": "0xC0000005",
                "root_cause_classification": "DEP_VIOLATION",
                "culprit_register": "RIP",
                "fault_address": "0x140004015",
                "confidence": 0.95,
            },
            ghidra_call_graph=cg,
            ghidra_data_flow=df_slice,
        )

        self.assertEqual(fused["status"], "ok")
        graph = fused["fused_graph"]
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)
        self.assertEqual(len(graph["nodes"]), 4)  # pe_forensics, crash_rca, ghidra_call_graph, ghidra_data_flow
        self.assertGreaterEqual(len(graph["edges"]), 4)

        # Verify edge attributes and cross-correlation
        edge_relations = [e["relation"] for e in graph["edges"]]
        self.assertIn("EXHIBITED_FAULT", edge_relations)
        self.assertIn("DECOMPILED_TOPOLOGY", edge_relations)
        self.assertIn("CONTAINS_SLICE", edge_relations)
        self.assertIn("EXPLAINS_DATA_PROVENANCE", edge_relations)


if __name__ == "__main__":
    unittest.main()
