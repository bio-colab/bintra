#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for Bintra Ghidra Advanced Integration:
- Pure-Python MSVC C++ Symbol Demangling
- Advanced Function Search (Name, RVA, Opcode, XREF, Decompiled C)
- Deep Single-Function Architectural Inspection
- Global Computational Profiling (12-Category P-Code Distribution)
- ExecutionGuard Mediation for all Ghidra Operations
- Headless Analyzer Timeout Resilience & Transient Project Isolation
"""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from ghidra_pcode_vectorizer import GhidraDeepAnalyzer
from ghidra_export_store import GhidraExportStore


MOCK_GHIDRA_EXPORT = {
    "program_name": "TestNetworkApp.exe",
    "image_base": "0x140000000",
    "functions": [
        {
            "name": "?ProcessPacket@NetworkManager@@QEAA_NPEBDH@Z",
            "entry_point": "0x140001000",
            "size": 256,
            "signature": "bool NetworkManager::ProcessPacket(char const*, int)",
            "return_type": "bool",
            "parameter_count": 2,
            "parameters": [
                {"name": "buf", "type": "char const*", "ordinal": 0},
                {"name": "len", "type": "int", "ordinal": 1}
            ],
            "local_variables": [
                {"name": "uVar1", "type": "uint", "offset": -8},
                {"name": "pvVar2", "type": "void*", "offset": -16}
            ],
            "callees": ["LoadLibraryA", "WSASocketA", "sub_140002000"],
            "xrefs": [
                {"from": "0x140001010", "to": "0x140005000", "type": "DATA", "symbol": "s_PacketHeader"},
                {"from": "0x140001050", "to": "0x140006000", "type": "CALL", "symbol": "WSASocketA"}
            ],
            "decompiled_c": "bool ProcessPacket(char *buf, int len) {\n    if (len < 4) return false;\n    void *sock = WSASocketA(2, 1, 0, 0, 0, 0);\n    return true;\n}",
            "basic_blocks": [
                {"id": 0, "start": "0x140001000", "stop": "0x140001030", "in_degree": 0, "out_degree": 2, "successors": [1, 2]},
                {"id": 1, "start": "0x140001031", "stop": "0x140001050", "in_degree": 1, "out_degree": 1, "successors": [2]},
                {"id": 2, "start": "0x140001051", "stop": "0x140001100", "in_degree": 2, "out_degree": 0, "successors": []}
            ],
            "pcode_ops": [
                {"opcode": "INT_LESS", "address": "0x140001005", "inputs": ["in_len", "4"], "output": "uVar1"},
                {"opcode": "CBRANCH", "address": "0x140001008", "inputs": ["0x140001051", "uVar1"]},
                {"opcode": "CALL", "address": "0x140001020", "inputs": ["WSASocketA"], "output": "sock", "target_name": "WSASocketA"},
                {"opcode": "RETURN", "address": "0x140001080", "inputs": ["1"]}
            ]
        },
        {
            "name": "??0CString@@QEAA@PEBD@Z",
            "entry_point": "0x140002000",
            "size": 128,
            "signature": "void CString::CString(char const*)",
            "return_type": "void",
            "parameter_count": 1,
            "callees": ["memcpy"],
            "xrefs": [
                {"from": "0x140002010", "to": "0x140007000", "type": "DATA", "symbol": "s_EmptyString"}
            ],
            "decompiled_c": "void CString(char *s) { this->m_str = strdup(s); }",
            "basic_blocks": [
                {"id": 0, "start": "0x140002000", "stop": "0x140002080", "in_degree": 0, "out_degree": 0, "successors": []}
            ],
            "pcode_ops": [
                {"opcode": "CALLIND", "address": "0x140002020", "inputs": ["vtable_ptr"]},
                {"opcode": "RETURN", "address": "0x140002080", "inputs": []}
            ]
        },
        {
            "name": "compute_checksum_fast",
            "entry_point": "0x140003000",
            "size": 64,
            "signature": "uint compute_checksum_fast(byte *data, int len)",
            "return_type": "uint",
            "parameter_count": 2,
            "callees": [],
            "xrefs": [],
            "decompiled_c": "uint compute_checksum_fast(byte *data, int len) { uint h = 0x811c9dc5; return h; }",
            "basic_blocks": [
                {"id": 0, "start": "0x140003000", "stop": "0x140003040", "in_degree": 0, "out_degree": 0, "successors": []}
            ],
            "pcode_ops": [
                {"opcode": "INT_XOR", "address": "0x140003010", "inputs": ["h", "v"], "output": "h"},
                {"opcode": "INT_MULT", "address": "0x140003015", "inputs": ["h", "0x1000193"], "output": "h"},
                {"opcode": "RETURN", "address": "0x140003040", "inputs": ["h"]}
            ]
        }
    ]
}


class TestGhidraAdvancedIntegration(unittest.TestCase):

    def test_msvc_symbol_demangler(self):
        """Validates pure-Python demangling of MSVC mangled symbols."""
        # Member function with class scope, parameters, return type
        res1 = GhidraDeepAnalyzer.demangle_msvc_symbol("?ProcessPacket@NetworkManager@@QEAA_NPEBDH@Z")
        self.assertIn("NetworkManager::ProcessPacket", res1)
        self.assertTrue(res1.startswith("bool"))
        self.assertIn("char const*", res1)

        # Constructor
        res2 = GhidraDeepAnalyzer.demangle_msvc_symbol("??0CString@@QEAA@PEBD@Z")
        self.assertIn("CString::CString", res2)

        # Destructor
        res3 = GhidraDeepAnalyzer.demangle_msvc_symbol("??1CString@@QEAA@XZ")
        self.assertIn("CString::~CString", res3)

        # Non-mangled identifier
        res4 = GhidraDeepAnalyzer.demangle_msvc_symbol("compute_checksum_fast")
        self.assertEqual(res4, "compute_checksum_fast")

    def test_ghidra_export_store_search_in_memory(self):
        """Validates search_functions on in-memory Ghidra export."""
        store = GhidraExportStore(in_memory_dict=MOCK_GHIDRA_EXPORT)

        # 1. Search by name / demangled substring
        res_name = store.search_functions(query="ProcessPacket")
        self.assertEqual(res_name["total_matches"], 1)
        self.assertIn("ProcessPacket", res_name["matches"][0]["name"])

        # 2. Search by decompiled C substring
        res_c = store.search_functions(query="WSASocketA")
        self.assertEqual(res_c["total_matches"], 1)

        # 3. Search by opcode filter
        res_op = store.search_functions(opcode="CALLIND")
        self.assertEqual(res_op["total_matches"], 1)
        self.assertIn("CString", res_op["matches"][0]["name"])

        # 4. Search by xref target
        res_xref = store.search_functions(xref_target="s_EmptyString")
        self.assertEqual(res_xref["total_matches"], 1)

        # 5. Sensitive API filter
        res_sens = store.search_functions(sensitive_only=True)
        self.assertEqual(res_sens["total_matches"], 2)

    def test_ghidra_export_store_search_sqlite_parity(self):
        """Validates 100% search parity between in-memory and SQLite stores."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w", encoding="utf-8") as tf:
            json.dump(MOCK_GHIDRA_EXPORT, tf)
            json_path = tf.name

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as db_f:
            db_path = db_f.name

        try:
            from security import ExecutionGuard
            with ExecutionGuard.scoped_session(workspace_dir=os.path.dirname(db_path)):
                GhidraExportStore.ingest_to_sqlite(json_path, db_path)
            with GhidraExportStore.from_path(db_path) as store:
                res_op = store.search_functions(opcode="INT_XOR")
                self.assertEqual(res_op["total_matches"], 1)
                self.assertEqual(res_op["matches"][0]["name"], "compute_checksum_fast")

                res_query = store.search_functions(query="CString")
                self.assertEqual(res_query["total_matches"], 1)

                xrefs = store.search_xrefs("s_PacketHeader")
                self.assertEqual(len(xrefs), 1)
                self.assertIn("ProcessPacket", xrefs[0]["function"])
        finally:
            if os.path.exists(json_path):
                os.remove(json_path)
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_ghidra_inspect_function(self):
        """Validates deep architectural single-function inspection."""
        store = GhidraExportStore(in_memory_dict=MOCK_GHIDRA_EXPORT)
        dossier = store.inspect_function("?ProcessPacket@NetworkManager@@QEAA_NPEBDH@Z")
        self.assertIsNotNone(dossier)
        self.assertEqual(dossier["return_type"], "bool")
        self.assertEqual(dossier["parameter_count"], 2)
        self.assertEqual(dossier["local_variables_count"], 2)
        self.assertIn("WSASocketA", dossier["sensitive_apis_called"])
        self.assertTrue(dossier["has_decompiled_c"])
        self.assertIn("COMPARE", dossier["pcode_category_distribution"])
        self.assertEqual(dossier["cyclomatic_complexity"], 2)

    def test_ghidra_computational_profile(self):
        """Validates binary-wide computational and architectural profiling."""
        store = GhidraExportStore(in_memory_dict=MOCK_GHIDRA_EXPORT)
        prof = store.query_computational_profile()
        self.assertEqual(prof["status"], "ok")
        self.assertEqual(prof["total_functions"], 3)
        self.assertGreater(prof["total_pcode_ops"], 5)
        self.assertEqual(prof["sensitive_api_functions_count"], 2)
        self.assertIn("category_distribution", prof)
        self.assertIn("architectural_classification", prof)

    def test_mcp_bintra_ghidra_analyze_search_and_inspect(self):
        """Validates bintra_ghidra_analyze MCP handler routing for search, inspect, and profile."""
        from mcp_server import BintraMcpServer
        server = BintraMcpServer()

        # 1. Search action via MCP
        res_search = server.dispatch_tool("bintra_ghidra_analyze", {
            "payload": MOCK_GHIDRA_EXPORT,
            "opcode_filter": "CALLIND"
        })
        self.assertEqual(res_search["total_matches"], 1)

        # 2. Inspect action via MCP
        res_inspect = server.dispatch_tool("bintra_ghidra_analyze", {
            "payload": MOCK_GHIDRA_EXPORT,
            "function_name": "compute_checksum_fast"
        })
        self.assertEqual(res_inspect["name"], "compute_checksum_fast")
        self.assertEqual(res_inspect["return_type"], "uint")

        # 3. Profile action via MCP
        res_prof = server.dispatch_tool("bintra_ghidra_analyze", {
            "payload": MOCK_GHIDRA_EXPORT,
            "profile": True
        })
        self.assertEqual(res_prof["total_functions"], 3)

    def test_mcp_ghidra_security_perimeter_enforcement(self):
        """Validates ExecutionGuard enforcement on Ghidra MCP tools."""
        from mcp_server import BintraMcpServer
        server = BintraMcpServer()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w", encoding="utf-8") as tf:
            json.dump(MOCK_GHIDRA_EXPORT, tf)
            export_path = tf.name

        try:
            res = server.dispatch_tool("bintra_ghidra_call_graph", {"export_path": export_path})
            self.assertEqual(res["status"], "ok")

            res_df = server.dispatch_tool("bintra_ghidra_data_flow", {
                "export_path": export_path,
                "function_name": "compute_checksum_fast"
            })
            self.assertEqual(res_df["status"], "ok")
        finally:
            if os.path.exists(export_path):
                os.remove(export_path)

    @patch("subprocess.run")
    def test_mcp_ghidra_headless_timeout_and_isolation(self, mock_run):
        """Validates timeout resilience and project cleanup in bintra_ghidra_headless."""
        import subprocess
        from mcp_server import BintraMcpServer
        server = BintraMcpServer()

        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["analyzeHeadless"], timeout=30)

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            tf.write(b"MZ\x90\x00")
            dummy_bin = tf.name

        try:
            with patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": tempfile.gettempdir()}):
                support_dir = os.path.join(tempfile.gettempdir(), "support")
                os.makedirs(support_dir, exist_ok=True)
                bat_path = os.path.join(support_dir, "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
                with open(bat_path, "w") as f:
                    f.write("@echo off\n")

                try:
                    res = server.dispatch_tool("bintra_ghidra_headless", {
                        "binary_path": dummy_bin,
                        "timeout_seconds": 30,
                        "delete_project": True
                    })
                    self.assertTrue(res["is_timeout"])
                    self.assertEqual(res["exit_code"], 124)
                    self.assertTrue(res["project_cleaned"])
                finally:
                    if os.path.exists(bat_path):
                        os.remove(bat_path)
        finally:
            if os.path.exists(dummy_bin):
                os.remove(dummy_bin)


if __name__ == "__main__":
    unittest.main()
