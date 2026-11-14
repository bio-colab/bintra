import json
import os
import shutil
import tempfile
import unittest
from ghidra_export_store import GhidraExportStore
from ghidra_pcode_vectorizer import GhidraDeepAnalyzer


class TestGhidraExportStore(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="bintra_test_store_")
        self.sample_export = {
            "program_name": "target_service.exe",
            "image_base": "0x140000000",
            "functions": [
                {
                    "name": "wmain",
                    "entry_point": "0x140001000",
                    "size": 256,
                    "parameter_count": 2,
                    "return_type": "int",
                    "callees": ["dispatch_worker", "init_logger"],
                    "xrefs": [{"from": "0x140000800", "to": "0x140001000", "type": "UNCONDITIONAL_CALL"}],
                    "pcode_ops": [],
                    "basic_blocks": [{"start": "0x140001000", "end": "0x140001100"}]
                },
                {
                    "name": "dispatch_worker",
                    "entry_point": "0x140001200",
                    "size": 512,
                    "parameter_count": 1,
                    "return_type": "void",
                    "callees": ["allocate_executable_buffer"],
                    "xrefs": [{"from": "0x140001050", "to": "0x140001200", "type": "UNCONDITIONAL_CALL"}],
                    "pcode_ops": [],
                    "basic_blocks": [{"start": "0x140001200", "end": "0x140001400"}]
                },
                {
                    "name": "allocate_executable_buffer",
                    "entry_point": "0x140002000",
                    "size": 128,
                    "parameter_count": 2,
                    "return_type": "void*",
                    "callees": ["VirtualAlloc"],
                    "xrefs": [{"from": "0x140001250", "to": "0x140002000", "type": "UNCONDITIONAL_CALL"}],
                    "pcode_ops": [
                        {"opcode": "COPY", "address": "0x140002004", "inputs": ["param_1"], "output": "v_size"},
                        {"opcode": "CALL", "address": "0x140002010", "inputs": ["v_size"], "output": "pMem", "target_name": "VirtualAlloc"}
                    ],
                    "basic_blocks": [{"start": "0x140002000", "end": "0x140002080"}],
                    "decompiled_c": "void* allocate_executable_buffer(size_t sz) { return VirtualAlloc(0, sz, 0x3000, 0x40); }"
                }
            ]
        }

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_in_memory_dict_compatibility(self):
        """Verifies that GhidraExportStore wraps existing in-memory dictionaries seamlessly."""
        store = GhidraExportStore.from_path(self.sample_export)
        self.assertFalse(store.is_sqlite)
        self.assertEqual(store.count_functions(), 3)
        fn = store.get_function("allocate_executable_buffer")
        self.assertIsNotNone(fn)
        self.assertEqual(fn["entry_point"], "0x140002000")

        # Call graph parity
        cg = store.build_call_graph_and_xrefs(target_function="wmain")
        self.assertEqual(cg["functions_indexed"], 3)
        self.assertGreaterEqual(len(cg["sensitive_api_reachability"]), 1)
        self.assertEqual(cg["sensitive_api_reachability"][0]["api"], "VirtualAlloc")

    def test_json_to_sqlite_ingestion_and_query_parity(self):
        """Verifies that JSON files ingested to SQLite yield 100% identical query results."""
        json_path = os.path.join(self.tmp_dir, "export.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self.sample_export, f)

        db_path = os.path.join(self.tmp_dir, "export.db")
        GhidraExportStore.ingest_to_sqlite(json_path, db_path, is_jsonl=False)
        self.assertTrue(os.path.exists(db_path))

        # Query direct SQLite store
        store = GhidraExportStore.from_path(db_path)
        self.assertTrue(store.is_sqlite)
        self.assertEqual(store.count_functions(), 3)

        # Single function lookup
        fn = store.get_function("allocate_executable_buffer")
        self.assertIsNotNone(fn)
        self.assertEqual(fn["name"], "allocate_executable_buffer")
        self.assertEqual(fn["size"], 128)

        # List functions with sensitive_only
        sens_fns = store.list_functions(sensitive_only=True)
        self.assertEqual(len(sens_fns), 1)
        self.assertEqual(sens_fns[0]["name"], "allocate_executable_buffer")

        # Full call graph
        cg = store.build_call_graph_and_xrefs(target_function="wmain", max_depth=4)
        self.assertEqual(cg["status"], "ok")
        self.assertEqual(cg["functions_indexed"], 3)
        self.assertGreaterEqual(len(cg["sensitive_api_reachability"]), 1)
        self.assertEqual(cg["sensitive_api_reachability"][0]["api"], "VirtualAlloc")
        self.assertIn("dispatch_worker", cg["sensitive_api_reachability"][0]["upstream_callers"])

        # Dict export parity
        exported_dict = store.to_dict()
        self.assertEqual(len(exported_dict["functions"]), 3)
        store.close()

    def test_jsonl_streaming_ingestion(self):
        """Verifies JSON Lines (.jsonl) streaming ingestion and retrieval."""
        jsonl_path = os.path.join(self.tmp_dir, "export.jsonl")
        with open(jsonl_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"program_name": "target_service.exe", "image_base": "0x140000000"}) + "\n")
            for fn in self.sample_export["functions"]:
                f.write(json.dumps(fn) + "\n")

        db_path = os.path.join(self.tmp_dir, "streamed.db")
        GhidraExportStore.ingest_to_sqlite(jsonl_path, db_path, is_jsonl=True)
        self.assertTrue(os.path.exists(db_path))

        store = GhidraExportStore.from_path(db_path)
        self.assertEqual(store.count_functions(), 3)
        fn_entry = store.get_function("0x140001200")
        self.assertIsNotNone(fn_entry)
        self.assertEqual(fn_entry["name"], "dispatch_worker")
        store.close()

    def test_mcp_ghidra_tools_dispatch_with_sqlite_and_jsonl(self):
        """Verifies bintra_ghidra_call_graph & bintra_ghidra_data_flow via MCP on .db and .json."""
        from mcp_server import BintraMcpServer

        # Prepare .json
        json_path = os.path.join(self.tmp_dir, "mcp_export.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self.sample_export, f)

        # Prepare .db
        db_path = os.path.join(self.tmp_dir, "mcp_export.db")
        GhidraExportStore.ingest_to_sqlite(json_path, db_path)

        srv = BintraMcpServer()

        # 1. Test Call Graph via .db
        res_db = srv.handle_tools_call({
            "name": "bintra_ghidra_call_graph",
            "arguments": {"export_path": db_path, "target_function": "wmain", "max_depth": 4}
        })
        self.assertFalse(res_db.get("isError", False))
        cg_data = json.loads(res_db["content"][0]["text"])
        self.assertEqual(cg_data["status"], "ok")
        self.assertEqual(cg_data["functions_indexed"], 3)
        self.assertEqual(cg_data["sensitive_api_reachability"][0]["api"], "VirtualAlloc")

        # 2. Test Data Flow via .db (instant single-function query)
        res_df_db = srv.handle_tools_call({
            "name": "bintra_ghidra_data_flow",
            "arguments": {"export_path": db_path, "function_name": "allocate_executable_buffer", "target_var": "pMem"}
        })
        self.assertFalse(res_df_db.get("isError", False))
        df_data = json.loads(res_df_db["content"][0]["text"])
        self.assertEqual(df_data["status"], "ok")
        self.assertEqual(df_data["function"], "allocate_executable_buffer")
        self.assertIn("VirtualAlloc", df_data["decompiler_summary"]["decompiled_c_preview"])

        # 3. Test Call Graph via legacy .json (backward-compatible)
        res_json = srv.handle_tools_call({
            "name": "bintra_ghidra_call_graph",
            "arguments": {"export_path": json_path, "target_function": "wmain"}
        })
        self.assertFalse(res_json.get("isError", False))
        cg_json_data = json.loads(res_json["content"][0]["text"])
        self.assertEqual(cg_json_data["functions_indexed"], 3)

    def test_ghidra_annotation_planner_with_store(self):
        """Verifies GhidraAnnotationPlanner works seamlessly on SQLite store and streamed exports."""
        from ghidra_pcode_vectorizer import GhidraAnnotationPlanner

        db_path = os.path.join(self.tmp_dir, "planner.db")
        json_path = os.path.join(self.tmp_dir, "planner.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self.sample_export, f)

        GhidraExportStore.ingest_to_sqlite(json_path, db_path)
        store = GhidraExportStore.from_path(db_path)

        plan = GhidraAnnotationPlanner.analyze_program_export(store)
        self.assertEqual(plan["program_name"], "target_service.exe")
        self.assertEqual(plan["analyzed_functions"], 1)
        self.assertIn("rename_actions", plan)
        self.assertIn("comment_actions", plan)
        store.close()


if __name__ == "__main__":
    unittest.main()
