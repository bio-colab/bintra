# -*- coding: utf-8 -*-
"""
NEON SOTA Evolution v2 regression tests.

Covers the 'Connect the Disconnected Cortex' evolution patch:
  1. Signature intelligence schema-contract normalization (timestamp/expiration).
  2. PcodeSimilarityIndex behavioral nearest-routine search (unlock of match_batch).
  3. GhidraExportStore.search_similar_functions (JSON + SQLite paths).
  4. Evidence graph fusion extension (sensory / embedded-AI / slack nodes).
  5. Triage orchestrator v2 (sensory + hybrid stages, markdown, skip flags).
  6. MCP: bintra_ghidra_similar_functions tool, tools/list pagination (2025-06-18),
     audit_neural_weights prompt, list_capabilities outputSchema.
  7. fuse_evidence Ghidra provenance quarantine parity.
  8. Shared GhidraHeadlessRunner (mocked analyzeHeadless execution).
  9. CLI ghidra-similar command (subprocess end-to-end).
 10. verify_ghidra_export_provenance unit contract.

All tests are cross-platform (Linux CI included): Windows/Ghidra specifics are
simulated with synthetic fixtures and mocks; nothing here requires a live host.
"""

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(REPO_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


def build_minimal_pe64(with_ai_marker: bool = False) -> bytes:
    """Synthetic PE32+ image with one executable section (cross-platform fixture)."""
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)
    file_hdr = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 34)
    opt_hdr = b"\x0b\x02" + b"\x00" * 222
    sec = b".text\x00\x00\x00" + struct.pack(
        "<IIIIIIHHI", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020
    )
    body = b"\x90" * 0x100
    if with_ai_marker:
        body += b"onnxruntime.dll\x00"
    body += b"\x00" * (0x200 - len(body))
    return dos + b"\x00" * (64 - len(dos)) + b"PE\x00\x00" + file_hdr + opt_hdr + sec + body


def sample_export(sha256: str = None, program_name: str = "target_service.exe") -> dict:
    return {
        "program_name": program_name,
        "sha256": sha256,
        "image_base": "0x140000000",
        "functions": [
            {
                "name": "fn_alpha",
                "entry_point": "0x140001000",
                "pcode_ops": [
                    {"opcode": "INT_ADD", "inputs": ["a", "b"], "output": "c"},
                    {"opcode": "INT_SUB", "inputs": ["c", "d"], "output": "e"},
                    {"opcode": "CBRANCH", "inputs": ["e", "f"]},
                ],
            },
            {
                "name": "fn_alpha_clone",
                "entry_point": "0x140002000",
                "pcode_ops": [
                    {"opcode": "INT_ADD", "inputs": ["x", "y"], "output": "z"},
                    {"opcode": "INT_SUB", "inputs": ["z", "w"], "output": "v"},
                    {"opcode": "CBRANCH", "inputs": ["v", "u"]},
                ],
            },
            {
                "name": "fn_memory_only",
                "entry_point": "0x140003000",
                "pcode_ops": [
                    {"opcode": "LOAD", "inputs": ["p"]},
                    {"opcode": "STORE", "inputs": ["q", "r"]},
                ],
            },
            {
                "name": "thunk_no_pcode",
                "entry_point": "0x140004000",
                "pcode_ops": [],
            },
        ],
    }


class TestSignatureIntelligenceContract(unittest.TestCase):
    """1. Every verification path must expose timestamp_status / expiration_status."""

    def setUp(self):
        from security import ExecutionGuard
        self.tmp_dir = tempfile.mkdtemp(prefix="bintra_sigcontract_")
        self._scope = ExecutionGuard.scoped_session(workspace_dir=self.tmp_dir)
        self._scope.__enter__()

    def tearDown(self):
        self._scope.__exit__(None, None, None)
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_unsigned_pe_carries_temporal_trust_fields(self):
        from windows_intelligence.signature_intelligence import WindowsSignatureIntelligence
        target = os.path.join(self.tmp_dir, "unsigned.exe")
        with open(target, "wb") as f:
            f.write(build_minimal_pe64())
        res = WindowsSignatureIntelligence.verify_file(target)
        self.assertIn("expiration_status", res, "expiration_status missing on unsigned path")
        self.assertIn("timestamp_status", res, "timestamp_status missing on unsigned path")
        self.assertEqual(res["expiration_status"], "UNKNOWN")
        self.assertEqual(res["timestamp_status"], "UNKNOWN")
        self.assertEqual(res["trust_status"], "UNSIGNED")

    def test_nonexistent_file_raises(self):
        from windows_intelligence.signature_intelligence import WindowsSignatureIntelligence
        with self.assertRaises(FileNotFoundError):
            WindowsSignatureIntelligence.verify_file(
                os.path.join(self.tmp_dir, "does_not_exist.exe")
            )


class TestPcodeSimilarityIndex(unittest.TestCase):
    """2. Nearest-routine search engine over High P-Code vectors."""

    def test_ranking_and_threshold(self):
        from ghidra_pcode_vectorizer import PcodeSimilarityIndex
        idx = PcodeSimilarityIndex()
        for fn in sample_export()["functions"]:
            idx.index_function(fn)
        self.assertEqual(idx.skipped_functions, 1, "thunk without pcode must be skipped")
        ref_ops = sample_export()["functions"][0]["pcode_ops"]
        res = idx.search(ref_ops, threshold=0.5)
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["indexed_functions"], 3)
        names = [m["function_name"] for m in res["matches"]]
        self.assertIn("fn_alpha", names)
        self.assertIn("fn_alpha_clone", names)
        self.assertNotIn("fn_memory_only", names, "behaviorally different routine must fall below threshold")
        sims = [m["pcode_cosine_similarity"] for m in res["matches"]]
        self.assertEqual(sims, sorted(sims, reverse=True), "matches must be ranked descending")

    def test_identical_ops_match_with_high_confidence(self):
        from ghidra_pcode_vectorizer import PcodeSimilarityIndex
        idx = PcodeSimilarityIndex()
        idx.index_function(sample_export()["functions"][0])
        res = idx.search(sample_export()["functions"][0]["pcode_ops"], threshold=0.9)
        self.assertEqual(res["matches_count"], 1)
        self.assertGreaterEqual(res["matches"][0]["pcode_cosine_similarity"], 0.99)
        self.assertTrue(res["matches"][0]["is_semantic_match"])
        self.assertEqual(res["matches"][0]["confidence"], "HIGH")

    def test_empty_reference_rejected(self):
        from ghidra_pcode_vectorizer import PcodeSimilarityIndex
        idx = PcodeSimilarityIndex()
        with self.assertRaises(ValueError):
            idx.search([])

    def test_empty_index_returns_structured_status(self):
        from ghidra_pcode_vectorizer import PcodeSimilarityIndex
        idx = PcodeSimilarityIndex()
        res = idx.search([{"opcode": "INT_ADD"}])
        self.assertEqual(res["status"], "empty_index")
        self.assertEqual(res["matches"], [])

    def test_limit_bounds_result_count(self):
        from ghidra_pcode_vectorizer import PcodeSimilarityIndex
        idx = PcodeSimilarityIndex()
        for fn in sample_export()["functions"]:
            idx.index_function(fn)
        res = idx.search(sample_export()["functions"][0]["pcode_ops"], threshold=-1.0, limit=2)
        self.assertLessEqual(len(res["matches"]), 2)


class TestStoreSimilarFunctions(unittest.TestCase):
    """3. GhidraExportStore.search_similar_functions across JSON and SQLite backends."""

    def setUp(self):
        from security import ExecutionGuard
        self.tmp_dir = tempfile.mkdtemp(prefix="bintra_simstore_")
        self._scope = ExecutionGuard.scoped_session(workspace_dir=self.tmp_dir)
        self._scope.__enter__()

    def tearDown(self):
        self._scope.__exit__(None, None, None)
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _write_export(self, suffix: str) -> str:
        path = os.path.join(self.tmp_dir, f"export{suffix}")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sample_export(), f)
        return path

    def test_json_backend_search(self):
        from ghidra_export_store import GhidraExportStore
        path = self._write_export(".json")
        with GhidraExportStore.from_path(path) as store:
            res = store.search_similar_functions(reference_function="fn_alpha", threshold=0.5)
            self.assertEqual(res["status"], "ok")
            self.assertEqual(res["reference"]["kind"], "export_function")
            self.assertEqual(res["reference"]["label"], "fn_alpha")
            names = [m["function_name"] for m in res["matches"]]
            self.assertIn("fn_alpha_clone", names)

    def test_sqlite_backend_search_parity(self):
        from ghidra_export_store import GhidraExportStore
        json_path = self._write_export("_src.json")
        db_path = os.path.join(self.tmp_dir, "export.db")
        GhidraExportStore.ingest_to_sqlite(json_path, db_path)
        with GhidraExportStore.from_path(db_path) as store:
            self.assertTrue(store.is_sqlite)
            res = store.search_similar_functions(reference_function="fn_alpha", threshold=0.5)
            names = [m["function_name"] for m in res["matches"]]
            self.assertIn("fn_alpha_clone", names)
            self.assertIn("fn_alpha", names)

    def test_external_pcode_reference(self):
        from ghidra_export_store import GhidraExportStore
        path = self._write_export(".json")
        with GhidraExportStore.from_path(path) as store:
            res = store.search_similar_functions(
                reference_pcode=sample_export()["functions"][1]["pcode_ops"], threshold=0.5
            )
            self.assertEqual(res["reference"]["kind"], "external_pcode")
            self.assertIn("fn_alpha", [m["function_name"] for m in res["matches"]])

    def test_unknown_reference_function(self):
        from ghidra_export_store import GhidraExportStore
        path = self._write_export(".json")
        with GhidraExportStore.from_path(path) as store:
            res = store.search_similar_functions(reference_function="missing_fn")
            self.assertEqual(res["status"], "not_found")

    def test_reference_without_pcode_reports_notice(self):
        from ghidra_export_store import GhidraExportStore
        path = self._write_export(".json")
        with GhidraExportStore.from_path(path) as store:
            res = store.search_similar_functions(reference_function="thunk_no_pcode")
            self.assertEqual(res["status"], "reference_without_pcode")

    def test_neither_reference_rejected(self):
        from ghidra_export_store import GhidraExportStore
        path = self._write_export(".json")
        with GhidraExportStore.from_path(path) as store:
            with self.assertRaises(ValueError):
                store.search_similar_functions()


class TestEvidenceGraphFusionExtension(unittest.TestCase):
    """4. fuse_static_dynamic_ghidra accepts sensory / embedded-AI / slack inputs."""

    def test_new_nodes_and_edges_added(self):
        from windows_intelligence.evidence_engine.graph_model import fuse_static_dynamic_ghidra
        fused = fuse_static_dynamic_ghidra(
            binary_inspection={"format": "PE", "file_name": "app.exe", "sha256": "ab" * 32},
            sensory_audit={
                "active_senses_count": 10,
                "overall_sensory_efficiency": 0.95,
                "senses": {f"sense_{i}": {"present": True} for i in range(10)},
            },
            embedded_ai_scan={
                "is_hybrid_binary": True,
                "findings": [{"kind": "ONNXRuntime_DLL", "description": "ONNX Runtime", "offset": 4096}],
            },
            slack_forensics={"has_trailing_slack": True, "slack_type": "PE_OVERLAY", "slack_bytes_count": 512},
        )
        nodes = {n["id"]: n for n in fused["fused_graph"]["nodes"]}
        self.assertIn("sensory:cortex", nodes)
        self.assertEqual(nodes["sensory:cortex"]["type"], "SENSORY_PERCEPTION")
        self.assertIn("ai:0:ONNXRuntime_DLL", nodes)
        self.assertEqual(nodes["ai:0:ONNXRuntime_DLL"]["type"], "EMBEDDED_AI_ASSET")
        self.assertIn("slack:trailing", nodes)
        edges = fused["fused_graph"]["edges"]
        relations = {e["relation"] for e in edges}
        self.assertIn("IS_PERCEIVED_BY", relations)
        self.assertIn("EMBEDS_NEURAL_ASSET", relations)
        self.assertIn("HAS_SLACK_SPACE", relations)

    def test_backward_compatibility_without_new_inputs(self):
        from windows_intelligence.evidence_engine.graph_model import fuse_static_dynamic_ghidra
        fused = fuse_static_dynamic_ghidra(
            binary_inspection={"format": "PE", "file_name": "app.exe", "sha256": "cd" * 32},
        )
        node_types = {n["type"] for n in fused["fused_graph"]["nodes"]}
        self.assertNotIn("SENSORY_PERCEPTION", node_types)
        self.assertNotIn("EMBEDDED_AI_ASSET", node_types)
        self.assertNotIn("SLACK_SPACE", node_types)
        self.assertEqual(fused["status"], "ok")

    def test_slack_node_absent_when_clean(self):
        from windows_intelligence.evidence_engine.graph_model import fuse_static_dynamic_ghidra
        fused = fuse_static_dynamic_ghidra(
            binary_inspection={"format": "PE", "file_name": "app.exe"},
            slack_forensics={"has_trailing_slack": False, "slack_bytes_count": 0},
        )
        node_ids = {n["id"] for n in fused["fused_graph"]["nodes"]}
        self.assertNotIn("slack:trailing", node_ids)


class TestTriageOrchestratorV2(unittest.TestCase):
    """5. Sensory Cortex + embedded-AI scan integrated into unified triage."""

    def setUp(self):
        from security import ExecutionGuard
        self.tmp_dir = tempfile.mkdtemp(prefix="bintra_triage2_")
        self._scope = ExecutionGuard.scoped_session(workspace_dir=self.tmp_dir)
        self._scope.__enter__()
        self.target = os.path.join(self.tmp_dir, "hybrid_app.exe")
        with open(self.target, "wb") as f:
            f.write(build_minimal_pe64(with_ai_marker=True))

    def tearDown(self):
        self._scope.__exit__(None, None, None)
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_sensory_and_hybrid_stages_present(self):
        from analysis_orchestrator import BinaryTriageOrchestrator
        res = BinaryTriageOrchestrator.triage_binary(
            file_path=self.target, include_deobfuscation=False
        )
        self.assertIn("sensory_perception", res["stage_statuses"])
        self.assertEqual(res["stage_statuses"]["sensory_perception"]["status"], "ok")
        self.assertGreaterEqual(res["stage_statuses"]["sensory_perception"]["active_senses_count"], 1)
        self.assertIn("embedded_ai_scan", res["stage_statuses"])
        self.assertEqual(res["stage_statuses"]["embedded_ai_scan"]["status"], "ok")
        self.assertTrue(res["stage_statuses"]["embedded_ai_scan"]["is_hybrid_binary"])
        # Artifacts + graph + summary wiring
        self.assertIn("sensory_perception", res["artifacts"])
        self.assertIn("embedded_ai_scan", res["artifacts"])
        graph_types = {n["type"] for n in res["evidence_graph"]["nodes"]}
        self.assertIn("SENSORY_PERCEPTION", graph_types)
        self.assertIn("EMBEDDED_AI_ASSET", graph_types)
        heuristics = res["summary"]["heuristic_indicators"]
        self.assertIn("EMBEDDED_NEURAL_INFERENCE_LOGIC_PRESENT", heuristics)
        recs = res["summary"]["recommended_next_steps"]
        self.assertIn("bintra_wsp_audit", recs)

    def test_skip_flags_disable_new_stages(self):
        from analysis_orchestrator import BinaryTriageOrchestrator
        res = BinaryTriageOrchestrator.triage_binary(
            file_path=self.target,
            include_deobfuscation=False,
            include_sensory=False,
            include_hybrid_scan=False,
        )
        self.assertEqual(res["stage_statuses"]["sensory_perception"]["status"], "skipped")
        self.assertEqual(res["stage_statuses"]["embedded_ai_scan"]["status"], "skipped")
        graph_types = {n["type"] for n in res["evidence_graph"]["nodes"]}
        self.assertNotIn("SENSORY_PERCEPTION", graph_types)
        self.assertNotIn("EMBEDDED_AI_ASSET", graph_types)

    def test_markdown_report_contains_new_sections(self):
        from analysis_orchestrator import BinaryTriageOrchestrator
        res = BinaryTriageOrchestrator.triage_binary(
            file_path=self.target, include_deobfuscation=False
        )
        md = BinaryTriageOrchestrator.generate_markdown_report(res)
        self.assertIn("Sensory Cortex Perception", md)
        self.assertIn("Embedded Neural Inference Assets", md)

    def test_provenance_verifier_contract(self):
        from analysis_orchestrator import BinaryTriageOrchestrator
        from ghidra_export_store import GhidraExportStore
        import hashlib
        with open(self.target, "rb") as f:
            target_sha = hashlib.sha256(f.read()).hexdigest()

        with GhidraExportStore.from_path(sample_export(sha256=target_sha)) as store:
            prov, crypto, heuristic = BinaryTriageOrchestrator.verify_ghidra_export_provenance(
                store, target_sha256=target_sha, target_filename="hybrid_app.exe"
            )
            self.assertTrue(crypto)
            self.assertFalse(heuristic)
            self.assertEqual(prov["status"], "VERIFIED_CRYPTOGRAPHIC_HASH")

        with GhidraExportStore.from_path(sample_export(sha256="0" * 64, program_name="hybrid_app.exe")) as store:
            prov, crypto, heuristic = BinaryTriageOrchestrator.verify_ghidra_export_provenance(
                store, target_sha256=target_sha, target_filename="hybrid_app.exe"
            )
            self.assertFalse(crypto)
            self.assertFalse(heuristic)
            self.assertEqual(prov["status"], "PROVENANCE_HASH_MISMATCH")

        with GhidraExportStore.from_path(sample_export(sha256=None, program_name="other.exe")) as store:
            prov, crypto, heuristic = BinaryTriageOrchestrator.verify_ghidra_export_provenance(
                store, target_sha256=target_sha, target_filename="hybrid_app.exe"
            )
            self.assertFalse(crypto)
            self.assertFalse(heuristic)
            self.assertEqual(prov["status"], "PROVENANCE_NAME_MISMATCH")

        with GhidraExportStore.from_path(sample_export(sha256=None, program_name="hybrid_app.exe")) as store:
            prov, crypto, heuristic = BinaryTriageOrchestrator.verify_ghidra_export_provenance(
                store, target_sha256=target_sha, target_filename="hybrid_app.exe"
            )
            self.assertFalse(crypto)
            self.assertTrue(heuristic)
            self.assertEqual(prov["status"], "HEURISTIC_NAME_MATCH")


class TestMcpServerEvolution(unittest.TestCase):
    """6. MCP tool/prompt/pagination/outputSchema surface."""

    @classmethod
    def setUpClass(cls):
        from security import ExecutionGuard
        cls.tmp_dir = tempfile.mkdtemp(prefix="bintra_mcp_evo_")
        cls._scope = ExecutionGuard.scoped_session(workspace_dir=cls.tmp_dir)
        cls._scope.__enter__()
        from mcp_server import BintraMcpServer, TOOLS_REGISTRY
        cls.srv = BintraMcpServer(workspace_root=cls.tmp_dir)
        cls.export_path = os.path.join(cls.tmp_dir, "export.json")
        with open(cls.export_path, "w", encoding="utf-8") as f:
            json.dump(sample_export(), f)

    @classmethod
    def tearDownClass(cls):
        cls._scope.__exit__(None, None, None)
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def test_registry_contains_new_tool_and_count(self):
        from mcp_server import TOOLS_REGISTRY, BintraMcpServer
        names = {t["name"] for t in TOOLS_REGISTRY}
        self.assertIn("bintra_ghidra_similar_functions", names)
        self.assertEqual(len(TOOLS_REGISTRY), 51)
        self.assertIn("bintra_ghidra_similar_functions", BintraMcpServer.TOOL_SECURITY_METADATA)

    def test_new_tool_dispatch(self):
        resp = self.srv.handle_tools_call({
            "name": "bintra_ghidra_similar_functions",
            "arguments": {"export_path": self.export_path, "reference_function": "fn_alpha", "threshold": 0.5},
        })
        self.assertFalse(resp["isError"])
        data = json.loads(resp["content"][0]["text"])
        self.assertEqual(data["status"], "ok")
        self.assertIn("fn_alpha_clone", [m["function_name"] for m in data["matches"]])
        self.assertIn("structuredContent", resp)

    def test_new_tool_rejects_unknown_parameter(self):
        resp = self.srv.handle_tools_call({
            "name": "bintra_ghidra_similar_functions",
            "arguments": {"export_path": self.export_path, "reference_function": "fn_alpha", "bogus": 1},
        })
        self.assertTrue(resp["isError"])
        self.assertIn("Unknown parameter", json.loads(resp["content"][0]["text"])["error"])

    def test_new_tool_requires_reference(self):
        resp = self.srv.handle_tools_call({
            "name": "bintra_ghidra_similar_functions",
            "arguments": {"export_path": self.export_path},
        })
        self.assertTrue(resp["isError"])

    def test_new_tool_annotations_read_only(self):
        ann = self.srv._derive_tool_annotations("bintra_ghidra_similar_functions")
        self.assertTrue(ann["readOnlyHint"])
        self.assertFalse(ann["destructiveHint"])
        self.assertTrue(ann["idempotentHint"])

    def test_capabilities_listing_includes_new_tool(self):
        resp = self.srv.handle_tools_call({
            "name": "bintra_list_capabilities",
            "arguments": {"platform_filter": "ghidra_required"},
        })
        data = json.loads(resp["content"][0]["text"])
        self.assertIn(
            "bintra_ghidra_similar_functions",
            [t["name"] for t in data["tools"]],
        )

    def test_ghidra_profile_includes_new_tool(self):
        listing = self.srv.handle_tools_list({"profile": "ghidra"})
        names = {t["name"] for t in listing["tools"]}
        self.assertIn("bintra_ghidra_similar_functions", names)

    def test_tools_list_pagination(self):
        page1 = self.srv.handle_tools_list({"cursor": "0"})
        self.assertEqual(len(page1["tools"]), self.srv.TOOLS_LIST_PAGE_SIZE)
        self.assertIn("nextCursor", page1)
        page2 = self.srv.handle_tools_list({"cursor": page1["nextCursor"]})
        page3 = self.srv.handle_tools_list({"cursor": page2["nextCursor"]})
        total = len(page1["tools"]) + len(page2["tools"]) + len(page3["tools"])
        from mcp_server import TOOLS_REGISTRY
        self.assertEqual(total, len(TOOLS_REGISTRY))
        self.assertNotIn("nextCursor", page3, "last page must not advertise a next cursor")
        # No dedup/loss: first tool of page1 == first registry tool
        self.assertEqual(page1["tools"][0]["name"], TOOLS_REGISTRY[0]["name"])

    def test_tools_list_without_cursor_returns_everything(self):
        full = self.srv.handle_tools_list({})
        from mcp_server import TOOLS_REGISTRY
        self.assertEqual(len(full["tools"]), len(TOOLS_REGISTRY))
        self.assertNotIn("nextCursor", full)

    def test_tools_list_invalid_cursor_rejected(self):
        with self.assertRaises(ValueError):
            self.srv.handle_tools_list({"cursor": "not-a-number"})
        with self.assertRaises(ValueError):
            self.srv.handle_tools_list({"cursor": "99999"})

    def test_neural_weights_prompt(self):
        prompts = self.srv.handle_prompts_list({})
        names = {p["name"] for p in prompts["prompts"]}
        self.assertIn("audit_neural_weights", names)
        got = self.srv.handle_prompts_get({
            "name": "audit_neural_weights",
            "arguments": {"target_path": "hybrid_app.exe"},
        })
        text = got["messages"][0]["content"]["text"]
        self.assertIn("bintra_scan_hybrid", text)
        self.assertIn("bintra_wsp_audit", text)
        with self.assertRaises(ValueError):
            self.srv.handle_prompts_get({"name": "audit_neural_weights", "arguments": {}})

    def test_list_capabilities_output_schema_declared_and_conforming(self):
        listing = self.srv.handle_tools_list({})
        caps_tool = next(t for t in listing["tools"] if t["name"] == "bintra_list_capabilities")
        self.assertIn("outputSchema", caps_tool, "list_capabilities must declare outputSchema (MCP 2025-06-18)")
        schema = caps_tool["outputSchema"]
        self.assertEqual(schema["type"], "object")
        self.assertIn("tools", schema["required"])

        resp = self.srv.handle_tools_call({
            "name": "bintra_list_capabilities",
            "arguments": {"platform_filter": "all"},
        })
        data = resp["structuredContent"]
        # Manual conformance check (no external jsonschema dependency)
        self.assertEqual(data["status"], "ok")
        self.assertIsInstance(data["host_os"], str)
        self.assertIsInstance(data["total_tools"], int)
        self.assertIsInstance(data["tools"], list)
        for entry in data["tools"]:
            for req in ("name", "environment", "capability", "access_mode"):
                self.assertIn(req, entry)
            self.assertIn(entry["environment"], ("cross_platform", "windows_native", "ghidra_required"))

    def test_triage_tool_accepts_new_flags(self):
        target = os.path.join(self.tmp_dir, "t.exe")
        with open(target, "wb") as f:
            f.write(build_minimal_pe64())
        resp = self.srv.handle_tools_call({
            "name": "bintra_triage_binary",
            "arguments": {
                "file_path": target,
                "include_deobfuscation": False,
                "include_sensory": False,
                "include_hybrid_scan": False,
            },
        })
        data = json.loads(resp["content"][0]["text"])
        self.assertEqual(data["stage_statuses"]["sensory_perception"]["status"], "skipped")
        self.assertEqual(data["stage_statuses"]["embedded_ai_scan"]["status"], "skipped")


class TestFuseEvidenceProvenanceParity(unittest.TestCase):
    """7. bintra_fuse_evidence quarantines provenance-mismatched Ghidra exports."""

    def setUp(self):
        from security import ExecutionGuard
        self.tmp_dir = tempfile.mkdtemp(prefix="bintra_fuse_prov_")
        self._scope = ExecutionGuard.scoped_session(workspace_dir=self.tmp_dir)
        self._scope.__enter__()
        self.target = os.path.join(self.tmp_dir, "target_hybrid.exe")
        with open(self.target, "wb") as f:
            f.write(build_minimal_pe64())

    def tearDown(self):
        self._scope.__exit__(None, None, None)
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_hash_mismatch_is_quarantined(self):
        from mcp_server import BintraMcpServer
        srv = BintraMcpServer(workspace_root=self.tmp_dir)
        export_path = os.path.join(self.tmp_dir, "mismatch.json")
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(sample_export(sha256="f" * 64, program_name="target_hybrid.exe"), f)
        resp = srv.handle_tools_call({
            "name": "bintra_fuse_evidence",
            "arguments": {"binary_path": self.target, "ghidra_export_path": export_path},
        })
        data = json.loads(resp["content"][0]["text"])
        self.assertEqual(data["status"], "provenance_mismatch")
        self.assertEqual(data["ghidra_provenance"]["status"], "PROVENANCE_HASH_MISMATCH")
        self.assertNotIn("fused_graph", data, "quarantined export must not be fused")

    def test_heuristic_name_match_still_fuses(self):
        from mcp_server import BintraMcpServer
        srv = BintraMcpServer(workspace_root=self.tmp_dir)
        export_path = os.path.join(self.tmp_dir, "name_match.json")
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(sample_export(sha256=None, program_name="target_hybrid.exe"), f)
        resp = srv.handle_tools_call({
            "name": "bintra_fuse_evidence",
            "arguments": {"binary_path": self.target, "ghidra_export_path": export_path},
        })
        data = json.loads(resp["content"][0]["text"])
        self.assertEqual(data["status"], "ok")
        self.assertIn("fused_graph", data)


class TestGhidraHeadlessRunner(unittest.TestCase):
    """8. Shared analyzeHeadless runner (mocked execution; no Ghidra required)."""

    def setUp(self):
        from security import ExecutionGuard
        self.tmp_dir = tempfile.mkdtemp(prefix="bintra_runner_")
        self._scope = ExecutionGuard.scoped_session(workspace_dir=self.tmp_dir)
        self._scope.__enter__()
        self.target = os.path.join(self.tmp_dir, "target.exe")
        with open(self.target, "wb") as f:
            f.write(build_minimal_pe64())
        self.fake_headless = os.path.join(self.tmp_dir, "ghidra", "support")
        os.makedirs(self.fake_headless, exist_ok=True)

    def tearDown(self):
        self._scope.__exit__(None, None, None)
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _fake_binary(self, script_body: str, win_body: str = None):
        if os.name == "nt":
            launcher = os.path.join(self.fake_headless, "analyzeHeadless.bat")
            body = win_body if win_body is not None else script_body
        else:
            launcher = os.path.join(self.fake_headless, "analyzeHeadless")
            body = script_body
        with open(launcher, "w", encoding="utf-8") as f:
            f.write(body)
        if os.name != "nt":
            os.chmod(launcher, 0o755)
        return launcher

    def test_metrics_parsing_and_cleanup(self):
        from ghidra_headless_runner import GhidraHeadlessRunner
        win_script = (
            "@echo off\n"
            "echo Extracted High P-Code ^& Full CFG for 42/42 functions\n"
            "echo Proven Invariant Tautologies: 7\n"
            "echo Control Flow Flattening backbones: 3\n"
        )
        launcher = self._fake_binary(
            "#!/bin/sh\necho 'Extracted High P-Code & Full CFG for 42/42 functions'\n"
            "echo 'Proven Invariant Tautologies: 7'\n"
            "echo 'Control Flow Flattening backbones: 3'\n",
            win_body=win_script,
        )
        res = GhidraHeadlessRunner.run(
            binary_path=self.target,
            ghidra_path=os.path.dirname(os.path.dirname(launcher)),
            timeout_sec=30,
        )
        self.assertEqual(res["exit_code"], 0)
        self.assertFalse(res["is_error"])
        self.assertEqual(res["analyzed_functions_count"], 42)
        self.assertEqual(res["opaque_predicates_detected"], 7)
        self.assertEqual(res["cff_backbones_detected"], 3)
        self.assertTrue(res["project_cleaned"])
        self.assertEqual(res["epistemic_classification"], "GHIDRA_HEADLESS_BATCH_EXECUTION")

    def test_script_error_marker_flips_is_error(self):
        from ghidra_headless_runner import GhidraHeadlessRunner
        win_script = "@echo off\necho SCRIPT ERROR: boom\nexit /b 1\n"
        launcher = self._fake_binary(
            "#!/bin/sh\necho 'SCRIPT ERROR: boom'\n",
            win_body=win_script,
        )
        res = GhidraHeadlessRunner.run(
            binary_path=self.target,
            ghidra_path=os.path.dirname(os.path.dirname(launcher)),
        )
        self.assertTrue(res["script_error_detected"])
        self.assertEqual(res["exit_code"], 1)
        self.assertTrue(res["is_error"])

    def test_timeout_handled_as_124(self):
        import subprocess as sp
        from ghidra_headless_runner import GhidraHeadlessRunner
        win_script = "@echo off\nping -n 6 127.0.0.1 >nul\n"
        launcher = self._fake_binary(
            "#!/bin/sh\nsleep 5\n",
            win_body=win_script,
        )
        res = GhidraHeadlessRunner.run(
            binary_path=self.target,
            ghidra_path=os.path.dirname(os.path.dirname(launcher)),
            timeout_sec=1,
        )
        self.assertTrue(res["is_timeout"])
        self.assertEqual(res["raw_returncode"], 124)
        self.assertTrue(res["is_error"])

    def test_discovery_failure_raises(self):
        from ghidra_headless_runner import GhidraHeadlessRunner
        with mock.patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": ""}, clear=False):
            with mock.patch("ghidra_headless_runner.Path.home", return_value=__import__("pathlib").Path(self.tmp_dir)):
                with self.assertRaises(FileNotFoundError):
                    GhidraHeadlessRunner.run(
                        binary_path=self.target,
                        ghidra_path=os.path.join(self.tmp_dir, "nonexistent_ghidra"),
                    )

    def test_parse_bridge_metrics_unit(self):
        from ghidra_headless_runner import GhidraHeadlessRunner
        metrics = GhidraHeadlessRunner.parse_bridge_metrics(
            "Extracted High P-Code & Full CFG for 12/12 functions\n"
            "Proven Invariant Tautologies: 4\n"
            "Control Flow Flattening: 2\n"
            "unrelated noise\n"
        )
        self.assertEqual(metrics["analyzed_functions_count"], 12)
        self.assertEqual(metrics["opaque_predicates_detected"], 4)
        self.assertEqual(metrics["cff_backbones_detected"], 2)


class TestCliGhidraSimilarCommand(unittest.TestCase):
    """9. `python -m cli ghidra-similar` end-to-end on a synthetic export."""

    def test_json_and_markdown_output(self):
        tmp_dir = tempfile.mkdtemp(prefix="bintra_cli_sim_")
        try:
            export_path = os.path.join(tmp_dir, "export.json")
            with open(export_path, "w", encoding="utf-8") as f:
                json.dump(sample_export(), f)
            pcode_ref = os.path.join(tmp_dir, "ref.json")
            with open(pcode_ref, "w", encoding="utf-8") as f:
                json.dump({"pcode_ops": sample_export()["functions"][1]["pcode_ops"]}, f)

            env = dict(os.environ)
            env["HOME"] = tmp_dir
            env["USERPROFILE"] = tmp_dir
            cli_entry = os.path.join(SRC_DIR, "cli.py")
            res_json = subprocess.run(
                [sys.executable, cli_entry, "ghidra-similar", "--input", export_path,
                 "--function", "fn_alpha", "--threshold", "0.5"],
                cwd=REPO_ROOT, capture_output=True, text=True, env=env, timeout=120,
            )
            self.assertEqual(res_json.returncode, 0, res_json.stderr[-500:])
            payload = json.loads(res_json.stdout)
            self.assertEqual(payload["status"], "ok")
            self.assertIn("fn_alpha_clone", [m["function_name"] for m in payload["matches"]])

            res_md = subprocess.run(
                [sys.executable, cli_entry, "ghidra-similar", "--input", export_path,
                 "--pcode-file", pcode_ref, "--threshold", "0.5", "--format", "md"],
                cwd=REPO_ROOT, capture_output=True, text=True, env=env, timeout=120,
            )
            self.assertEqual(res_md.returncode, 0, res_md.stderr[-500:])
            self.assertIn("fn_alpha", res_md.stdout)
            self.assertIn("| Rank |", res_md.stdout)

            res_missing_ref = subprocess.run(
                [sys.executable, cli_entry, "ghidra-similar", "--input", export_path],
                cwd=REPO_ROOT, capture_output=True, text=True, env=env, timeout=120,
            )
            self.assertNotEqual(res_missing_ref.returncode, 0)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
