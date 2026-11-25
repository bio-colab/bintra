# -*- coding: utf-8 -*-
"""
Tests for Bintra SOTA Architecture and Quality Enhancements:
- max_exports truncation for both dict and list structures
- Ghidra export provenance verification against target binary
- Evidence Graph epistemic confidence, verification levels, and sources
- Accurate stage status and overall status in BinaryTriageOrchestrator
- MCP protocol version negotiation and structuredContent contracts
- Subprocess pipe read error recording
- Digital signature signer_cert_expired validity check
"""

import json
import os
import shutil
import struct
import sys
import tempfile
import unittest
from unittest import mock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(REPO_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


class TestSotaAuditEnhancements(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="bintra_sota_enh_")
        self.ws_dir = os.path.join(self.tmp_dir, "workspace")
        os.makedirs(self.ws_dir, exist_ok=True)

        # Create a valid minimal PE file
        self.pe_path = os.path.join(self.ws_dir, "sample_target.exe")
        pe_bytes = bytearray(1024)
        pe_bytes[0:2] = b"MZ"
        struct.pack_into("<I", pe_bytes, 0x3C, 0x80)
        pe_bytes[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<HHIIIHH", pe_bytes, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
        struct.pack_into("<H", pe_bytes, 0x84 + 20, 0x20B)
        struct.pack_into("<I", pe_bytes, 0x84 + 20 + 108, 16)
        with open(self.pe_path, "wb") as f:
            f.write(pe_bytes)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_max_exports_truncation_dict_and_list(self):
        """Verify that max_exports properly truncates both dict {'functions': [...]} and list formats."""
        from analysis_orchestrator import BinaryTriageOrchestrator

        # 1. Test dict format (the real format returned by BinaryFormatInspector)
        mock_pe_dict = {
            "status": "ok",
            "format": "PE32+",
            "exports": {
                "exported_functions_count": 50,
                "functions": [f"ExportFunc_{i}" for i in range(50)],
            },
        }
        with mock.patch("binary_neural_engine.BinaryFormatInspector.inspect", return_value=mock_pe_dict):
            res = BinaryTriageOrchestrator.triage_binary(self.pe_path, max_exports=10, include_deobfuscation=False)
            exports_res = res["artifacts"]["binary_inspection"]["exports"]
            self.assertIsInstance(exports_res, dict)
            self.assertEqual(len(exports_res["functions"]), 10)
            self.assertTrue(exports_res.get("functions_truncated"))
            self.assertEqual(exports_res.get("truncated_from"), 50)
            self.assertTrue(res["artifacts"]["binary_inspection"].get("exports_truncated"))

        # 2. Test list format (fallback compatibility)
        mock_pe_list = {
            "status": "ok",
            "format": "PE32+",
            "exports": [f"ExportFunc_{i}" for i in range(50)],
        }
        with mock.patch("binary_neural_engine.BinaryFormatInspector.inspect", return_value=mock_pe_list):
            res2 = BinaryTriageOrchestrator.triage_binary(self.pe_path, max_exports=8, include_deobfuscation=False)
            exports_res2 = res2["artifacts"]["binary_inspection"]["exports"]
            self.assertIsInstance(exports_res2, list)
            self.assertEqual(len(exports_res2), 8)
            self.assertTrue(res2["artifacts"]["binary_inspection"].get("exports_truncated"))

    def test_ghidra_provenance_verification_hash_match(self):
        """Verify that Ghidra export with matching SHA-256 gets VERIFIED_CRYPTOGRAPHIC_HASH."""
        from analysis_orchestrator import BinaryTriageOrchestrator
        import hashlib

        with open(self.pe_path, "rb") as f:
            target_sha = hashlib.sha256(f.read()).hexdigest().lower()

        ghidra_json = os.path.join(self.ws_dir, "ghidra_matched.json")
        with open(ghidra_json, "w", encoding="utf-8") as f:
            json.dump({
                "program_name": "sample_target.exe",
                "sha256": target_sha,
                "functions": [{"name": "main", "entry_point": "0x140001000", "pcode_opcodes": ["CALL"]}]
            }, f)

        res = BinaryTriageOrchestrator.triage_binary(
            self.pe_path,
            ghidra_export_path=ghidra_json,
            include_deobfuscation=False,
        )
        gh_stage = res["stage_statuses"]["ghidra_analysis"]
        self.assertEqual(gh_stage["status"], "ok")
        self.assertEqual(gh_stage["provenance"]["status"], "VERIFIED_CRYPTOGRAPHIC_HASH")
        self.assertTrue(gh_stage["provenance"]["verified"])
        self.assertIn("Ghidra export provenance cryptographically verified: VERIFIED_CRYPTOGRAPHIC_HASH", res["summary"]["observed_facts"])

    def test_ghidra_provenance_verification_hash_mismatch(self):
        """Verify that Ghidra export with mismatched SHA-256 gets quarantined, failing stage status and alert."""
        from analysis_orchestrator import BinaryTriageOrchestrator

        ghidra_json = os.path.join(self.ws_dir, "ghidra_foreign.json")
        with open(ghidra_json, "w", encoding="utf-8") as f:
            json.dump({
                "program_name": "other_binary.exe",
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                "functions": [{"name": "evil_func", "entry_point": "0x1000", "pcode_opcodes": ["CALL"]}]
            }, f)

        res = BinaryTriageOrchestrator.triage_binary(
            self.pe_path,
            ghidra_export_path=ghidra_json,
            include_deobfuscation=False,
        )
        gh_stage = res["stage_statuses"]["ghidra_analysis"]
        self.assertEqual(gh_stage["status"], "provenance_mismatch")
        self.assertEqual(gh_stage["provenance"]["status"], "PROVENANCE_HASH_MISMATCH")
        self.assertFalse(gh_stage["provenance"]["verified"])
        self.assertIn("ghidra_analysis", res["failed_stages"])
        self.assertNotEqual(res["status"], "ok")
        self.assertIn("GHIDRA_PROVENANCE_MISMATCH_QUARANTINED:PROVENANCE_HASH_MISMATCH", res["summary"]["heuristic_indicators"])
        # Ensure foreign graph nodes were strictly quarantined
        nodes = {n["id"]: n for n in res["evidence_graph"].get("nodes", [])}
        self.assertNotIn("ghidra:call_graph", nodes)

    def test_adversarial_ghidra_name_match_is_heuristic_unverified(self):
        """Verify that filename matching without SHA-256 is labeled HEURISTIC_NAME_MATCH and unverified."""
        from analysis_orchestrator import BinaryTriageOrchestrator

        ghidra_json = os.path.join(self.ws_dir, "ghidra_name_only.json")
        with open(ghidra_json, "w", encoding="utf-8") as f:
            json.dump({
                "program_name": "sample_target.exe",  # Same name, but no sha256
                "functions": [{"name": "main", "entry_point": "0x140001000", "pcode_opcodes": ["CALL"]}]
            }, f)

        res = BinaryTriageOrchestrator.triage_binary(
            self.pe_path,
            ghidra_export_path=ghidra_json,
            include_deobfuscation=False,
        )
        gh_stage = res["stage_statuses"]["ghidra_analysis"]
        self.assertEqual(gh_stage["status"], "heuristic_unverified")
        self.assertEqual(gh_stage["provenance"]["status"], "HEURISTIC_NAME_MATCH")
        self.assertFalse(gh_stage["provenance"]["verified"])
        self.assertTrue(gh_stage["provenance"].get("is_heuristic"))
        self.assertIn("GHIDRA_EXPORT_MATCHED_BY_HEURISTIC_FILENAME_ONLY", res["summary"]["heuristic_indicators"])

    def test_causal_evidence_validation_co_occurrence_low_confidence(self):
        """Verify that unrelated data flow slice and crash telemetry produce CO_OCCURRENCE with low confidence."""
        from windows_intelligence.evidence_engine.graph_model import evaluate_data_flow_crash_causality

        unrelated_df = {
            "function": "LogMessage",
            "entry_point": "0x1000",
            "sinks": [{"address": "0x1020", "var": "ECX", "inputs": ["ESP"]}],
            "sources": [],
            "backward_slice": [],
        }
        crash_telemetry = {
            "fault_module": "game.exe",
            "fault_rva": "0x245F40",
            "fault_virtual_address": "0x645f40",
            "culprit_register": "EAX",
            "exception_code": "0xC0000005",
        }
        res = evaluate_data_flow_crash_causality(unrelated_df, crash_telemetry)
        self.assertEqual(res["level"], "CO_OCCURRENCE")
        self.assertEqual(res["relation"], "CO_OCCURS_IN_INCIDENT")
        self.assertEqual(res["relation_semantic"], "CO_OCCURRENCE")
        self.assertLessEqual(res["epistemic_confidence"], 0.30)

    def test_causal_evidence_validation_causally_validated_high_confidence(self):
        """Verify that exact instruction address and culprit register match produce CAUSALLY_VALIDATED with >=0.90."""
        from windows_intelligence.evidence_engine.graph_model import evaluate_data_flow_crash_causality

        matching_df = {
            "function": "RenderEntity",
            "entry_point": "0x245f00",
            "sinks": [{"address": "0x245f40", "var": "ECX", "inputs": ["EAX", "0x474"]}],
            "sources": [{"address": "0x245f37", "var": "EAX"}],
            "backward_slice": [],
            "provenance": {"verification_level": "VERIFIED_CRYPTOGRAPHIC_HASH", "source": "ghidra_bridge"},
        }
        crash_telemetry = {
            "fault_module": "game.exe",
            "fault_rva": "0x245f40",
            "fault_virtual_address": "0x645f40",
            "culprit_register": "EAX",
            "exception_code": "0xC0000005",
        }
        res = evaluate_data_flow_crash_causality(matching_df, crash_telemetry)
        self.assertEqual(res["level"], "CAUSALLY_VALIDATED")
        self.assertEqual(res["relation"], "EXPLAINS_DATA_PROVENANCE")
        self.assertEqual(res["relation_semantic"], "CAUSALLY_VALIDATED_FAULT_PATHWAY")
        self.assertGreaterEqual(res["epistemic_confidence"], 0.90)

    def test_evidence_graph_epistemic_metadata(self):
        """Verify that fused EvidenceGraph edges and nodes contain rich epistemic metadata."""
        from windows_intelligence.evidence_engine.graph_model import fuse_static_dynamic_ghidra

        pe_for = {"status": "ok", "pdata_functions": {"total_runtime_functions": 12}}
        sig_intel = {
            "status": "ok",
            "trust_status": "TRUSTED",
            "is_verified": True,
            "signature_type": "EMBEDDED_AUTHENTICODE",
            "is_whql_certified": True,
        }
        deobf = {
            "status": "ok",
            "control_flow_flattening": {"has_control_flow_flattening": True},
            "opaque_predicates_detected": 4,
        }
        crash = {
            "exception_code": "0xc0000005",
            "root_cause_classification": "NULL_POINTER_DEREFERENCE",
            "culprit_register": "RAX",
            "fault_address": "0x0",
            "confidence": "HIGH",
        }
        gh_cg = {
            "status": "ok",
            "functions_indexed": 40,
            "call_edges_count": 80,
            "indirect_calls_count": 5,
            "sensitive_api_reachability": ["VirtualAlloc"],
        }
        gh_df = {
            "status": "ok",
            "function": "target_fn",
            "sources_count": 2,
            "sinks_count": 1,
            "backward_slice": ["op1", "op2"],
        }

        res = fuse_static_dynamic_ghidra(
            pe_forensics=pe_for,
            crash_rca=crash,
            ghidra_call_graph=gh_cg,
            ghidra_data_flow=gh_df,
            signature_intel=sig_intel,
            deobfuscation=deobf,
        )
        self.assertEqual(res["status"], "ok")
        graph_dict = res["fused_graph"]

        # Check nodes have evidence_source and verification_level
        nodes = {n["id"]: n for n in graph_dict["nodes"]}
        self.assertIn("sig:TRUSTED", nodes)
        self.assertEqual(nodes["sig:TRUSTED"]["properties"]["verification_level"], "CRYPTOGRAPHIC_VALIDATION")
        self.assertIn("obf:signals", nodes)
        self.assertEqual(nodes["obf:signals"]["properties"]["verification_level"], "HEURISTIC_DISASSEMBLY_PATTERN")
        self.assertIn("crash:0xc0000005", nodes)
        self.assertEqual(nodes["crash:0xc0000005"]["properties"]["evidence_source"], "CRASH_ROOT_CAUSE_ANALYZER")

        # Check edges have epistemic metadata
        for edge in graph_dict["edges"]:
            meta = edge.get("metadata", {})
            self.assertIn("evidence_source", meta)
            self.assertIn("verification_level", meta)
            self.assertIn("relation_semantic", meta)
            self.assertIn("epistemic_confidence", meta)
            self.assertIn("confidence_rationale", meta)
            self.assertIsInstance(meta["epistemic_confidence"], float)

    def test_mcp_protocol_version_negotiation(self):
        """Verify that BintraMcpServer negotiates protocolVersion according to MCP standards."""
        from mcp_server import BintraMcpServer

        server = BintraMcpServer()

        # 1. Request latest published version 2026-07-28
        init_req_latest = {"protocolVersion": "2026-07-28", "capabilities": {}}
        resp_latest = server.handle_initialize(init_req_latest)
        self.assertEqual(resp_latest["protocolVersion"], "2026-07-28")
        self.assertIn("2026-07-28", resp_latest["supportedProtocolVersions"])
        self.assertEqual(resp_latest["serverInfo"]["version"], "1.1.0")

        # 2. Request legacy version 2024-11-05
        init_req_legacy = {"protocolVersion": "2024-11-05", "capabilities": {}}
        resp_legacy = server.handle_initialize(init_req_legacy)
        self.assertEqual(resp_legacy["protocolVersion"], "2024-11-05")

        # 3. Request unsupported future version is strictly rejected per MCP 2026-07-28 spec
        init_req_future = {"protocolVersion": "2029-01-01", "capabilities": {}}
        with self.assertRaises(ValueError) as ctx:
            server.handle_initialize(init_req_future)
        self.assertIn("Unsupported protocol version", str(ctx.exception))

        # Check rejection via JSON-RPC request interface returns error code -32022
        rpc_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2029-01-01"}
        }
        rpc_err = server._handle_single_request(rpc_req)
        self.assertEqual(rpc_err["error"]["code"], -32022)
        self.assertIn("supportedProtocolVersions", rpc_err["error"]["data"])
        self.assertEqual(rpc_err["error"]["data"]["requested"], "2029-01-01")
        self.assertIn("2026-07-28", rpc_err["error"]["data"]["supported"])

        # 4. Request without version defaults to standard
        resp_empty = server.handle_initialize({})
        self.assertEqual(resp_empty["protocolVersion"], "2024-11-05")

    def test_mcp_stateless_server_discover(self):
        """Verify that stateless server/discover returns capabilities and supported versions without initialize."""
        from mcp_server import BintraMcpServer

        server = BintraMcpServer()
        resp = server._handle_single_request({
            "jsonrpc": "2.0",
            "id": "disco-1",
            "method": "server/discover",
            "params": {}
        })
        self.assertIsNotNone(resp)
        self.assertEqual(resp["id"], "disco-1")
        res = resp["result"]
        self.assertEqual(res["name"], "bintra")
        self.assertEqual(res["protocolVersion"], "2026-07-28")
        self.assertIn("2026-07-28", res["supportedProtocolVersions"])
        self.assertIn("tools", res["capabilities"])

    def test_mcp_destructive_hint_accurate(self):
        """Verify that destructiveHint accurately classifies mutating vs read-only tools."""
        from mcp_server import BintraMcpServer

        # Pure inspection tool
        inspect_ann = BintraMcpServer._derive_tool_annotations("bintra_inspect_binary")
        self.assertTrue(inspect_ann["readOnlyHint"])
        self.assertFalse(inspect_ann["destructiveHint"])

        # Binary patch tool
        patch_ann = BintraMcpServer._derive_tool_annotations("bintra_patch_binary")
        self.assertFalse(patch_ann["readOnlyHint"])
        self.assertTrue(patch_ann["destructiveHint"])

    def test_mcp_structured_content_returned(self):
        """Verify that handle_tools_call returns both content and structuredContent."""
        from mcp_server import BintraMcpServer

        server = BintraMcpServer()
        resp = server.handle_tools_call({
            "name": "bintra_list_capabilities",
            "arguments": {"compact": True}
        })
        self.assertIn("content", resp)
        self.assertIn("structuredContent", resp)
        self.assertFalse(resp["isError"])
        self.assertIsInstance(resp["structuredContent"], dict)
        self.assertEqual(resp["structuredContent"]["status"], "ok")

    def test_subprocess_pipe_error_captured(self):
        """Verify that SafeSubprocessBroker records pipe errors instead of swallowing silently."""
        from security.safe_subprocess import SafeSubprocessBroker

        res = SafeSubprocessBroker.run_bounded_process(
            [sys.executable, "-c", "import sys; sys.stdout.write('hello'); sys.exit(0)"],
            timeout=5.0,
        )
        self.assertEqual(res["status"], "success")
        self.assertIn("pipe_read_error", res)
        self.assertIsNone(res["pipe_read_error"])

    def test_signature_signer_cert_expired_field(self):
        """Verify that WindowsSignatureIntelligence genuinely extracts expiration_status and timestamp_status."""
        from windows_intelligence.signature_intelligence import WindowsSignatureIntelligence

        sig_intel = WindowsSignatureIntelligence()
        res = sig_intel.verify_file(self.pe_path)
        self.assertIn("trust_status", res)
        self.assertIn("expiration_status", res)
        self.assertIn("timestamp_status", res)
        self.assertIn("is_driver", res)
        self.assertEqual(res["trust_status"], "UNSIGNED")
        self.assertEqual(res["expiration_status"], "UNKNOWN")

        # Test on a real system driver with Authenticode if available
        netwtw = r"C:\Windows\System32\drivers\Netwtw06.sys"
        if os.path.exists(netwtw):
            res_driver = sig_intel.verify_file(netwtw)
            self.assertIn("expiration_status", res_driver)
            self.assertIn("timestamp_status", res_driver)
            self.assertEqual(res_driver["timestamp_status"], "VALID_TRUSTED")
            self.assertEqual(res_driver["expiration_status"], "EXPIRED_WITH_VALID_TIMESTAMP")
            if res_driver.get("primary_signer"):
                self.assertIn("is_expired", res_driver["primary_signer"])
                self.assertIsInstance(res_driver["primary_signer"]["is_expired"], bool)

    def test_continuous_deobfuscator_analyze_file_polymorphism(self):
        """Verify that ContinuousDeobfuscator supports polymorphic analyze_file with status ok."""
        from binary_neural_engine import ContinuousDeobfuscator
        res = ContinuousDeobfuscator.analyze_file(self.pe_path, length=512)
        self.assertIsInstance(res, dict)
        self.assertEqual(res.get("status"), "ok")
        self.assertIn("opaque_predicates_detected", res)
        self.assertIn("control_flow_flattening", res)
        self.assertIn("analysis_file_offset", res)

    def test_windows_dependency_resolver_sxs_resolution(self):
        """Verify that WindowsDependencyResolver correctly resolves Side-by-Side (SxS) assemblies."""
        from windows_intelligence.dependency_resolver import WindowsDependencyResolver

        # Check SxS assembly map
        self.assertIn("comctl32.dll", WindowsDependencyResolver.SXS_ASSEMBLY_MAP)
        self.assertEqual(WindowsDependencyResolver.SXS_ASSEMBLY_MAP["comctl32.dll"], "microsoft.windows.common-controls")

        # Test manifest extraction and resolution on mspaint.exe if on Windows
        mspaint = r"C:\Windows\System32\mspaint.exe"
        if os.path.exists(mspaint):
            manifest = WindowsDependencyResolver.extract_manifest_text(mspaint)
            self.assertIn("Microsoft.Windows.Common-Controls", manifest)
            sxs_path = WindowsDependencyResolver.resolve_sxs_dll("comctl32.dll", mspaint, is_64bit=True, manifest_text=manifest)
            self.assertIsNotNone(sxs_path)
            self.assertTrue(os.path.isfile(sxs_path))
            self.assertIn("WinSxS", sxs_path)

            report = WindowsDependencyResolver.audit_dependencies(mspaint)
            self.assertEqual(report["verdict"], "HEALTHY")
            self.assertEqual(report["missing_exports_count"], 0)
            self.assertEqual(report["missing_dlls_count"], 0)
            self.assertGreaterEqual(report["sxs_assemblies_count"], 1)

    def test_cli_argument_parsing_resilience(self):
        """Verify that CLI subcommands (sig-verify, resolve-deps) flexibly handle both flags and positional arguments."""
        import subprocess

        # 1. sig-verify with --file flag
        mspaint = r"C:\Windows\System32\mspaint.exe"
        if os.path.exists(mspaint):
            res_flag = subprocess.run(
                [sys.executable, os.path.join(SRC_DIR, "cli.py"), "sig-verify", "--file", mspaint],
                capture_output=True,
                text=True, encoding="utf-8", errors="replace"
            )
            self.assertEqual(res_flag.returncode, 0)
            self.assertIn("WINDOWS_SIGNATURE_INTELLIGENCE", res_flag.stdout)

            # 2. sig-verify with positional argument
            res_pos = subprocess.run(
                [sys.executable, os.path.join(SRC_DIR, "cli.py"), "sig-verify", mspaint],
                capture_output=True,
                text=True, encoding="utf-8", errors="replace"
            )
            self.assertEqual(res_pos.returncode, 0)
            self.assertIn("WINDOWS_SIGNATURE_INTELLIGENCE", res_pos.stdout)

            # 3. resolve-deps with --file flag
            res_rd_flag = subprocess.run(
                [sys.executable, os.path.join(SRC_DIR, "cli.py"), "resolve-deps", "--file", mspaint],
                capture_output=True,
                text=True, encoding="utf-8", errors="replace"
            )
            self.assertEqual(res_rd_flag.returncode, 0)
            self.assertIn("STATIC_HEURISTIC_AUDIT", res_rd_flag.stdout)

    def test_unverified_provenance_caps_causality_at_correlated(self):
        """Verify that Ghidra export with heuristic/unverified provenance cannot claim CAUSALLY_VALIDATED."""
        from windows_intelligence.evidence_engine.graph_model import evaluate_data_flow_crash_causality

        matching_df = {
            "function": "ParseBuffer",
            "entry_point": "0x140001000",
            "sinks": [{"address": "0x140001050", "var": "RCX", "inputs": ["RAX", "0x8"]}],
            "sources": [{"address": "0x140001020", "var": "RAX"}],
            "backward_slice": [],
            "provenance": {"verification_level": "HEURISTIC_NAME_MATCH", "source": "ghidra_bridge"},
        }
        crash_telemetry = {
            "fault_module": "target.exe",
            "fault_rva": "0x1050",
            "fault_virtual_address": "0x140001050",
            "culprit_register": "RAX",
            "exception_code": "0xC0000005",
        }
        res = evaluate_data_flow_crash_causality(matching_df, crash_telemetry)
        self.assertEqual(res["level"], "CORRELATED")
        self.assertLessEqual(res["epistemic_confidence"], 0.50)
        self.assertTrue(any("capped at CORRELATED" in r for r in res.get("epistemic_reasons", [])))

    def test_exact_register_token_matching_prevents_substring_false_positive(self):
        """Verify that register token matching requires exact word boundaries (e.g. AX must not match TAX)."""
        from windows_intelligence.evidence_engine.graph_model import evaluate_data_flow_crash_causality

        # Sink has variable TAX, crash telemetry has culprit AX
        slice_tax = {
            "function": "CalculateRate",
            "entry_point": "0x1000",
            "sinks": [{"address": "0x1050", "var": "TAX", "inputs": ["RATE", "0x10"]}],
            "sources": [{"address": "0x1010", "var": "RATE"}],
            "backward_slice": [],
            "provenance": {"verification_level": "VERIFIED_CRYPTOGRAPHIC_HASH", "source": "ghidra_bridge"},
        }
        crash_ax = {
            "fault_module": "target.exe",
            "fault_rva": "0x1050",
            "fault_virtual_address": "0x1050",
            "culprit_register": "AX",
            "exception_code": "0xC0000005",
        }
        res = evaluate_data_flow_crash_causality(slice_tax, crash_ax)
        # Should NOT match register, so it falls back to INFERRED_PARTIAL or CORRELATED without register match
        self.assertFalse(res.get("register_matched", False))
        self.assertNotEqual(res["level"], "CAUSALLY_VALIDATED")

    def test_mcp_per_request_meta_version_rejection_code_32022(self):
        """Verify MCP 2026-07-28 per-request _meta protocol version check and code -32022."""
        from mcp_server import BintraMcpServer
        server = BintraMcpServer()

        # Valid initialize first
        server.handle_initialize({"protocolVersion": "2026-07-28"})

        # Per-request call with invalid protocolVersion in _meta
        bad_req = {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": "bintra_inspect_binary",
                "arguments": {"file_path": self.pe_path},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2099-01-01",
                    "io.modelcontextprotocol/clientCapabilities": {"experimental": True}
                }
            }
        }
        resp = server._handle_single_request(bad_req)
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32022)
        self.assertEqual(resp["error"]["data"]["requested"], "2099-01-01")
        self.assertIn("2026-07-28", resp["error"]["data"]["supported"])
        self.assertTrue(server.current_client_capabilities.get("experimental"))

    def test_cli_mediation_proc_profile_and_slack_audit(self):
        """Verify that CLI proc-profile and slack-audit invoke ExecutionGuard mediation."""
        from security import ExecutionGuard, Capability

        access_log = []
        orig_req = ExecutionGuard.request_access

        def mock_request(component, operation, target, capability, access_mode="READ", metadata=None, raise_on_deny=True):
            access_log.append((component, operation, target, capability, access_mode, metadata))
            return orig_req(component, operation, target, capability, access_mode=access_mode, metadata=metadata, raise_on_deny=raise_on_deny)

        with mock.patch.object(ExecutionGuard, "request_access", side_effect=mock_request):
            # Test slack-audit CLI mediation
            test_file = os.path.join(self.ws_dir, "test.txt")
            with open(test_file, "w") as f:
                f.write("test content")

            with mock.patch("sys.argv", ["cli.py", "slack-audit", test_file]):
                from cli import _dispatch_cli
                try:
                    _dispatch_cli()
                except SystemExit:
                    pass

            slack_calls = [c for c in access_log if c[3] == Capability.FILE_READ and c[4] == "READ"]
            self.assertGreaterEqual(len(slack_calls), 1)
            self.assertEqual(slack_calls[0][2], test_file)


if __name__ == "__main__":
    unittest.main()
