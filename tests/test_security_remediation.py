# -*- coding: utf-8 -*-
"""
Tests for REA-Neural Complete Mediation & Security Architecture Remediation.
Verifies complete mediation across all 27 MCP tools, mandatory workspace confinement
at the core library engine layer, audit logger cross-process persistence and recovery,
and Windows intelligence safe query semantics.
"""

import unittest
import os
import sys
import tempfile
import json
import shutil
import pathlib

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from security import (
    ExecutionGuard,
    Capability,
    AuditLogger,
    AuditIntegrityError,
    AuditPersistenceError,
    SecurityViolationError,
    TargetMutationError,
    OutOfScopeError,
    PathIdentity
)
from binary_neural_engine import SurgicalBinaryPatcher
from rea_neural_engine import SafetensorsHandler
from mcp_server import ReaMcpServer


class TestSecurityRemediation(unittest.TestCase):
    """Rigorous verification of the 6 security & Windows intelligence remediation guarantees."""

    def test_complete_mediation_all_27_mcp_tools(self):
        """Guarantee 1: All 27 MCP tools are registered in security metadata and mediated fail-closed."""
        server = ReaMcpServer()
        tools_list = server.handle_tools_list({})["tools"]
        tool_names = [t["name"] for t in tools_list]
        self.assertEqual(len(tool_names), 27, f"Expected exactly 27 tools, found {len(tool_names)}")

        for t_name in tool_names:
            self.assertIn(t_name, server.TOOL_SECURITY_METADATA, f"Tool '{t_name}' missing from TOOL_SECURITY_METADATA")
            cap_val, mode, target_param = server.TOOL_SECURITY_METADATA[t_name]
            self.assertIn(cap_val, [c.value for c in Capability])
            self.assertIn(mode, ("READ", "WRITE", "MODIFY", "DELETE", "QUERY", "EXECUTE"))

        # Test unregistered tool rejection fails closed
        unregistered_call = {
            "name": "rea_malicious_unregistered_tool",
            "arguments": {"cmd": "whoami"}
        }
        res = server.handle_tools_call(unregistered_call)
        self.assertTrue(res.get("isError"))
        self.assertIn("UNREGISTERED_TOOL", res.get("content", [{}])[0].get("text", ""))

    def test_library_patch_file_blocks_write_outside_workspace(self):
        """Guarantee 2: SurgicalBinaryPatcher.patch_file strictly forbids unconfined writes outside workspace."""
        with tempfile.TemporaryDirectory() as tgt_dir, tempfile.TemporaryDirectory() as ws_dir, tempfile.TemporaryDirectory() as foreign_dir:
            pe_path = os.path.join(tgt_dir, "test.exe")
            with open(pe_path, "wb") as f:
                f.write(b"MZ" + b"\x00" * 512)

            foreign_out = os.path.join(foreign_dir, "escaped_output.exe")
            with ExecutionGuard.scoped_session(target_binary_path=pe_path, workspace_dir=ws_dir):
                with self.assertRaises(OutOfScopeError) as ctx:
                    SurgicalBinaryPatcher.patch_file(pe_path, foreign_out, 0x100, "90")
                self.assertIn("WRITE_OUTSIDE_WORKSPACE", str(ctx.exception))

    def test_library_write_patched_safetensors_blocks_write_outside_workspace(self):
        """Guarantee 3: SafetensorsHandler.write_patched_safetensors strictly forbids unconfined writes outside workspace."""
        with tempfile.TemporaryDirectory() as tgt_dir, tempfile.TemporaryDirectory() as ws_dir, tempfile.TemporaryDirectory() as foreign_dir:
            st_path = os.path.join(tgt_dir, "model.safetensors")
            with open(st_path, "wb") as f:
                hdr = json.dumps({"w": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}}).encode("utf-8")
                f.write((len(hdr)).to_bytes(8, "little"))
                f.write(hdr)
                f.write(b"\x00" * 16)

            foreign_out = os.path.join(foreign_dir, "escaped_weights.safetensors")
            with ExecutionGuard.scoped_session(target_binary_path=st_path, workspace_dir=ws_dir):
                with self.assertRaises(OutOfScopeError) as ctx:
                    SafetensorsHandler.write_patched_safetensors(st_path, foreign_out, {"w": None})
                self.assertIn("WRITE_OUTSIDE_WORKSPACE", str(ctx.exception))

    def test_audit_logger_cross_process_recovery_and_disk_tamper_detection(self):
        """Guarantee 4: AuditLogger persists records, recovers chain across process restarts, and detects disk tampering."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = os.path.join(tmp_dir, "audit.jsonl")

            # Process 1: Setup and log initial events
            AuditLogger.clear()
            AuditLogger.set_log_file(log_path)
            AuditLogger.set_strict_persistence(True)

            r1 = AuditLogger.log_decision(
                component="test_runner",
                operation="init_session",
                target="target.exe",
                decision="ALLOW",
                reason="authorized",
                requested_capability=Capability.FILE_READ.value
            )
            r2 = AuditLogger.log_decision(
                component="test_runner",
                operation="scan_header",
                target="target.exe",
                decision="ALLOW",
                reason="authorized",
                requested_capability=Capability.FILE_READ.value
            )

            self.assertEqual(len(AuditLogger.get_audit_trail()), 2)
            self.assertEqual(r2["sequence"], 1)

            # Process 2: Clear memory (simulate clean restart) and recover chain from disk
            AuditLogger.clear()
            self.assertEqual(len(AuditLogger.get_audit_trail()), 0)

            rec_info = AuditLogger.recover_chain_from_disk(log_path)
            self.assertTrue(rec_info["recovered"])
            self.assertEqual(rec_info["records_count"], 2)
            self.assertEqual(rec_info["head_hash"], r2["record_hash"])

            # Process 2: Append subsequent event seamlessly
            r3 = AuditLogger.log_decision(
                component="test_runner",
                operation="patch_file",
                target="workspace/out.exe",
                decision="ALLOW_SCOPED",
                reason="workspace write",
                requested_capability=Capability.WORKSPACE_WRITE.value
            )
            self.assertEqual(r3["sequence"], 2)
            self.assertEqual(r3["prev_hash"], r2["record_hash"])

            # Verify entire chain on disk is cryptographically valid
            val_res = AuditLogger.verify_audit_chain(log_path)
            self.assertTrue(val_res["is_valid"])
            self.assertEqual(val_res["records_verified"], 3)

            # Tamper test: Corrupt line 2 on disk
            with open(log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            corrupted_data = json.loads(lines[1])
            corrupted_data["target"] = "tampered_target.exe"
            lines[1] = json.dumps(corrupted_data) + "\n"
            with open(log_path, "w", encoding="utf-8") as f:
                f.writelines(lines)

            # Verify tamper detection
            tampered_res = AuditLogger.verify_audit_chain(log_path)
            self.assertFalse(tampered_res["is_valid"])
            self.assertIn("tamper detected", tampered_res["error"].lower())

            # Verify that recovery of tampered log fails closed
            AuditLogger.clear()
            with self.assertRaises(AuditIntegrityError):
                AuditLogger.recover_chain_from_disk(log_path)

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_file_usage_inspector_granularity_and_safe_access(self):
        """Guarantee 5: FileUsageInspector provides 4-way usage breakdown and queries via SafeProcessAccess."""
        from windows_intelligence.process_intelligence import FileUsageInspector

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"test file content")
            f_path = tf.name

        try:
            with ExecutionGuard.scoped_session(target_binary_path=f_path):
                report = FileUsageInspector.inspect_file_locks(f_path)
            self.assertEqual(report["status"], "success")
            self.assertIn("usage_breakdown", report)
            ub = report["usage_breakdown"]
            self.assertIn("is_actively_executing", ub)
            self.assertIn("is_loaded_as_dll", ub)
            self.assertIn("has_restart_manager_handle", ub)
            self.assertIn("has_exclusive_lock", ub)
            self.assertIn("usage_classifications", report)
            self.assertFalse(ub["has_exclusive_lock"])
        finally:
            if os.path.exists(f_path):
                os.remove(f_path)

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_driver_matcher_whql_disclaimer_and_mediation(self):
        """Guarantee 6: DriverMatcher mediates query access and explicitly disclaims cryptographic WHQL."""
        from windows_intelligence.device_intelligence import DriverMatcher

        with ExecutionGuard.scoped_session():
            res = DriverMatcher.audit_device_driver_bindings(max_devices=1)
        self.assertEqual(res["status"], "success")
        if res.get("device_reports"):
            rep = res["device_reports"][0]
            binding = rep.get("driver_binding", {})
            self.assertFalse(binding.get("is_cryptographically_verified_whql", True))
            self.assertIn("hardware_ids_match_evaluation", rep)
            self.assertIn("cryptographic catalog signature validation was not executed", binding.get("whql_verification_note", ""))


    def test_mcp_output_path_cannot_auto_derive_workspace(self):
        """GAP-2: MCP server cannot auto-derive workspace from output_path to escape confinement."""
        server = ReaMcpServer()
        with tempfile.TemporaryDirectory() as tgt_dir, tempfile.TemporaryDirectory() as ws_dir, tempfile.TemporaryDirectory() as foreign_dir:
            pe_path = os.path.join(tgt_dir, "victim.exe")
            with open(pe_path, "wb") as f:
                f.write(b"MZ" + b"\x00" * 512)
            foreign_out = os.path.join(foreign_dir, "mcp_escape.exe")

            # Call without explicit workspace_dir - output in foreign_dir must be REJECTED fail-closed
            res = server.handle_tools_call({
                "name": "rea_patch_binary",
                "arguments": {
                    "file_path": pe_path,
                    "output_path": foreign_out,
                    "offset": 0x10,
                    "patch_hex": "90 90"
                }
            })
            self.assertTrue(res.get("isError"))
            err_msg = res.get("content", [{}])[0].get("text", "")
            self.assertIn("WRITE_OUTSIDE_WORKSPACE", err_msg)
            self.assertFalse(os.path.exists(foreign_out))

    def test_target_directory_write_forbidden(self):
        """LIM-8: Writing patch directly into target's original directory returns TARGET_DIRECTORY_WRITE_FORBIDDEN."""
        with tempfile.TemporaryDirectory() as tgt_dir:
            pe_path = os.path.join(tgt_dir, "victim.exe")
            with open(pe_path, "wb") as f:
                f.write(b"MZ" + b"\x00" * 512)
            same_dir_out = os.path.join(tgt_dir, "patched_victim.exe")

            with ExecutionGuard.scoped_session(target_binary_path=pe_path, workspace_dir=tgt_dir):
                with self.assertRaises(TargetMutationError) as ctx:
                    SurgicalBinaryPatcher.patch_file(pe_path, same_dir_out, 0x10, "90")
                self.assertIn("TARGET_DIRECTORY_WRITE_FORBIDDEN", str(ctx.exception))

    def test_sycophancy_auditor_scale_adaptive_detection(self):
        """LIM-3: Scale-adaptive sycophancy decision fires on small-norm weight matrices."""
        from rea_neural_engine import AttentionPatternAuditor
        import numpy as np

        d = 64
        q_ans = np.zeros(d, dtype=np.float32)
        q_ans[0] = 0.5
        k_quest = np.zeros((5, d), dtype=np.float32)
        k_sugg = np.zeros((5, d), dtype=np.float32)
        # Small unnormalized projection matrix with suggestion preference
        qk = np.zeros((d, d), dtype=np.float32)
        qk[0, 1] = 2.0  # Suggestion preference
        k_sugg[:, 1] = 0.5

        res = AttentionPatternAuditor.audit_sycophancy_attention(qk, k_quest, k_sugg, q_ans)
        self.assertTrue(res["is_sycophantic_head"])
        self.assertIn("mean_question_logit", res)
        self.assertIn("logit_difference", res)

    def test_amenability_scale_recommendation(self):
        """LIM-5: Amenability diagnostic outputs recommended_num_columns and pathology_distribution."""
        from rea_neural_engine import AmenabilityDiagnostic
        import numpy as np

        # Concentrated attractor: a few dominant columns
        mat_conc = np.zeros((64, 64), dtype=np.float32)
        mat_conc[:, :4] = 10.0
        res_conc = AmenabilityDiagnostic.evaluate_surgical_amenability(mat_conc, observed_loop_rate=0.90)
        self.assertTrue(res_conc["is_amenable_to_weight_surgery"])
        self.assertEqual(res_conc["pathology_distribution"], "CONCENTRATED_COLUMN_BOTTLENECK")
        self.assertEqual(res_conc["recommended_num_columns"], 64)

        # Diffuse attractor: spread across all columns
        mat_diff = np.ones((64, 64), dtype=np.float32) * 2.0
        res_diff = AmenabilityDiagnostic.evaluate_surgical_amenability(mat_diff, observed_loop_rate=0.90)
        self.assertTrue(res_diff["is_amenable_to_weight_surgery"])
        self.assertEqual(res_diff["pathology_distribution"], "DIFFUSE_UNIFORM_ATTRACTOR")
        self.assertEqual(res_diff["recommended_num_columns"], 256)

    def test_semantic_matcher_rejects_branch_topology_divergence(self):
        """LIM-2: SemanticFunctionMatcher rejects false-positive matching between looping and branchless functions."""
        from binary_neural_engine import SemanticFunctionMatcher

        # Branchless function: return 42
        ret42_hex = "55 48 89 e5 b8 2a 00 00 00 5d c3"
        # Function with loop/jumps: loop counter
        loop_hex = "55 48 89 e5 31 c0 83 c0 01 83 f8 0a 75 f8 5d c3"

        res = SemanticFunctionMatcher.match_functions(ret42_hex, loop_hex)
        self.assertFalse(res["is_semantic_match"])
        self.assertFalse(res["branch_topology_congruent"])

    def test_self_update_check_command(self):
        """Verifies that 'rea-neural update --check' executes cleanly and verifies remote HEAD."""
        import subprocess
        res = subprocess.run([sys.executable, "-m", "cli", "update", "--check"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Checking remote repository for updates", res.stdout)
        self.assertIn("REA-Neural is already at the latest commit", res.stdout)


if __name__ == "__main__":
    unittest.main()
