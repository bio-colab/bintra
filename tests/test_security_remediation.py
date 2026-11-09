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


if __name__ == "__main__":
    unittest.main()
