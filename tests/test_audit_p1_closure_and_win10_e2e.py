# -*- coding: utf-8 -*-
"""
Targeted regression tests closing P1 security gaps & verifying live Windows 10 analysis
with cryptographic pre/post target-immutability proof:
1. SafeSubprocessBroker.run_bounded_process rejects unmediated arbitrary argv execution.
2. MCP side-effect tool classifications (bintra_registry_audit, bintra_ghidra_live_bridge,
   bintra_etw_capture) + central tamper gate inside ExecutionGuard / PolicyEngine.
3. CLI direct write closure (bintra triage --output / synthesize-weights --output).
4. Optional external HMAC trust anchors for AuditLogger and Ghidra provenance.
5. Real Windows 10 integration on native system binaries proving zero byte mutation.
"""

import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock as mock

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from mcp_server import BintraMcpServer  # noqa: E402
from security import (  # noqa: E402
    AccessRequest,
    AuditIntegrityError,
    AuditLogger,
    Capability,
    ExecutionGuard,
    PolicyEngine,
    SafeSubprocessBroker,
    SecurityViolationError,
    TargetScope,
)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(65536):
            h.update(chunk)
    return h.hexdigest()


class TestP1SecurityClosureAndTamperGates(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.target_dir = os.path.join(self.root, "targets")
        self.ws_dir = os.path.join(self.root, "ws")
        self.foreign_dir = os.path.join(self.root, "foreign")
        self.log_dir = os.path.join(self.root, "logs")
        for d in (self.target_dir, self.ws_dir, self.foreign_dir, self.log_dir):
            os.makedirs(d, exist_ok=True)

        self.target_pe = os.path.join(self.target_dir, "victim.exe")
        with open(self.target_pe, "wb") as fh:
            fh.write(b"MZ" + b"\x90" * 510)

        self._prev_scope = ExecutionGuard.get_current_scope()
        self._prev_log_dir = AuditLogger._log_dir
        self._prev_log_file = AuditLogger._log_file
        self._prev_strict = AuditLogger.get_strict_persistence()
        self._prev_known = AuditLogger._known_disk_state
        self.log_file = os.path.join(self.log_dir, "audit.jsonl")
        AuditLogger.clear()
        AuditLogger.set_log_file(self.log_file)
        AuditLogger.set_strict_persistence(False)

    def tearDown(self) -> None:
        ExecutionGuard.set_current_scope(self._prev_scope)
        AuditLogger.set_strict_persistence(self._prev_strict)
        AuditLogger._log_dir = self._prev_log_dir
        AuditLogger._log_file = self._prev_log_file
        AuditLogger._known_disk_state = self._prev_known
        AuditLogger.clear()
        self._tmp.cleanup()

    def test_unmediated_run_bounded_process_blocked_and_audited(self) -> None:
        denials_before = len(AuditLogger.get_denials())
        with self.assertRaises(SecurityViolationError):
            SafeSubprocessBroker.run_bounded_process([sys.executable, "-c", "print('pwned')"], timeout=5.0)
        denials_after = AuditLogger.get_denials()
        self.assertGreater(len(denials_after), denials_before)
        self.assertIn("run_bounded_process", denials_after[-1]["operation"])

    def test_mcp_side_effect_annotations_and_tamper_gate_enforcement(self) -> None:
        srv = BintraMcpServer(workspace_root=self.ws_dir)
        tools_by_name = {t["name"]: t for t in srv.handle_tools_list({})["tools"]}

        for side_effect_tool in ("bintra_registry_audit", "bintra_ghidra_live_bridge", "bintra_etw_capture"):
            ann = tools_by_name[side_effect_tool]["annotations"]
            self.assertFalse(ann["readOnlyHint"], f"{side_effect_tool} must not be marked readOnlyHint=True")
            self.assertFalse(ann["destructiveHint"], f"{side_effect_tool} destructiveHint mismatch")

        self.assertEqual(srv.TOOL_SECURITY_METADATA["bintra_etw_capture"][1], "EXECUTE")
        self.assertEqual(srv.TOOL_SECURITY_METADATA["bintra_ghidra_live_bridge"][1], "EXECUTE")

        # Simulate audit tampering detected in-session
        AuditLogger.mark_tampered("simulated on-disk hash break")

        # 1. PolicyEngine / ExecutionGuard centrally refuse mutating & execution calls
        scope = TargetScope(target_binary_path=self.target_pe, workspace_dir=self.ws_dir)
        for req in (
            AccessRequest("safe_file_access", "write_test", os.path.join(self.ws_dir, "a.txt"), Capability.WORKSPACE_WRITE, "WRITE"),
            AccessRequest("cmd_executor", "execute_command", "os_ver", Capability.SUBPROCESS_CATALOG_EXEC, "EXECUTE", {"is_catalog_command": True}),
            AccessRequest("ghidra_headless", "run_ghidra", self.target_pe, Capability.GHIDRA_HEADLESS_EXEC, "EXECUTE"),
            AccessRequest("etw_capture_engine", "start_session", "Sess", Capability.EVENT_LOG_READ, "EXECUTE"),
        ):
            dec = PolicyEngine.evaluate(req, scope=scope)
            self.assertEqual(dec.verdict, "DENY", f"Expected central DENY for {req.operation} while tampered")
            self.assertIn("AUDIT_TAMPER_DETECTED", dec.reason)

        with ExecutionGuard.scoped_session(self.target_pe, self.ws_dir):
            with self.assertRaises(SecurityViolationError) as ctx:
                ExecutionGuard.request_access(
                    component="safe_file_access",
                    operation="write_test",
                    target=os.path.join(self.ws_dir, "a.txt"),
                    capability=Capability.WORKSPACE_WRITE,
                    access_mode="WRITE",
                )
            self.assertIn("AUDIT_TAMPER_DETECTED", str(ctx.exception))

        # 2. MCP tools with side effects are blocked even if called while tampered
        res_reg_exp = srv.handle_tools_call({
            "name": "bintra_registry_audit",
            "arguments": {"action": "export_reg", "hive": "HKLM", "key": "SOFTWARE\\Microsoft", "reg_path": os.path.join(self.ws_dir, "out.reg")},
        })
        self.assertTrue(res_reg_exp["isError"])
        self.assertIn("AUDIT_TAMPER_DETECTED", res_reg_exp["content"][0]["text"])

        res_bridge = srv.handle_tools_call({
            "name": "bintra_ghidra_live_bridge",
            "arguments": {"action": "start", "port": 0},
        })
        self.assertTrue(res_bridge["isError"])
        self.assertIn("AUDIT_TAMPER_DETECTED", res_bridge["content"][0]["text"])

        res_etw = srv.handle_tools_call({
            "name": "bintra_etw_capture",
            "arguments": {"session_name": "TamperBlocked", "duration_seconds": 0.1},
        })
        self.assertTrue(res_etw["isError"])
        self.assertIn("AUDIT_TAMPER_DETECTED", res_etw["content"][0]["text"])

        # Pure read action on bintra_registry_audit still runs with degraded/tamper warning
        res_reg_read = srv.handle_tools_call({
            "name": "bintra_registry_audit",
            "arguments": {"action": "parse_reg", "reg_content": "Windows Registry Editor Version 5.00\n"},
        })
        self.assertFalse(res_reg_read["isError"])
        self.assertTrue(res_reg_read["structuredContent"].get("audit_tamper_detected"))

    def test_mcp_registry_export_enforces_workspace_before_dispatch(self) -> None:
        srv = BintraMcpServer(workspace_root=self.ws_dir)
        escaped = os.path.join(self.foreign_dir, "escape.reg")
        res = srv.handle_tools_call({
            "name": "bintra_registry_audit",
            "arguments": {"action": "export_reg", "hive": "HKLM", "key": "SOFTWARE\\Test", "reg_path": escaped},
        })
        self.assertTrue(res["isError"])
        self.assertIn("WRITE_OUTSIDE_WORKSPACE", res["content"][0]["text"])
        self.assertFalse(os.path.exists(escaped))

    def test_cli_triage_output_blocks_target_and_external_paths_and_allows_workspace(self) -> None:
        cli_py = os.path.join(SRC_DIR, "cli.py")
        before_hash = _sha256_file(self.target_pe)

        # 1. Attempting to overwrite the target binary itself MUST fail closed and preserve exact bytes
        overwrite_proc = subprocess.run(
            [
                sys.executable, cli_py, "triage",
                "--file", self.target_pe,
                "--output", self.target_pe,
                "--skip-deobf", "--skip-sensory", "--skip-hybrid-scan",
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
        self.assertNotEqual(overwrite_proc.returncode, 0, overwrite_proc.stdout + overwrite_proc.stderr)
        self.assertEqual(_sha256_file(self.target_pe), before_hash)

        # 2. Writing into target directory MUST fail closed
        target_dir_out = os.path.join(self.target_dir, "triage_report.json")
        targdir_proc = subprocess.run(
            [
                sys.executable, cli_py, "triage",
                "--file", self.target_pe,
                "--output", target_dir_out,
                "--skip-deobf", "--skip-sensory", "--skip-hybrid-scan",
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
        self.assertNotEqual(targdir_proc.returncode, 0, targdir_proc.stdout + targdir_proc.stderr)
        self.assertFalse(os.path.exists(target_dir_out))
        self.assertEqual(_sha256_file(self.target_pe), before_hash)

        # 3. Writing outside explicit workspace MUST fail closed
        outside_out = os.path.join(self.foreign_dir, "escape_triage.json")
        outside_proc = subprocess.run(
            [
                sys.executable, cli_py, "triage",
                "--file", self.target_pe,
                "--workspace", self.ws_dir,
                "--output", outside_out,
                "--skip-deobf", "--skip-sensory", "--skip-hybrid-scan",
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
        self.assertNotEqual(outside_proc.returncode, 0, outside_proc.stdout + outside_proc.stderr)
        self.assertFalse(os.path.exists(outside_out))
        self.assertEqual(_sha256_file(self.target_pe), before_hash)

        # 4. Writing inside authorized workspace succeeds cleanly
        valid_out = os.path.join(self.ws_dir, "triage_ok.json")
        ok_proc = subprocess.run(
            [
                sys.executable, cli_py, "triage",
                "--file", self.target_pe,
                "--workspace", self.ws_dir,
                "--output", valid_out,
                "--skip-deobf", "--skip-sensory", "--skip-hybrid-scan",
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
        self.assertEqual(ok_proc.returncode, 0, ok_proc.stdout + ok_proc.stderr)
        self.assertTrue(os.path.exists(valid_out))
        with open(valid_out, "r", encoding="utf-8") as fh:
            written = json.load(fh)
        self.assertEqual(written["target_sha256"], before_hash)
        self.assertEqual(_sha256_file(self.target_pe), before_hash)

    def test_audit_and_provenance_external_hmac_enforcement_and_disclosure(self) -> None:
        from analysis_orchestrator import BinaryTriageOrchestrator
        from ghidra_export_store import GhidraExportStore

        # AuditLogger without external HMAC discloses absent_hash_chain_only
        AuditLogger.log_decision("smoke_test", "op", self.ws_dir, "ALLOW_SCOPED", "ok")
        no_anchor = AuditLogger.verify_audit_chain(self.log_file, full_verify=True)
        self.assertTrue(no_anchor["is_valid"])
        self.assertEqual(no_anchor["external_trust_anchor"], "absent_hash_chain_only")

        # AuditLogger with BINTRA_AUDIT_HMAC_KEY authenticates and detects HMAC stripping
        hmac_log = os.path.join(self.log_dir, "audit_hmac.jsonl")
        with mock.patch.dict(os.environ, {"BINTRA_AUDIT_HMAC_KEY": "super-secret-audit-key"}):
            AuditLogger.clear()
            AuditLogger.set_log_file(hmac_log)
            AuditLogger.log_decision("smoke_test", "op_hmac", self.ws_dir, "ALLOW_SCOPED", "ok")
            ver_ok = AuditLogger.verify_audit_chain(hmac_log, full_verify=True)
            self.assertTrue(ver_ok["is_valid"])
            self.assertEqual(ver_ok["external_trust_anchor"], "hmac_sha256_verified")

            # Strip HMAC tag while leaving SHA-256 chain untouched -> must be caught
            with open(hmac_log, "r", encoding="utf-8") as fh:
                rec = json.loads(fh.readline())
            rec.pop("record_hmac", None)
            with open(hmac_log, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")

            ver_bad = AuditLogger.verify_audit_chain(hmac_log, full_verify=True)
            self.assertFalse(ver_bad["is_valid"])
            self.assertIn("HMAC", ver_bad["error"])
            AuditLogger.clear()
            with self.assertRaises(AuditIntegrityError):
                AuditLogger.recover_chain_from_disk(hmac_log)

        # Provenance manifest with BINTRA_PROVENANCE_HMAC_KEY refuses missing hmac_sha256
        export_path = os.path.join(self.ws_dir, "export.json")
        target_sha = _sha256_file(self.target_pe)
        payload = {"program_name": "victim.exe", "sha256": target_sha, "functions": [{"name": "entry", "entry_rva": "0x1000"}]}
        with open(export_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)

        with GhidraExportStore.from_path(export_path) as store:
            content_sha = BinaryTriageOrchestrator.compute_ghidra_export_content_sha256(store)
            sidecar = f"{export_path}.provenance.json"
            with open(sidecar, "w", encoding="utf-8") as fh:
                json.dump({"target_sha256": target_sha, "export_content_sha256": content_sha}, fh)

            # Without key configured -> honest caveat & hmac_verified=False
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("BINTRA_PROVENANCE_HMAC_KEY", None)
                prov_unkeyed, is_crypto, _ = BinaryTriageOrchestrator.verify_ghidra_export_provenance(
                    store, target_sha256=target_sha, target_filename="victim.exe"
                )
                self.assertTrue(is_crypto)
                self.assertFalse(prov_unkeyed["hmac_verified"])

            # With key configured -> stripped hmac_sha256 MUST be quarantined (not skipped!)
            with mock.patch.dict(os.environ, {"BINTRA_PROVENANCE_HMAC_KEY": "prov-key-123"}):
                prov_missing_sig, is_crypto_missing, _ = BinaryTriageOrchestrator.verify_ghidra_export_provenance(
                    store, target_sha256=target_sha, target_filename="victim.exe"
                )
                self.assertFalse(is_crypto_missing)
                self.assertEqual(prov_missing_sig["status"], "PROVENANCE_CONTENT_TAMPERED")
                self.assertEqual(prov_missing_sig["hmac_status"], "HMAC_SIGNATURE_MISSING")

                sig = hmac.new(b"prov-key-123", f"{target_sha}:{content_sha}".encode("utf-8"), hashlib.sha256).hexdigest()
                with open(sidecar, "w", encoding="utf-8") as fh:
                    json.dump({"target_sha256": target_sha, "export_content_sha256": content_sha, "hmac_sha256": sig}, fh)
                prov_signed, is_crypto_signed, _ = BinaryTriageOrchestrator.verify_ghidra_export_provenance(
                    store, target_sha256=target_sha, target_filename="victim.exe"
                )
                self.assertTrue(is_crypto_signed)
                self.assertTrue(prov_signed["hmac_verified"])
                self.assertEqual(prov_signed["hmac_status"], "VERIFIED")

    @unittest.skipUnless(sys.platform == "win32", "Requires live Windows host binaries")
    def test_live_windows_system_binary_integration_and_zero_mutation(self) -> None:
        """
        Real integration test against native Windows system binaries (notepad.exe / kernel32.dll)
        proving full read-only triage/dependency/catalog analysis with unchanged target SHA-256.
        """
        sys32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
        notepad = os.path.join(sys32, "notepad.exe")
        kernel32 = os.path.join(sys32, "kernel32.dll")
        sample = notepad if os.path.isfile(notepad) else sys.executable
        sample_copy = os.path.join(self.target_dir, os.path.basename(sample))
        shutil.copy2(sample, sample_copy)

        sys_before = _sha256_file(sample)
        copy_before = _sha256_file(sample_copy)
        k32_before = _sha256_file(kernel32) if os.path.isfile(kernel32) else None

        cli_py = os.path.join(SRC_DIR, "cli.py")
        out_md = os.path.join(self.ws_dir, "win10_live_triage.md")
        proc = subprocess.run(
            [
                sys.executable, cli_py, "triage",
                "--file", sample_copy,
                "--workspace", self.ws_dir,
                "--format", "md",
                "--output", out_md,
                "--skip-deobf", "--skip-sensory", "--skip-hybrid-scan",
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=45,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(os.path.exists(out_md))
        with open(out_md, "r", encoding="utf-8") as fh:
            md_txt = fh.read()
        self.assertIn(copy_before, md_txt)

        # Catalog command through SafeSubprocessBroker on live Windows host
        cat_res = SafeSubprocessBroker.execute_catalog_command("os_ver", timeout=10)
        self.assertEqual(cat_res["status"], "success")
        self.assertIn("Windows", cat_res["stdout"])

        # Inspect real System32 kernel32.dll read-only via MCP
        srv = BintraMcpServer(workspace_root=self.ws_dir)
        if os.path.isfile(kernel32):
            k32_resp = srv.handle_tools_call({
                "name": "bintra_inspect_binary",
                "arguments": {"file_path": kernel32, "max_exports": 10},
            })
            self.assertFalse(k32_resp["isError"])
            self.assertEqual(_sha256_file(kernel32), k32_before)

        # Cryptographic proof of zero byte mutation on target binaries
        self.assertEqual(_sha256_file(sample), sys_before)
        self.assertEqual(_sha256_file(sample_copy), copy_before)


if __name__ == "__main__":
    unittest.main()
