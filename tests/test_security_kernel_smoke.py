import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import security  # noqa: E402
from security import (  # noqa: E402
    PROHIBITED_HAZARDS,
    AccessDecision,
    AccessRequest,
    AuditIntegrityError,
    AuditLogger,
    AuditPersistenceError,
    Capability,
    CapabilityRegistry,
    ExecutionGuard,
    GhidraProjectGuard,
    OutOfScopeError,
    PathIdentity,
    PolicyEngine,
    SafeFileAccess,
    SafeProcessAccess,
    SafeRegistryAccess,
    SafeSubprocessBroker,
    SecurityViolationError,
    TargetMutationError,
    TargetScope,
)
import security.audit_logger as audit_mod  # noqa: E402
import security.capability_registry as cap_mod  # noqa: E402
import security.execution_guard as guard_mod  # noqa: E402
import security.ghidra_project_guard as ghidra_mod  # noqa: E402
import security.path_identity as path_mod  # noqa: E402
import security.policy_engine as policy_mod  # noqa: E402
import security.safe_file_access as sfa_mod  # noqa: E402
import security.safe_process_access as spa_mod  # noqa: E402
import security.safe_registry_access as sra_mod  # noqa: E402
import security.safe_subprocess as sub_mod  # noqa: E402
import security.target_scope as scope_mod  # noqa: E402


class _IsolatedSecurityTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = self._tmpdir.name
        self.target_dir = os.path.join(self.root, "target_app")
        self.workspace_dir = os.path.join(self.root, "workspace")
        self.log_dir = os.path.join(self.root, "logs")
        os.makedirs(self.target_dir, exist_ok=True)
        os.makedirs(self.workspace_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)

        self.target_file = os.path.join(self.target_dir, "sample.bin")
        with open(self.target_file, "wb") as fh:
            fh.write(b"MZ\x90\x00BINTRA_SMOKE_TARGET")

        self._prev_scope = ExecutionGuard.get_current_scope()
        self._prev_log_dir = AuditLogger._log_dir
        self._prev_log_file = AuditLogger._log_file
        self._prev_strict = AuditLogger.get_strict_persistence()
        self._prev_seg_max = AuditLogger._segment_max_bytes
        self._prev_known_disk_state = AuditLogger._known_disk_state

        self.log_file = os.path.join(self.log_dir, "audit_smoke.jsonl")
        AuditLogger.clear()
        AuditLogger.set_log_file(self.log_file)
        AuditLogger.set_strict_persistence(False)

    def tearDown(self) -> None:
        ExecutionGuard.set_current_scope(self._prev_scope)
        AuditLogger._segment_max_bytes = self._prev_seg_max
        AuditLogger.set_strict_persistence(self._prev_strict)
        AuditLogger._log_dir = self._prev_log_dir
        AuditLogger._log_file = self._prev_log_file
        AuditLogger._known_disk_state = self._prev_known_disk_state
        AuditLogger.clear()
        self._tmpdir.cleanup()


class TestSecurityKernelSmoke(_IsolatedSecurityTestBase):
    def test_module_export_parity(self) -> None:
        self.assertGreaterEqual(len(security.__all__), 20)
        self.assertIs(Capability, cap_mod.Capability)
        self.assertIs(CapabilityRegistry, cap_mod.CapabilityRegistry)
        self.assertIs(PROHIBITED_HAZARDS, cap_mod.PROHIBITED_HAZARDS)
        self.assertIs(PathIdentity, path_mod.PathIdentity)
        self.assertIs(TargetScope, scope_mod.TargetScope)
        self.assertIs(AuditLogger, audit_mod.AuditLogger)
        self.assertIs(AuditPersistenceError, audit_mod.AuditPersistenceError)
        self.assertIs(AuditIntegrityError, audit_mod.AuditIntegrityError)
        self.assertIs(PolicyEngine, policy_mod.PolicyEngine)
        self.assertIs(AccessRequest, policy_mod.AccessRequest)
        self.assertIs(AccessDecision, policy_mod.AccessDecision)
        self.assertIs(ExecutionGuard, guard_mod.ExecutionGuard)
        self.assertIs(SecurityViolationError, guard_mod.SecurityViolationError)
        self.assertIs(TargetMutationError, guard_mod.TargetMutationError)
        self.assertIs(OutOfScopeError, guard_mod.OutOfScopeError)
        self.assertIs(SafeFileAccess, sfa_mod.SafeFileAccess)
        self.assertIs(SafeRegistryAccess, sra_mod.SafeRegistryAccess)
        self.assertIs(SafeProcessAccess, spa_mod.SafeProcessAccess)
        self.assertIs(SafeSubprocessBroker, sub_mod.SafeSubprocessBroker)
        self.assertIs(GhidraProjectGuard, ghidra_mod.GhidraProjectGuard)
        self.assertIsNotNone(getattr(audit_mod, "_ProcessFileLock", None))

    def test_capability_registry_and_hazards(self) -> None:
        caps = CapabilityRegistry.get_capabilities("safe_file_access")
        self.assertIn(Capability.FILE_READ, caps)
        self.assertIn(Capability.WORKSPACE_WRITE, caps)
        self.assertTrue(CapabilityRegistry.has_capability("safe_file_access", Capability.FILE_READ))
        self.assertFalse(CapabilityRegistry.has_capability("unknown_component", Capability.FILE_READ))
        for hazard in (
            Capability.TARGET_MUTATE,
            Capability.REGISTRY_MUTATE,
            Capability.PROCESS_MUTATE,
            Capability.SERVICE_MUTATE,
            Capability.DRIVER_MUTATE,
            Capability.SHELL_FREE_EXEC,
            Capability.PRIVILEGE_ELEVATE,
        ):
            self.assertIn(hazard, PROHIBITED_HAZARDS)

        orig_test_caps = set(CapabilityRegistry.COMPONENT_CAPABILITIES.get("_smoke_temp", set()))
        try:
            CapabilityRegistry.register_component_capability("_smoke_temp", Capability.FILE_READ)
            self.assertTrue(CapabilityRegistry.has_capability("_smoke_temp", Capability.FILE_READ))
        finally:
            if orig_test_caps:
                CapabilityRegistry.COMPONENT_CAPABILITIES["_smoke_temp"] = orig_test_caps
            else:
                CapabilityRegistry.COMPONENT_CAPABILITIES.pop("_smoke_temp", None)

    def test_path_identity_canonicalization_and_guards(self) -> None:
        can_target = PathIdentity.canonicalize(self.target_file)
        self.assertTrue(os.path.isabs(can_target))
        self.assertTrue(PathIdentity.is_same_file(self.target_file, can_target))
        self.assertTrue(PathIdentity.is_within_directory(self.target_file, self.target_dir))
        self.assertFalse(PathIdentity.is_within_directory(self.target_file, self.workspace_dir))

        for bad in (r"\\.\PhysicalDrive0", r"\\?\C:\Windows", "//./PhysicalDrive0", "  //?/C:/Windows"):
            with self.assertRaises(ValueError):
                PathIdentity.canonicalize(bad)

        # Nearest-ancestor resolution preserves canonical physical path even for uncreated children
        uncreated_child = os.path.join(self.workspace_dir, "nested_new", "leaf.bin")
        self.assertTrue(PathIdentity.is_within_directory(uncreated_child, self.workspace_dir))

        if sys.platform == "win32":
            with self.assertRaises(ValueError):
                PathIdentity.canonicalize(self.target_file + ":hidden_stream")

    def test_target_scope_integrity_and_containment(self) -> None:
        scope = TargetScope(
            target_binary_path=self.target_file,
            workspace_dir=self.workspace_dir,
            strict_read_scope=True,
        )
        self.assertTrue(scope.has_registered_targets())
        self.assertTrue(scope.is_target_file(self.target_file))
        self.assertTrue(scope.is_target_directory(self.target_dir))
        self.assertEqual(
            scope.containing_target_directory(os.path.join(self.target_dir, "nested", "out.txt")),
            PathIdentity.canonicalize(self.target_dir),
        )
        self.assertTrue(scope.is_inside_workspace(os.path.join(self.workspace_dir, "report.json")))
        self.assertFalse(scope.is_inside_workspace(self.target_file))
        self.assertTrue(scope.is_authorized_read_target(self.target_file))

        unrelated = os.path.join(self.root, "other.txt")
        with open(unrelated, "w", encoding="utf-8") as fh:
            fh.write("unrelated")
        self.assertFalse(scope.is_authorized_read_target(unrelated))

        ws_artifact = os.path.join(self.workspace_dir, "artifact.txt")
        with open(ws_artifact, "w", encoding="utf-8") as fh:
            fh.write("ok")
        scope.record_session_file(ws_artifact)
        self.assertTrue(scope.is_session_file(ws_artifact))
        self.assertIn(PathIdentity.canonicalize(ws_artifact), scope.get_session_files())
        self.assertTrue(scope.is_authorized_read_target(ws_artifact))

        integrity_ok = scope.verify_target_integrity(self.target_file)
        self.assertEqual(integrity_ok["status"], "success")
        self.assertTrue(integrity_ok["is_intact"])
        self.assertFalse(integrity_ok["tamper_detected"])

        with open(self.target_file, "ab") as fh:
            fh.write(b"TAMPER")
        integrity_bad = scope.verify_target_integrity(self.target_file)
        self.assertEqual(integrity_bad["status"], "success")
        self.assertFalse(integrity_bad["is_intact"])
        self.assertTrue(integrity_bad["tamper_detected"])

        # Replacing target file with a directory reports tampered gracefully without IsADirectoryError
        dir_target = os.path.join(self.target_dir, "replaced.bin")
        with open(dir_target, "wb") as fh:
            fh.write(b"REAL")
        scope_dir = TargetScope(target_binary_path=dir_target, workspace_dir=self.workspace_dir)
        os.remove(dir_target)
        os.makedirs(dir_target, exist_ok=True)
        integrity_dir = scope_dir.verify_target_integrity(dir_target)
        self.assertEqual(integrity_dir["status"], "tampered")
        self.assertFalse(integrity_dir["is_intact"])
        self.assertTrue(integrity_dir["tamper_detected"])

    def test_policy_engine_and_execution_guard(self) -> None:
        scope = TargetScope(
            target_binary_path=self.target_file,
            workspace_dir=self.workspace_dir,
            strict_read_scope=True,
        )
        # Hazard deny
        d_hazard = PolicyEngine.evaluate(
            AccessRequest("safe_file_access", "mutate", self.target_file, Capability.TARGET_MUTATE, "WRITE"),
            scope=scope,
        )
        self.assertEqual(d_hazard.verdict, "DENY")

        # Missing capability deny
        d_uncap = PolicyEngine.evaluate(
            AccessRequest("unknown_comp", "read", self.target_file, Capability.FILE_READ, "READ"),
            scope=scope,
        )
        self.assertEqual(d_uncap.verdict, "DENY")

        # Target directory write deny
        d_dir = PolicyEngine.evaluate(
            AccessRequest(
                "safe_file_access",
                "write",
                os.path.join(self.target_dir, "report.txt"),
                Capability.WORKSPACE_WRITE,
                "WRITE",
            ),
            scope=scope,
        )
        self.assertEqual(d_dir.verdict, "DENY")

        # Out of workspace write deny
        d_oow = PolicyEngine.evaluate(
            AccessRequest(
                "safe_file_access",
                "write",
                os.path.join(self.root, "outside.txt"),
                Capability.WORKSPACE_WRITE,
                "WRITE",
            ),
            scope=scope,
        )
        self.assertEqual(d_oow.verdict, "DENY")

        # Valid workspace write allow
        ws_out = os.path.join(self.workspace_dir, "out.txt")
        d_ws = PolicyEngine.evaluate(
            AccessRequest("safe_file_access", "write", ws_out, Capability.WORKSPACE_WRITE, "WRITE"),
            scope=scope,
        )
        self.assertEqual(d_ws.verdict, "ALLOW_SCOPED")

        # Write without TargetScope must fail closed
        d_no_scope = PolicyEngine.evaluate(
            AccessRequest("safe_file_access", "write", ws_out, Capability.WORKSPACE_WRITE, "WRITE"),
            scope=None,
        )
        self.assertEqual(d_no_scope.verdict, "DENY")
        self.assertIn("SCOPE_REQUIRED", d_no_scope.reason)

        # Sensitive credential path deny (SAM + SYSTEM + NTDS)
        for cred_path in (
            r"C:\Windows\System32\config\SAM",
            r"C:\Windows\System32\config\SYSTEM",
            r"C:\Windows\NTDS\ntds.dit",
        ):
            d_cred = PolicyEngine.evaluate(
                AccessRequest("safe_file_access", "read", cred_path, Capability.FILE_READ, "READ"),
                scope=None,
            )
            self.assertEqual(d_cred.verdict, "DENY")
            self.assertIn("FORBIDDEN_SYSTEM_READ", d_cred.reason)

        # Temp marker write allow only for ghidra_live_bridge + .bintra_bridge.json
        marker_path = os.path.join(tempfile.gettempdir(), ".bintra_bridge.json")
        d_marker = PolicyEngine.evaluate(
            AccessRequest(
                "ghidra_live_bridge",
                "write_tempdir_discovery_marker",
                marker_path,
                Capability.TEMPDIR_MARKER_WRITE,
                "WRITE",
            ),
            scope=scope,
        )
        self.assertEqual(d_marker.verdict, "ALLOW_SCOPED")

        d_marker_wrong = PolicyEngine.evaluate(
            AccessRequest(
                "safe_file_access",
                "marker",
                marker_path,
                Capability.TEMPDIR_MARKER_WRITE,
                "WRITE",
            ),
            scope=scope,
        )
        self.assertEqual(d_marker_wrong.verdict, "DENY")

        # ExecutionGuard scoped_session restores prior scope
        outside_scope = ExecutionGuard.get_current_scope()
        with ExecutionGuard.scoped_session(self.target_file, self.workspace_dir):
            self.assertTrue(ExecutionGuard.get_current_scope().is_target_file(self.target_file))
            with self.assertRaises(TargetMutationError):
                ExecutionGuard.request_access(
                    "safe_file_access",
                    "write",
                    self.target_file,
                    Capability.WORKSPACE_WRITE,
                    access_mode="WRITE",
                )
            with self.assertRaises(OutOfScopeError):
                ExecutionGuard.request_access(
                    "safe_file_access",
                    "write",
                    os.path.join(self.root, "escape.txt"),
                    Capability.WORKSPACE_WRITE,
                    access_mode="WRITE",
                )
        self.assertIs(ExecutionGuard.get_current_scope(), outside_scope)

    def test_safe_file_access_roundtrip(self) -> None:
        with ExecutionGuard.scoped_session(self.target_file, self.workspace_dir):
            data = SafeFileAccess.read_bytes(self.target_file, offset=2, length=4)
            self.assertEqual(data, b"\x90\x00BI")

            with self.assertRaises(ValueError):
                SafeFileAccess.read_bytes(self.target_file, offset=-1)
            with self.assertRaises(ValueError):
                SafeFileAccess.read_bytes(self.target_file, length=-5)
            with self.assertRaises(IsADirectoryError):
                SafeFileAccess.read_bytes(self.target_dir)

            ws_txt = os.path.join(self.workspace_dir, "notes", "summary.txt")
            written_path = SafeFileAccess.write_workspace_file(ws_txt, "hello smoke")
            self.assertEqual(SafeFileAccess.read_text(written_path), "hello smoke")

            with self.assertRaises(FileExistsError):
                SafeFileAccess.write_workspace_file(ws_txt, "overwrite", overwrite=False)

            with self.assertRaises(TargetMutationError):
                SafeFileAccess.write_workspace_file(self.target_file, "corrupt")

            self.assertTrue(SafeFileAccess.delete_workspace_file(ws_txt))
            self.assertFalse(SafeFileAccess.delete_workspace_file(ws_txt))

            notes_dir = os.path.join(self.workspace_dir, "notes")
            with self.assertRaises(SecurityViolationError):
                SafeFileAccess.delete_workspace_dir(notes_dir)

            ExecutionGuard.get_current_scope().record_session_file(notes_dir)
            self.assertTrue(SafeFileAccess.delete_workspace_dir(notes_dir))

    def test_safe_registry_and_process_access(self) -> None:
        if sys.platform == "win32":
            import ctypes

            reg_res = SafeRegistryAccess.query_value(
                "HKLM",
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "ProductName",
            )
            self.assertEqual(reg_res["status"], "success")
            self.assertTrue(reg_res["value"])

            bad_reg = SafeRegistryAccess.enumerate_values("HKLM", r"SOFTWARE\BintraNonExistentSmokeKey123")
            self.assertEqual(bad_reg["status"], "not_found")

            proc_res = SafeProcessAccess.open_process_for_query(os.getpid())
            self.assertEqual(proc_res["status"], "success")
            if proc_res.get("handle"):
                ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(proc_res["handle"])
            img_path = SafeProcessAccess.query_process_image_path(os.getpid())
            self.assertTrue(img_path and os.path.basename(img_path).lower().endswith("python.exe"))
            bad_pid = SafeProcessAccess.open_process_for_query(-1)
            self.assertEqual(bad_pid["status"], "error")
            self.assertIsNone(bad_pid["handle"])
        else:
            reg_res = SafeRegistryAccess.query_value("HKLM", "SOFTWARE", "Test")
            self.assertEqual(reg_res["status"], "error")

    def test_safe_subprocess_and_ghidra_guard(self) -> None:
        denials_before = len(AuditLogger.get_denials())
        with self.assertRaises(SecurityViolationError):
            SafeSubprocessBroker.execute_catalog_command("nonexistent_catalog_cmd")

        with self.assertRaises(SecurityViolationError):
            SafeSubprocessBroker.execute_catalog_command("task_list", extra_flags=[";whoami"])

        self.assertGreaterEqual(len(AuditLogger.get_denials()), denials_before + 2)

        with self.assertRaises(ValueError):
            SafeSubprocessBroker.run_bounded_process([sys.executable, "-c", "pass"], timeout=0)

        proc_ok = SafeSubprocessBroker.run_bounded_process(
            [sys.executable, "-c", "print('smoke_ok')"],
            timeout=5.0,
        )
        self.assertEqual(proc_ok["status"], "success")
        self.assertIn("smoke_ok", proc_ok["stdout"])

        proc_trunc = SafeSubprocessBroker.run_bounded_process(
            [sys.executable, "-c", "print('A' * 200)"],
            timeout=5.0,
            max_stdout_bytes=32,
        )
        self.assertEqual(proc_trunc["status"], "output_limit_exceeded")
        self.assertTrue(proc_trunc["stdout_truncated"])
        self.assertTrue(proc_trunc["output_limit_exceeded"])
        self.assertIn("[BINTRA-SAFETY: stdout truncated at 32 byte limit]", proc_trunc["stdout"])

        with ExecutionGuard.scoped_session(self.target_file, self.workspace_dir):
            with self.assertRaises(ValueError):
                GhidraProjectGuard.sanitize_project_name("bad name/..")
            with self.assertRaises(ValueError):
                GhidraProjectGuard.sanitize_project_name("proj\nevil")
            self.assertEqual(GhidraProjectGuard.sanitize_project_name("smoke_proj-1"), "smoke_proj-1")
            resolved = GhidraProjectGuard.resolve_project_dir(None)
            self.assertTrue(PathIdentity.is_within_directory(resolved, self.workspace_dir))
            rep_path, gpr_path = GhidraProjectGuard.register_and_prepare_project(
                "ghidra_headless", resolved, "smoke_proj"
            )
            self.assertTrue(os.path.isdir(resolved))
            self.assertTrue(rep_path.endswith("smoke_proj.rep"))
            self.assertTrue(gpr_path.endswith("smoke_proj.gpr"))
            os.makedirs(rep_path, exist_ok=True)
            with open(gpr_path, "w", encoding="utf-8") as fh:
                fh.write("<PROJECT/>")
            self.assertTrue(GhidraProjectGuard.clean_transient_project("ghidra_headless", resolved, "smoke_proj"))
            self.assertFalse(os.path.exists(rep_path))
            self.assertFalse(os.path.exists(gpr_path))

    def test_audit_logger_chain_rotation_and_recovery(self) -> None:
        AuditLogger._segment_max_bytes = 350
        for idx in range(6):
            AuditLogger.log_decision(
                component="smoke_test",
                operation=f"op_{idx}",
                target=self.workspace_dir,
                decision="ALLOW_SCOPED" if idx % 2 == 0 else "DENY",
                reason="token=supersecret_smoke_token",
                requested_capability="FILE_READ",
            )

        trail = AuditLogger.get_audit_trail()
        self.assertEqual(len(trail), 6)
        self.assertIn("***REDACTED***", trail[0]["reason"])
        self.assertEqual(len(AuditLogger.get_denials()), 3)
        summary = AuditLogger.summarize()
        self.assertEqual(summary["total_mediated_operations"], 6)
        self.assertEqual(summary["denied_count"], 3)
        self.assertEqual(summary["allowed_scoped_count"], 3)

        verify_res = AuditLogger.verify_audit_chain(self.log_file, full_verify=True)
        self.assertTrue(verify_res["is_valid"])
        self.assertEqual(verify_res["records_verified"], 6)

        # Ensure continuity seals the oversized active file and resumes cleanly
        AuditLogger.clear()
        AuditLogger.set_log_file(self.log_file)
        cont = AuditLogger.ensure_chain_continuity(self.log_file, rotate_on_corrupt=False)
        self.assertTrue(cont["recovered"])
        self.assertEqual(cont["records_count"], 6)
        sealed = AuditLogger._sealed_segments(self.log_file)
        self.assertGreaterEqual(len(sealed), 1)

        # Append a post-seal decision and verify full + cached digest mode
        AuditLogger.log_decision(
            component="smoke_test",
            operation="op_post_seal",
            target=self.workspace_dir,
            decision="ALLOW_SCOPED",
            reason="post seal check",
            requested_capability="FILE_READ",
        )
        verify_post = AuditLogger.verify_audit_chain(self.log_file, full_verify=True)
        self.assertTrue(verify_post["is_valid"])
        self.assertEqual(verify_post["records_verified"], 7)
        self.assertEqual(verify_post["verification_mode"], "full_record_chain")

        verify_cached_first = AuditLogger.verify_audit_chain(self.log_file, full_verify=False)
        self.assertTrue(verify_cached_first["is_valid"])
        self.assertEqual(verify_cached_first["records_verified"], 7)
        self.assertEqual(verify_cached_first["verification_mode"], "sealed_digest_cache")
        self.assertTrue(os.path.exists(AuditLogger._sealed_cache_path(self.log_file)))

        verify_cached_second = AuditLogger.verify_audit_chain(self.log_file, full_verify=False)
        self.assertTrue(verify_cached_second["is_valid"])
        self.assertEqual(verify_cached_second["records_verified"], 7)


if __name__ == "__main__":
    unittest.main()
