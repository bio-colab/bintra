# -*- coding: utf-8 -*-
"""
NEON Audit Regression Test Suite.
Validates all confirmed P0, P1, and P2 security, functional, packaging,
and Win32 native API contract fixes on Linux (with realistic Win32 API mocks).
"""

import ctypes
import io
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest
from ctypes import wintypes
from pathlib import Path
from unittest import mock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(REPO_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


class TestNeonAuditRegressions(unittest.TestCase):
    """Regression tests for NEON audit findings F-001 through F-013."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="bintra_neon_reg_")
        self.ws_dir = os.path.join(self.tmp_dir, "workspace")
        self.target_dir = os.path.join(self.tmp_dir, "target")
        os.makedirs(self.ws_dir, exist_ok=True)
        os.makedirs(self.target_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # F-001 (P0): GhidraExportStore fail-closed security mediation
    # ------------------------------------------------------------------
    def test_f001_ghidra_export_store_fail_closed_no_target_deletion(self):
        from ghidra_export_store import GhidraExportStore
        from security import ExecutionGuard, SecurityViolationError

        protected_target = os.path.join(self.target_dir, "protected.exe")
        original_bytes = b"MZ_PROTECTED_TARGET_DO_NOT_DELETE"
        with open(protected_target, "wb") as f:
            f.write(original_bytes)

        src_json = os.path.join(self.ws_dir, "export.json")
        with open(src_json, "w", encoding="utf-8") as f:
            json.dump({"program_name": "test.exe", "functions": []}, f)

        with ExecutionGuard.scoped_session(target_binary_path=protected_target, workspace_dir=self.ws_dir):
            with self.assertRaises(SecurityViolationError):
                GhidraExportStore.ingest_to_sqlite(src_json, protected_target)

        # Target file must remain completely untouched
        self.assertTrue(os.path.exists(protected_target))
        with open(protected_target, "rb") as f:
            self.assertEqual(f.read(), original_bytes)

    def test_f001_ghidra_export_store_rejects_outside_workspace(self):
        from ghidra_export_store import GhidraExportStore
        from security import ExecutionGuard, OutOfScopeError

        outside_db = os.path.join(self.target_dir, "outside.db")
        src_json = os.path.join(self.ws_dir, "export.json")
        with open(src_json, "w", encoding="utf-8") as f:
            json.dump({"program_name": "test.exe", "functions": []}, f)

        with ExecutionGuard.scoped_session(workspace_dir=self.ws_dir):
            with self.assertRaises(OutOfScopeError):
                GhidraExportStore.ingest_to_sqlite(src_json, outside_db)
        self.assertFalse(os.path.exists(outside_db))

    # ------------------------------------------------------------------
    # F-002 (P1): Signature Intelligence Win32 API & classification fixes
    # ------------------------------------------------------------------
    def test_f002_signature_win32_error_classification_no_unsigned_mislabel(self):
        from windows_intelligence.signature_intelligence import (
            WindowsSignatureIntelligence,
            ERROR_SUCCESS,
            TRUST_E_NOSIGNATURE,
            CERT_E_EXPIRED,
            CERT_E_UNTRUSTEDROOT,
            CERT_E_REVOKED,
            CERT_E_REVOCATION_FAILURE,
            TRUST_E_EXPLICIT_DISTRUST,
            TRUST_E_BAD_DIGEST,
            TRUST_E_TIME_STAMP,
        )

        self.assertEqual(WindowsSignatureIntelligence._classify_win32_trust_status(ERROR_SUCCESS), "TRUSTED")
        self.assertEqual(WindowsSignatureIntelligence._classify_win32_trust_status(TRUST_E_NOSIGNATURE), "UNSIGNED")
        self.assertEqual(WindowsSignatureIntelligence._classify_win32_trust_status(CERT_E_EXPIRED), "EXPIRED")
        self.assertEqual(WindowsSignatureIntelligence._classify_win32_trust_status(CERT_E_UNTRUSTEDROOT), "UNTRUSTED_ROOT")
        self.assertEqual(WindowsSignatureIntelligence._classify_win32_trust_status(CERT_E_REVOKED), "REVOKED")
        self.assertEqual(WindowsSignatureIntelligence._classify_win32_trust_status(CERT_E_REVOCATION_FAILURE), "REVOCATION_UNKNOWN")
        self.assertEqual(WindowsSignatureIntelligence._classify_win32_trust_status(TRUST_E_EXPLICIT_DISTRUST), "EXPLICIT_DISTRUST")
        self.assertEqual(WindowsSignatureIntelligence._classify_win32_trust_status(TRUST_E_BAD_DIGEST), "TAMPERED")
        self.assertEqual(WindowsSignatureIntelligence._classify_win32_trust_status(TRUST_E_TIME_STAMP), "INVALID_TIMESTAMP")
        self.assertEqual(WindowsSignatureIntelligence._classify_win32_trust_status(0x800B0004), "VERIFICATION_ERROR")

    def test_f002_extract_win32_certificates_prototype_and_handle_cleanup(self):
        from windows_intelligence.signature_intelligence import (
            WindowsSignatureIntelligence,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        )

        closed_stores = []
        closed_msgs = []
        captured_flags = []

        class FakeFn:
            def __init__(self, impl):
                self._impl = impl
                self.argtypes = None
                self.restype = None

            def __call__(self, *args):
                return self._impl(*args)

        class FakeCrypt32:
            def __init__(self):
                self.CryptQueryObject = FakeFn(self._query_obj)
                self.CertEnumCertificatesInStore = FakeFn(self._enum_certs)
                self.CertGetNameStringW = FakeFn(self._get_name)
                self.CertCloseStore = FakeFn(lambda h, fl: closed_stores.append(h.value) or 1)
                self.CryptMsgClose = FakeFn(lambda h: closed_msgs.append(h.value) or 1)
                self._enum_called = 0

            def _query_obj(self, obj_type, pv_obj, content_flags, fmt_flags, flags, enc, ct, ft, ph_store, ph_msg, ppv):
                captured_flags.append(content_flags)
                # Populate both store and message handles (non-null)
                ctypes.cast(ph_store, ctypes.POINTER(ctypes.c_void_p)).contents.value = 0x1111
                ctypes.cast(ph_msg, ctypes.POINTER(ctypes.c_void_p)).contents.value = 0x2222
                return 1

            def _enum_certs(self, h_store, prev):
                self._enum_called += 1
                return 0x3333 if self._enum_called == 1 else None

            def _get_name(self, p_cert, name_type, flags, type_para, buf, cch):
                val = "Microsoft Root Authority" if flags else "Microsoft Windows"
                buf.value = val
                return len(val) + 1

        cr = FakeCrypt32()
        certs = WindowsSignatureIntelligence._extract_win32_certificates("C:\\Windows\\System32\\CatRoot\\test.cat", cr)

        # Verify argtypes[1] is LPCWSTR (not c_void_p)
        self.assertEqual(cr.CryptQueryObject.argtypes[1], wintypes.LPCWSTR)
        # Verify both standalone PKCS#7 (.cat) and embedded flags are passed
        expected_flags = CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED
        self.assertEqual(captured_flags, [expected_flags])
        # Verify both handles were closed
        self.assertEqual(closed_stores, [0x1111])
        self.assertEqual(closed_msgs, [0x2222])
        self.assertEqual(len(certs), 1)
        self.assertEqual(certs[0]["subject"], "Microsoft Windows")

    def test_f002_catalog_untrusted_never_claims_whql_or_microsoft(self):
        from windows_intelligence.signature_intelligence import (
            WindowsSignatureIntelligence,
            TRUST_E_EXPLICIT_DISTRUST,
        )

        fake_cat = os.path.join(self.ws_dir, "microsoft_package_fake.cat")
        with open(fake_cat, "wb") as f:
            f.write(b"FAKECAT")
        sample_sys = os.path.join(self.ws_dir, "driver.sys")
        with open(sample_sys, "wb") as f:
            f.write(b"MZ" + b"\x00" * 128)

        closed_handles = []
        released_cat_ctx = []
        released_admin = []
        wvt_actions = []

        class FakeFn:
            def __init__(self, impl):
                self._impl = impl
                self.argtypes = None
                self.restype = None

            def __call__(self, *args):
                return self._impl(*args)

        class FakeK32:
            def __init__(self):
                self.CreateFileW = FakeFn(lambda *a: 0x123456789)
                self.CloseHandle = FakeFn(lambda h: closed_handles.append(h) or 1)

        class FakeWT:
            def __init__(self):
                self.CryptCATAdminAcquireContext = FakeFn(self._acq)
                self.CryptCATAdminCalcHashFromFileHandle = FakeFn(self._calc)
                self._enum_done = False
                self.CryptCATAdminEnumCatalogFromHash = FakeFn(self._enum_once)
                self.CryptCATCatalogInfoFromContext = FakeFn(self._cat_info)
                self.CryptCATAdminReleaseCatalogContext = FakeFn(lambda a, c, f: released_cat_ctx.append(c) or 1)
                self.CryptCATAdminReleaseContext = FakeFn(lambda a, f: released_admin.append(a.value) or 1)
                self.WinVerifyTrust = FakeFn(self._wvt)

            def _enum_once(self, *a):
                if not self._enum_done:
                    self._enum_done = True
                    return 0xABCD
                return None

            def _acq(self, ph, sub, fl):
                ctypes.cast(ph, ctypes.POINTER(ctypes.c_void_p)).contents.value = 0x5555
                return 1

            def _calc(self, hf, psz, buf, fl):
                sz_ptr = ctypes.cast(psz, ctypes.POINTER(wintypes.DWORD))
                if buf is None:
                    sz_ptr.contents.value = 4
                    return 1
                for idx, b in enumerate(b"\xDE\xAD\xBE\xEF"):
                    buf[idx] = b
                return 1

            def _cat_info(self, h_cat, p_ci, fl):
                ci = ctypes.cast(p_ci, ctypes.POINTER(ctypes.c_byte))
                # Write catalog path via struct reference
                p_ci._obj.wszCatalogFile = fake_cat
                return 1

            def _wvt(self, hwnd, guid_ptr, wtd_ptr):
                wtd = wtd_ptr._obj
                wvt_actions.append(wtd.dwStateAction)
                return TRUST_E_EXPLICIT_DISTRUST

        class FakeCR:
            pass

        res = WindowsSignatureIntelligence._resolve_security_catalog(
            sample_sys, FakeWT(), FakeK32(), FakeCR(), verify_revocation=False
        )
        self.assertEqual(res["trust_status"], "EXPLICIT_DISTRUST")
        self.assertFalse(res["is_verified"])
        self.assertFalse(res["is_whql_certified"])
        self.assertFalse(res["is_microsoft_system_binary"])
        self.assertEqual(closed_handles, [0x123456789])
        self.assertEqual(released_cat_ctx, [])  # Released automatically when EnumCatalogFromHash returned NULL
        self.assertEqual(released_admin, [0x5555])
        self.assertEqual(wvt_actions, [1, 2])  # VERIFY then CLOSE

    def test_f002_pure_python_fallback_unverified_not_microsoft_and_rva_bounds(self):
        from windows_intelligence.signature_intelligence import WindowsSignatureIntelligence

        # Build a minimal PE32+ where NumberOfRvaAndSizes = 2 (no Security Directory)
        pe = bytearray(512)
        pe[0:2] = b"MZ"
        struct.pack_into("<I", pe, 0x3C, 0x80)
        pe[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<H", pe, 0x80 + 24, 0x20B)  # PE32+
        struct.pack_into("<I", pe, 0x80 + 24 + 108, 2)  # NumberOfRvaAndSizes = 2
        # Put junk at where entry 4 would be
        struct.pack_into("<II", pe, 0x80 + 24 + 112 + 32, 0x180, 32)
        pe_path = os.path.join(self.ws_dir, "tiny_rva.exe")
        with open(pe_path, "wb") as f:
            f.write(pe)

        res = WindowsSignatureIntelligence._verify_pure_python_fallback(pe_path)
        self.assertEqual(res["trust_status"], "UNSIGNED")
        self.assertFalse(res["signature_present"])

        # Build a PE32+ with an unverified ASN.1 string "Microsoft Corporation"
        pe2 = bytearray(1024)
        pe2[0:2] = b"MZ"
        struct.pack_into("<I", pe2, 0x3C, 0x80)
        pe2[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<H", pe2, 0x80 + 24, 0x20B)
        struct.pack_into("<I", pe2, 0x80 + 24 + 108, 16)
        cert_off = 0x200
        asn1 = b"\x0c\x15Microsoft Corporation"
        cert_len = 8 + len(asn1)
        struct.pack_into("<II", pe2, 0x80 + 24 + 112 + 32, cert_off, cert_len)
        struct.pack_into("<IHH", pe2, cert_off, cert_len, 0x0200, 0x0002)
        pe2[cert_off + 8 : cert_off + 8 + len(asn1)] = asn1
        pe2_path = os.path.join(self.ws_dir, "spoofed_ms.exe")
        with open(pe2_path, "wb") as f:
            f.write(pe2)

        res2 = WindowsSignatureIntelligence._verify_pure_python_fallback(pe2_path)
        self.assertEqual(res2["trust_status"], "SIGNATURE_PRESENT_UNVERIFIED")
        self.assertFalse(res2["is_verified"])
        self.assertFalse(res2["is_microsoft_system_binary"])

    # ------------------------------------------------------------------
    # F-003 (P1): PowerShellExecutor ExecutionGuard contract fix
    # ------------------------------------------------------------------
    def test_f003_powershell_executor_passes_execution_guard_policy(self):
        from windows_intelligence.command_engine.powershell_executor import PowerShellExecutor

        fake_run = {
            "status": "success",
            "exit_code": 0,
            "stdout": '{"Caption":"Windows 11"}',
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }
        with mock.patch("os.name", "nt"), \
             mock.patch("os.path.isfile", return_value=True), \
             mock.patch("security.safe_subprocess.SafeSubprocessBroker.run_bounded_process", return_value=fake_run):
            res = PowerShellExecutor.query("cim_os")

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["Caption"], "Windows 11")

    # ------------------------------------------------------------------
    # F-004 (P1): ExecutionGuard & PolicyEngine no \\ prefix bypass
    # ------------------------------------------------------------------
    def test_f004_execution_guard_blocks_raw_nt_and_unc_sam_paths(self):
        from security import ExecutionGuard, Capability, SecurityViolationError

        for bad_target in (
            r"\\?\C:\Windows\System32\config\SAM",
            r"\\.\PhysicalDrive0",
            r"\\localhost\C$\Windows\System32\config\SAM",
        ):
            with self.assertRaises(SecurityViolationError, msg=f"Failed to block {bad_target}"):
                ExecutionGuard.request_access(
                    component="safe_file_access",
                    operation="read_bytes",
                    target=bad_target,
                    capability=Capability.FILE_READ,
                    access_mode="READ",
                )

    # ------------------------------------------------------------------
    # F-005 (P1): PathIdentity ADS, ..hidden, and Win32 prototypes
    # ------------------------------------------------------------------
    def test_f005_path_identity_ads_and_dotdot_filename(self):
        from security.path_identity import PathIdentity

        # Non-alpha prefix before ':' must be rejected as ADS
        with self.assertRaises(ValueError):
            PathIdentity.canonicalize("1:hidden_stream")
        with self.assertRaises(ValueError):
            PathIdentity.canonicalize("_:hidden_stream")

        # Legitimate filename starting with '..' inside workspace must be allowed
        dotdot_file = os.path.join(self.ws_dir, "..hidden_config")
        with open(dotdot_file, "w", encoding="utf-8") as f:
            f.write("ok")
        self.assertTrue(PathIdentity.is_within_directory(dotdot_file, self.ws_dir))
        # Real traversal must still be rejected
        self.assertFalse(PathIdentity.is_within_directory(os.path.join(self.ws_dir, "..", "target"), self.ws_dir))

    # ------------------------------------------------------------------
    # F-006 (P1): SafeSubprocessBroker flag whitelist exact-match
    # ------------------------------------------------------------------
    def test_f006_safe_subprocess_rejects_prefix_bypass_flags(self):
        from security.safe_subprocess import SafeSubprocessBroker
        from security import SecurityViolationError

        for bad_flag in ("/malicious", "/fi;calc", "/mEXTRA"):
            with self.assertRaises(SecurityViolationError, msg=f"Flag bypass allowed: {bad_flag}"):
                SafeSubprocessBroker.execute_catalog_command("task_list", extra_flags=[bad_flag])

        with self.assertRaises(SecurityViolationError):
            SafeSubprocessBroker.execute_catalog_command("event_query", extra_flags=["Security/../evil"])

    # ------------------------------------------------------------------
    # F-008 (P1): pyproject.toml py-modules completeness
    # ------------------------------------------------------------------
    def test_f008_pyproject_py_modules_complete(self):
        import tomllib

        pyproject_path = Path(REPO_ROOT) / "pyproject.toml"
        data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        declared = set(data["tool"]["setuptools"]["py-modules"])
        actual = {p.stem for p in (Path(REPO_ROOT) / "src").glob("*.py") if p.name != "__init__.py"}
        self.assertEqual(actual - declared, set(), f"Modules omitted from pyproject.toml: {actual - declared}")

    # ------------------------------------------------------------------
    # F-009 (P1): WindowsRegistryEditor does not swallow SecurityViolationError
    # ------------------------------------------------------------------
    def test_f009_registry_editor_reraises_security_violation(self):
        from windows_intelligence.registry_intelligence.registry_editor import WindowsRegistryEditor
        from security import SecurityViolationError

        reg_file = os.path.join(self.ws_dir, "sample.reg")
        with open(reg_file, "w", encoding="utf-8") as f:
            f.write("Windows Registry Editor Version 5.00\n")

        with mock.patch(
            "windows_intelligence.registry_intelligence.registry_editor.SafeFileAccess.read_bytes",
            side_effect=SecurityViolationError("OUT_OF_SCOPE_READ"),
        ):
            with self.assertRaises(SecurityViolationError):
                WindowsRegistryEditor.parse_reg_file(reg_file)

    # ------------------------------------------------------------------
    # F-010 (P1): MiniDumpParser bounded string read & ExecutionGuard
    # ------------------------------------------------------------------
    def test_f010_minidump_string_read_bounded_and_mediated(self):
        from windows_intelligence.runtime_telemetry.minidump_parser import MiniDumpParser
        from security import SecurityViolationError

        # Construct buffer declaring 0xFFFFFFFF-byte string
        buf = io.BytesIO(struct.pack("<I", 0xFFFFFFFF) + ("A".encode("utf-16-le") * 100))
        s = MiniDumpParser._read_minidump_string(buf, 0)
        self.assertEqual(len(s), 100)
        self.assertEqual(MiniDumpParser._read_minidump_string(buf, -1), "")

        # Verify ExecutionGuard blocks forbidden system paths
        with self.assertRaises(SecurityViolationError):
            MiniDumpParser.parse_minidump(r"\\?\C:\Windows\System32\config\SAM")

    # ------------------------------------------------------------------
    # F-011 (P2): SafeFileAccess handles None scope safely
    # ------------------------------------------------------------------
    def test_f011_safe_file_access_handles_none_scope(self):
        from security import SafeFileAccess, ExecutionGuard

        out_path = os.path.join(self.ws_dir, "test_none_scope.txt")
        with mock.patch.object(ExecutionGuard, "request_access"), \
             mock.patch.object(ExecutionGuard, "get_current_scope", return_value=None):
            written = SafeFileAccess.write_workspace_file(out_path, "hello")
        self.assertTrue(os.path.isfile(written))

    # ------------------------------------------------------------------
    # F-012 (P2): GhidraLiveBridge uses constant-time token comparison
    # ------------------------------------------------------------------
    def test_f012_ghidra_live_bridge_constant_time_auth(self):
        src_path = Path(REPO_ROOT) / "src" / "ghidra_live_bridge.py"
        txt = src_path.read_text(encoding="utf-8")
        self.assertIn("hmac.compare_digest", txt)


    # ------------------------------------------------------------------
    # F-007 & F-013 (P1/P2): Win32 64-bit ctypes prototype & handle tests
    # ------------------------------------------------------------------
    def test_f007_f013_win32_ctypes_prototypes_declared(self):
        checks = {
            "src/security/path_identity.py": ["CreateFileW.argtypes", "GetFinalPathNameByHandleW.argtypes", "CloseHandle.argtypes"],
            "src/security/safe_process_access.py": ["OpenProcess.argtypes", "QueryFullProcessImageNameW.argtypes", "CloseHandle.argtypes", "use_last_error=True"],
            "src/windows_intelligence/os_profiler.py": ["RtlGetVersion.argtypes", "GetNativeSystemInfo.argtypes", "GetCurrentProcess.restype", "IsWow64Process.argtypes"],
            "src/windows_intelligence/security_inspector.py": ["OpenProcessToken.argtypes", "GetTokenInformation.argtypes", "GetSidSubAuthorityCount.argtypes", "GetSidSubAuthority.argtypes", "CloseHandle.argtypes"],
            "src/windows_intelligence/system_introspection/process_inspector.py": ["GetTokenInformation.argtypes", "CloseHandle.argtypes"],
            "src/windows_intelligence/process_intelligence/task_manager.py": ["NtQueryInformationProcess.argtypes", "class _UNICODE_STRING", "OpenProcessToken.argtypes", "LookupAccountSidW.restype", "IsWow64Process.argtypes"],
            "src/windows_intelligence/runtime_telemetry/virtual_memory_inspector.py": ["OpenProcess.argtypes", "VirtualQueryEx.argtypes", "GetProcessTimes.argtypes", "use_last_error=True"],
            "src/windows_intelligence/runtime_telemetry/etw_controller.py": ["EnumerateTraceGuidsEx.argtypes", "CLSIDFromString.argtypes"],
        }
        for rel_path, tokens in checks.items():
            content = (Path(REPO_ROOT) / rel_path).read_text(encoding="utf-8")
            for tok in tokens:
                self.assertIn(tok, content, f"Missing '{tok}' in {rel_path}")

if __name__ == "__main__":
    unittest.main()
