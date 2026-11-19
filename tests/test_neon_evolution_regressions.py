# -*- coding: utf-8 -*-
"""
NEON Autonomous Engineering Evolution Regression & Integration Test Suite.
Validates Workstream A (A1-A6) and Workstream B (Unified Streaming Bounded Subprocess Engine).
Clearly distinguishes Linux runtime tests from mocked Windows NT API contract tests.
"""

import ctypes
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from ctypes import wintypes
from unittest import mock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(REPO_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


class TestNeonEvolutionA1A2GhidraStore(unittest.TestCase):
    """A1 & A2: GhidraExportStore security mediation and transactional file provenance."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="bintra_evo_a1a2_")
        self.ws_dir = os.path.join(self.tmp_dir, "workspace")
        self.outside_dir = os.path.join(self.tmp_dir, "outside")
        os.makedirs(self.ws_dir, exist_ok=True)
        os.makedirs(self.outside_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_a1_from_path_blocks_unauthorized_read_no_fallback(self):
        from ghidra_export_store import GhidraExportStore
        from security import ExecutionGuard, TargetScope, SecurityViolationError

        secret_jsonl = os.path.join(self.outside_dir, "secret.jsonl")
        with open(secret_jsonl, "w", encoding="utf-8") as f:
            f.write('{"program_name": "secret.exe"}\n')

        strict_scope = TargetScope(workspace_dir=self.ws_dir, strict_read_scope=True)
        prev = ExecutionGuard.get_current_scope()
        ExecutionGuard.set_current_scope(strict_scope)
        try:
            with self.assertRaises(SecurityViolationError):
                GhidraExportStore.from_path(secret_jsonl)
            with self.assertRaises(SecurityViolationError):
                GhidraExportStore._read_jsonl_to_dict(secret_jsonl)
        finally:
            ExecutionGuard.set_current_scope(prev)

    def test_a1_cache_security_violation_propagates_not_swallowed(self):
        from ghidra_export_store import GhidraExportStore
        from security import ExecutionGuard, SecurityViolationError

        src_jsonl = os.path.join(self.ws_dir, "export.jsonl")
        with open(src_jsonl, "w", encoding="utf-8") as f:
            f.write('{"program_name": "ok.exe"}\n{"entry_point": "0x1000", "name": "fn_a"}\n')

        with ExecutionGuard.scoped_session(workspace_dir=self.ws_dir):
            with mock.patch.object(
                GhidraExportStore,
                "ingest_to_sqlite",
                side_effect=SecurityViolationError("SIMULATED_POLICY_DENY"),
            ):
                with self.assertRaises(SecurityViolationError):
                    GhidraExportStore.from_path(src_jsonl)

    def test_a1_operational_sqlite_error_falls_back_when_source_authorized(self):
        from ghidra_export_store import GhidraExportStore
        from security import ExecutionGuard

        src_jsonl = os.path.join(self.ws_dir, "export.jsonl")
        with open(src_jsonl, "w", encoding="utf-8") as f:
            f.write('{"program_name": "ok.exe"}\n{"entry_point": "0x1000", "name": "fn_a"}\n')

        with ExecutionGuard.scoped_session(workspace_dir=self.ws_dir):
            with mock.patch.object(
                GhidraExportStore,
                "ingest_to_sqlite",
                side_effect=sqlite3.OperationalError("disk full"),
            ):
                store = GhidraExportStore.from_path(src_jsonl)
                self.assertEqual(store._in_memory.get("program_name"), "ok.exe")

    def test_a2_preexisting_unowned_file_cannot_be_overwritten_or_deleted(self):
        from ghidra_export_store import GhidraExportStore
        from security import ExecutionGuard, SecurityViolationError

        src_json = os.path.join(self.ws_dir, "export.json")
        with open(src_json, "w", encoding="utf-8") as f:
            json.dump({"program_name": "demo.exe", "functions": []}, f)

        preexisting_db = os.path.join(self.ws_dir, "user_existing.db")
        original_content = b"PREEXISTING_USER_DATA_MUST_SURVIVE"
        with open(preexisting_db, "wb") as f:
            f.write(original_content)

        with ExecutionGuard.scoped_session(workspace_dir=self.ws_dir):
            with self.assertRaises(SecurityViolationError) as ctx:
                GhidraExportStore.ingest_to_sqlite(src_json, preexisting_db)
            self.assertIn("PREEXISTING_FILE_PROTECTED", str(ctx.exception))

        # Pre-existing file must remain completely untouched
        with open(preexisting_db, "rb") as f:
            self.assertEqual(f.read(), original_content)

    def test_a2_failed_ingestion_preserves_destination_and_cleans_staging(self):
        from ghidra_export_store import GhidraExportStore
        from security import ExecutionGuard

        bad_json = os.path.join(self.ws_dir, "corrupt.json")
        with open(bad_json, "w", encoding="utf-8") as f:
            f.write("{NOT VALID JSON")

        target_db = os.path.join(self.ws_dir, "existing_ok.db")
        with open(target_db, "wb") as f:
            f.write(b"ORIGINAL_DB_BYTES")

        with ExecutionGuard.scoped_session(workspace_dir=self.ws_dir):
            with self.assertRaises(json.JSONDecodeError):
                GhidraExportStore.ingest_to_sqlite(bad_json, target_db, overwrite=True)

        # Destination was not destroyed on staging failure, and no .tmp.db left behind
        with open(target_db, "rb") as f:
            self.assertEqual(f.read(), b"ORIGINAL_DB_BYTES")
        leftover_temps = [n for n in os.listdir(self.ws_dir) if n.startswith(".bintra_sqlite_")]
        self.assertEqual(leftover_temps, [])


class TestNeonEvolutionA3A4A5SignatureIntelligence(unittest.TestCase):
    """A3, A4, A5: Mocked Win32 API contract tests for catalog enumeration, CMS signer attribution, and timestamps."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="bintra_evo_sig_")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_a3_multi_catalog_enumeration_advances_to_trusted_catalog(self):
        from windows_intelligence.signature_intelligence import (
            WindowsSignatureIntelligence,
            CERT_E_EXPIRED,
            ERROR_SUCCESS,
        )

        cat1 = os.path.join(self.tmp_dir, "cat1_expired.cat")
        cat2 = os.path.join(self.tmp_dir, "cat2_trusted.cat")
        drv = os.path.join(self.tmp_dir, "sample.sys")
        for path in (cat1, cat2, drv):
            with open(path, "wb") as f:
                f.write(b"MZ" + b"\x00" * 64)

        closed_handles = []
        released_cats = []
        released_admins = []
        enum_calls = []

        class FakeFn:
            def __init__(self, impl):
                self._impl = impl
                self.argtypes = None
                self.restype = None

            def __call__(self, *args):
                return self._impl(*args)

        class FakeK32:
            def __init__(self):
                self.CreateFileW = FakeFn(lambda *a: 0x1001)
                self.CloseHandle = FakeFn(lambda h: closed_handles.append(h) or 1)

        class FakeWT:
            def __init__(self):
                self.CryptCATAdminAcquireContext = FakeFn(self._acq)
                self.CryptCATAdminCalcHashFromFileHandle = FakeFn(self._calc)
                self.CryptCATAdminEnumCatalogFromHash = FakeFn(self._enum)
                self.CryptCATCatalogInfoFromContext = FakeFn(self._info)
                self.CryptCATAdminReleaseCatalogContext = FakeFn(lambda a, c, f: released_cats.append(c) or 1)
                self.CryptCATAdminReleaseContext = FakeFn(lambda a, f: released_admins.append(a.value) or 1)
                self.WinVerifyTrust = FakeFn(self._wvt)

            def _acq(self, ph, sub, fl):
                ctypes.cast(ph, ctypes.POINTER(ctypes.c_void_p)).contents.value = 0x2002
                return 1

            def _calc(self, hf, psz, buf, fl):
                sz_ptr = ctypes.cast(psz, ctypes.POINTER(wintypes.DWORD))
                if buf is None:
                    sz_ptr.contents.value = 4
                    return 1
                for i, b in enumerate(b"\x01\x02\x03\x04"):
                    buf[i] = b
                return 1

            def _enum(self, h_admin, h_buf, h_sz, fl, p_prev):
                prev_val = p_prev._obj.value if p_prev else None
                enum_calls.append(prev_val)
                if not prev_val:
                    return 0xC001
                if prev_val == 0xC001:
                    return 0xC002
                return None

            def _info(self, h_cat, p_ci, fl):
                p_ci._obj.wszCatalogFile = cat1 if h_cat == 0xC001 else cat2
                return 1

            def _wvt(self, hwnd, guid_ptr, wtd_ptr):
                wtd = wtd_ptr._obj
                if wtd.dwStateAction == 2:
                    return 0
                cat_info = ctypes.cast(wtd.pFile, ctypes.POINTER(ctypes.c_byte))
                # First catalog fails (EXPIRED), second catalog succeeds (ERROR_SUCCESS)
                return CERT_E_EXPIRED if len(enum_calls) == 1 else ERROR_SUCCESS

        class FakeCR:
            pass

        res = WindowsSignatureIntelligence._resolve_security_catalog(
            drv, FakeWT(), FakeK32(), FakeCR(), verify_revocation=False
        )
        self.assertTrue(res["found_in_catalog"])
        self.assertTrue(res["catalog_verified"])
        self.assertEqual(res["trust_status"], "TRUSTED")
        self.assertEqual(res["trust_classification"], "TRUSTED_CATALOG")
        self.assertEqual(res["catalog_file"], cat2)
        self.assertEqual(res["catalog_candidates_checked"], 2)
        self.assertEqual(enum_calls, [None, 0xC001])
        self.assertEqual(closed_handles, [0x1001])
        self.assertEqual(released_cats, [0xC002])
        self.assertEqual(released_admins, [0x2002])

    def test_a4_cms_signer_attribution_does_not_pick_arbitrary_store_cert_or_substring_whql(self):
        from windows_intelligence.signature_intelligence import (
            WindowsSignatureIntelligence,
            CMSG_SIGNER_INFO,
            CTL_USAGE,
            OID_WHQL_CRYPTO,
        )

        # Store has cert 0xA1 ("Microsoft Windows Hardware Compatibility" - NOT signer!)
        # and cert 0xA2 ("Contoso Driver Corp" - ACTUAL CMS SignerInfo match with WHQL EKU)
        class FakeFn:
            def __init__(self, impl):
                self._impl = impl
                self.argtypes = None
                self.restype = None

            def __call__(self, *args):
                return self._impl(*args)

        whql_oid_bytes = OID_WHQL_CRYPTO.encode("ascii")
        eku_arr = (ctypes.c_char_p * 1)(whql_oid_bytes)

        class FakeCR:
            def __init__(self, with_whql: bool):
                self._with_whql = with_whql
                self._enum_idx = 0
                self.CryptQueryObject = FakeFn(self._query)
                self.CertEnumCertificatesInStore = FakeFn(self._enum)
                self.CertGetNameStringW = FakeFn(self._name)
                self.CertCloseStore = FakeFn(lambda h, fl: 1)
                self.CryptMsgClose = FakeFn(lambda h: 1)
                self.CryptMsgGetParam = FakeFn(self._msg_param)
                self.CertFindCertificateInStore = FakeFn(lambda *a: 0xA2)
                self.CertFreeCertificateContext = FakeFn(lambda p: 1)
                self.CertGetEnhancedKeyUsage = FakeFn(self._eku)

            def _query(self, *args):
                ctypes.cast(args[8], ctypes.POINTER(ctypes.c_void_p)).contents.value = 0x5001
                ctypes.cast(args[9], ctypes.POINTER(ctypes.c_void_p)).contents.value = 0x5002
                return 1

            def _enum(self, h_store, prev):
                self._enum_idx += 1
                if self._enum_idx == 1:
                    return 0xA1
                if self._enum_idx == 2:
                    return 0xA2
                return None

            def _name(self, p_ctx, name_type, flags, tp, buf, cch):
                if p_ctx == 0xA1:
                    buf.value = "Microsoft Windows Hardware Compatibility"
                else:
                    buf.value = "Contoso Driver Corp" if not flags else "Contoso CA"
                return len(buf.value) + 1

            def _msg_param(self, h_msg, param_type, idx, data, p_cb):
                cb_ptr = ctypes.cast(p_cb, ctypes.POINTER(wintypes.DWORD))
                needed = ctypes.sizeof(CMSG_SIGNER_INFO)
                if data is None:
                    cb_ptr.contents.value = needed
                    return 1
                si = CMSG_SIGNER_INFO()
                ctypes.memmove(data, ctypes.byref(si), needed)
                return 1

            def _eku(self, p_ctx, fl, buf, p_cb):
                cb_ptr = ctypes.cast(p_cb, ctypes.POINTER(wintypes.DWORD))
                if not self._with_whql or p_ctx != 0xA2:
                    cb_ptr.contents.value = 0
                    return 0
                needed = ctypes.sizeof(CTL_USAGE)
                if buf is None:
                    cb_ptr.contents.value = needed
                    return 1
                u = CTL_USAGE()
                u.cUsageIdentifier = 1
                u.rgpszUsageIdentifier = eku_arr
                ctypes.memmove(buf, ctypes.byref(u), needed)
                return 1

        # Case 1: With WHQL EKU on actual CMS signer
        info_whql = WindowsSignatureIntelligence._extract_win32_signer_and_certificates("fake.sys", FakeCR(True))
        self.assertEqual(info_whql["signer_attribution_method"], "CMS_SIGNER_INFO_MATCH")
        self.assertEqual(info_whql["primary_signer"]["subject"], "Contoso Driver Corp")
        self.assertTrue(info_whql["primary_signer"]["has_whql_eku"])

        # Case 2: Without WHQL EKU (even though unrelated store cert 0xA1 says "Windows Hardware")
        info_no_whql = WindowsSignatureIntelligence._extract_win32_signer_and_certificates("fake.sys", FakeCR(False))
        self.assertEqual(info_no_whql["primary_signer"]["subject"], "Contoso Driver Corp")
        self.assertFalse(info_no_whql["primary_signer"]["has_whql_eku"])

    def test_a5_timestamp_and_expiration_classification_matrix(self):
        from windows_intelligence.signature_intelligence import (
            WindowsSignatureIntelligence,
            ERROR_SUCCESS,
            CERT_E_EXPIRED,
            TRUST_E_TIME_STAMP,
            CERT_E_UNTRUSTEDROOT,
        )

        # 1. Currently valid cert with valid timestamp
        r1 = WindowsSignatureIntelligence._classify_timestamp_and_expiration(ERROR_SUCCESS, True, cert_expired=False)
        self.assertEqual(r1["expiration_status"], "VALID_CURRENT")
        self.assertEqual(r1["timestamp_status"], "VALID_TRUSTED")

        # 2. Expired cert supported by valid trusted timestamp (ERROR_SUCCESS)
        r2 = WindowsSignatureIntelligence._classify_timestamp_and_expiration(ERROR_SUCCESS, True, cert_expired=True)
        self.assertEqual(r2["expiration_status"], "EXPIRED_WITH_VALID_TIMESTAMP")
        self.assertEqual(r2["timestamp_status"], "VALID_TRUSTED")

        # 3. Expired cert without timestamp
        r3 = WindowsSignatureIntelligence._classify_timestamp_and_expiration(CERT_E_EXPIRED, False, cert_expired=True)
        self.assertEqual(r3["expiration_status"], "EXPIRED_NO_TRUSTED_TIMESTAMP")
        self.assertEqual(r3["timestamp_status"], "MISSING")

        # 4. Expired cert when timestamp presence could not be inspected
        r4 = WindowsSignatureIntelligence._classify_timestamp_and_expiration(CERT_E_EXPIRED, None, cert_expired=True)
        self.assertEqual(r4["expiration_status"], "EXPIRED_TIMESTAMP_UNKNOWN")
        self.assertEqual(r4["timestamp_status"], "UNKNOWN")

        # 5. Invalid timestamp
        r5 = WindowsSignatureIntelligence._classify_timestamp_and_expiration(TRUST_E_TIME_STAMP, True, cert_expired=False)
        self.assertEqual(r5["timestamp_status"], "INVALID")
        self.assertEqual(r5["expiration_status"], "INVALID_TIMESTAMP")

        # 6. Missing timestamp on valid current cert
        r6 = WindowsSignatureIntelligence._classify_timestamp_and_expiration(ERROR_SUCCESS, False, cert_expired=False)
        self.assertEqual(r6["timestamp_status"], "MISSING")
        self.assertEqual(r6["expiration_status"], "VALID_CURRENT")

        # 7. Certificate chain trust failure
        r7 = WindowsSignatureIntelligence._classify_timestamp_and_expiration(CERT_E_UNTRUSTEDROOT, True, cert_expired=False)
        self.assertEqual(r7["expiration_status"], "CHAIN_TRUST_FAILURE")


class TestNeonEvolutionA6AndWorkstreamBSubprocess(unittest.TestCase):
    """A6 & Workstream B: Real Linux streaming subprocess bounds, status accuracy, and command_engine integration."""

    def test_a6_streaming_stdout_limit_enforced_during_collection(self):
        from security.safe_subprocess import SafeSubprocessBroker

        # Emit 500 KB of stdout with a 4096-byte cap
        res = SafeSubprocessBroker.run_bounded_process(
            [sys.executable, "-c", "import sys; sys.stdout.write('A' * 512000); sys.stdout.flush()"],
            timeout=5.0,
            max_stdout_bytes=4096,
            max_stderr_bytes=4096,
        )
        self.assertEqual(res["status"], "output_limit_exceeded")
        self.assertTrue(res["stdout_truncated"])
        self.assertTrue(res["output_limit_exceeded"])
        self.assertLess(len(res["stdout"]), 4300)

    def test_a6_streaming_stderr_limit_enforced_during_collection(self):
        from security.safe_subprocess import SafeSubprocessBroker

        res = SafeSubprocessBroker.run_bounded_process(
            [sys.executable, "-c", "import sys; sys.stderr.write('E' * 256000); sys.stderr.flush()"],
            timeout=5.0,
            max_stdout_bytes=4096,
            max_stderr_bytes=2048,
        )
        self.assertEqual(res["status"], "output_limit_exceeded")
        self.assertTrue(res["stderr_truncated"])
        self.assertLess(len(res["stderr"]), 2300)

    def test_a6_nonzero_exit_never_reports_success_and_preserves_stderr(self):
        from security.safe_subprocess import SafeSubprocessBroker

        res = SafeSubprocessBroker.run_bounded_process(
            [sys.executable, "-c", "import sys; print('partial_out'); print('err_detail', file=sys.stderr); sys.exit(7)"],
            timeout=5.0,
        )
        self.assertEqual(res["status"], "nonzero_exit")
        self.assertEqual(res["exit_code"], 7)
        self.assertIn("partial_out", res["stdout"])
        self.assertIn("err_detail", res["stderr"])

    def test_a6_timeout_kills_child_process_deterministically(self):
        from security.safe_subprocess import SafeSubprocessBroker

        res = SafeSubprocessBroker.run_bounded_process(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout=0.3,
        )
        self.assertEqual(res["status"], "timeout")
        self.assertTrue(res["timed_out"])

    def test_workstream_b_cmd_executor_rejects_nonzero_exit_with_stdout(self):
        from windows_intelligence.command_engine.cmd_executor import CommandExecutor

        fake_run = {
            "status": "nonzero_exit",
            "exit_code": 1,
            "stdout": "ERROR: Invalid parameter\n",
            "stderr": "Access is denied.",
            "stdout_truncated": False,
            "stderr_truncated": False,
            "error": "Access is denied.",
        }
        with mock.patch("sys.platform", "win32"), \
             mock.patch("windows_intelligence.command_engine.command_catalog.CommandCatalog.resolve_executable_path", return_value=r"C:\Windows\System32\cmd.exe"), \
             mock.patch("security.safe_subprocess.SafeSubprocessBroker.run_bounded_process", return_value=fake_run):
            res = CommandExecutor.execute("os_ver", current_build=22621)

        self.assertEqual(res["status"], "error")
        self.assertEqual(res["subprocess_status"], "nonzero_exit")
        self.assertEqual(res["exit_code"], 1)

    def test_workstream_b_powershell_executor_handles_output_limit_exceeded(self):
        from windows_intelligence.command_engine.powershell_executor import PowerShellExecutor

        fake_run = {
            "status": "output_limit_exceeded",
            "exit_code": -9,
            "stdout": "[truncated]",
            "stderr": "",
            "stdout_truncated": True,
            "stderr_truncated": False,
            "output_limit_exceeded": True,
            "error": "Command output exceeded safety limit",
        }
        with mock.patch("os.name", "nt"), \
             mock.patch("os.path.isfile", return_value=True), \
             mock.patch("security.safe_subprocess.SafeSubprocessBroker.run_bounded_process", return_value=fake_run):
            res = PowerShellExecutor.query("cim_os")

        self.assertEqual(res["status"], "error")
        self.assertEqual(res["subprocess_status"], "output_limit_exceeded")
        self.assertTrue(res["is_truncated"])


if __name__ == "__main__":
    unittest.main()
