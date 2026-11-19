# -*- coding: utf-8 -*-
"""
Tests for WindowsSignatureIntelligence and Windows File Signature Verification.
Validates:
1. Pure Python ASN.1 DER fallback parsing and string extraction across platforms.
2. Unsigned binary detection and error classification.
3. Semantic separation: signature_present vs is_verified (SIGNATURE_PRESENT_UNVERIFIED).
4. Malformed and corrupted PE header resilience (bounded I/O, OOB offsets).
5. Post-signing tampered binary detection (TRUST_E_BAD_DIGEST -> TAMPERED).
6. Live Win32 WinVerifyTrust embedded Authenticode signature verification.
7. Live Win32 WINTRUST_CATALOG_INFO Security Catalog atomic verification.
8. Live Windows Driver (.sys) verification and Device Manager correlation.
9. Directory batch auditing with explicit error/corrupt tracking and summary metrics.
10. Security Capability Registry compliance.
11. CLI sig-verify and sig-audit command dispatch and JSON output.
12. MCP Server bintra_inspect_binary tool enrichment with security_authenticode.
"""

import os
import sys
import shutil
import struct
import tempfile
import unittest
import json
from unittest.mock import patch, MagicMock

# Ensure src is on sys.path
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from windows_intelligence.signature_intelligence import WindowsSignatureIntelligence
from security.capability_registry import CapabilityRegistry, Capability


class TestWindowsSignatureIntelligence(unittest.TestCase):

    def setUp(self):
        self.sig_intel = WindowsSignatureIntelligence()

    def test_capability_registry_registration(self):
        """Verify signature_intelligence component capabilities are registered."""
        caps = CapabilityRegistry.COMPONENT_CAPABILITIES.get("signature_intelligence")
        self.assertIsNotNone(caps)
        self.assertIn(Capability.FILE_READ, caps)
        self.assertIn(Capability.DRIVER_QUERY, caps)
        self.assertIn(Capability.DEVICE_QUERY, caps)

    def test_nonexistent_file(self):
        """Verify handling of nonexistent file raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            self.sig_intel.verify_file("C:\\nonexistent_dummy_file_12345.exe")

    def test_unsigned_file(self):
        """Verify handling of an unsigned binary/file."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"MZ\x90\x00" + b"\x00" * 512)
            tmp_path = f.name

        try:
            res = self.sig_intel.verify_file(tmp_path)
            self.assertFalse(res["is_signed"])
            self.assertFalse(res["is_verified"])
            self.assertEqual(res["trust_status"], "UNSIGNED")
            self.assertEqual(res["signature_type"], "NONE")
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_pure_python_asn1_extraction(self):
        """Verify pure Python ASN.1 DER parser extracts strings correctly."""
        synthetic_der = (
            b"\x30\x20"
            b"\x13\x0cDigiCert Inc"
            b"\x0c\x0eMicrosoft Corp"
        )
        strings = self.sig_intel._extract_asn1_strings(synthetic_der)
        self.assertTrue(any("DigiCert" in s for s in strings))
        self.assertTrue(any("Microsoft" in s for s in strings))

    def test_pure_python_fallback_parsing_unsigned(self):
        """Verify _verify_pure_python_fallback on dummy file without PE security directory."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"MZ" + b"\x00" * 200)
            tmp_path = f.name

        try:
            res = self.sig_intel._verify_pure_python_fallback(tmp_path)
            self.assertFalse(res["is_signed"])
            self.assertFalse(res["is_verified"])
            self.assertEqual(res["trust_status"], "UNSIGNED")
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_pure_python_fallback_semantic_honesty(self):
        """Verify that pure Python fallback classifies parsed certificates as SIGNATURE_PRESENT_UNVERIFIED."""
        # Create a synthetic PE containing a certificate table
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)
            pe = b"PE\x00\x00"
            coff = b"\x64\x86\x01\x00" + b"\x00" * 16
            opt_standard = struct.pack("<H", 0x20B) + b"\x00" * 22
            opt_windows = b"\x00" * 88
            dd_0_3 = b"\x00" * 32
            # Security Directory: file offset 512, size 64
            dd_sec = struct.pack("<II", 512, 64)
            header = dos + pe + coff + opt_standard + opt_windows + dd_0_3 + dd_sec
            header += b"\x00" * (512 - len(header))
            # WIN_CERTIFICATE: dwLength=64, wRevision=0x0200, wCertificateType=0x0002 (PKCS#7)
            # ASN.1 payload containing "DigiCert"
            asn1_data = b"\x30\x10\x13\x0cDigiCert Inc\x00\x00"
            win_cert = struct.pack("<IHH", 8 + len(asn1_data), 0x0200, 0x0002) + asn1_data
            win_cert += b"\x00" * (64 - len(win_cert))
            f.write(header + win_cert)
            tmp_path = f.name

        try:
            res = self.sig_intel._verify_pure_python_fallback(tmp_path)
            self.assertTrue(res["signature_present"])
            self.assertTrue(res["is_signed"])
            self.assertFalse(res["is_verified"])
            self.assertEqual(res["trust_status"], "SIGNATURE_PRESENT_UNVERIFIED")
            self.assertEqual(res["signature_type"], "EMBEDDED_AUTHENTICODE")
            self.assertIn("DigiCert Inc", res["signers_detected"])
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_malformed_pe_out_of_bounds_pe_offset(self):
        """Verify that out-of-bounds pe_offset is gracefully trapped as CORRUPTED_OR_MALFORMED_PE."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            data = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0xFFFFFFFF) + b"\x00" * 100
            f.write(data)
            tmp_path = f.name

        try:
            res = self.sig_intel._verify_pure_python_fallback(tmp_path)
            self.assertFalse(res["is_verified"])
            self.assertEqual(res["trust_status"], "CORRUPTED_OR_MALFORMED_PE")
            self.assertIn("Invalid PE header offset", res.get("error", ""))
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_malformed_pe_security_directory_out_of_bounds(self):
        """Verify that out-of-bounds security directory offset is trapped as CORRUPTED_OR_MALFORMED_PE."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)
            pe = b"PE\x00\x00"
            coff = b"\x64\x86\x01\x00" + b"\x00" * 16
            opt_standard = struct.pack("<H", 0x20B) + b"\x00" * 22
            opt_windows = b"\x00" * 88
            dd_0_3 = b"\x00" * 32
            # Security Directory offset 0x800000 exceeds file size
            dd_sec = struct.pack("<II", 0x800000, 0x1000)
            pe_total = dos + pe + coff + opt_standard + opt_windows + dd_0_3 + dd_sec + b"\x00" * 1024
            f.write(pe_total)
            tmp_path = f.name

        try:
            res = self.sig_intel._verify_pure_python_fallback(tmp_path)
            self.assertFalse(res["is_verified"])
            self.assertEqual(res["trust_status"], "CORRUPTED_OR_MALFORMED_PE")
            self.assertIn("exceeds file length", res.get("error", ""))
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_audit_directory_temp(self):
        """Verify audit_directory over a folder of files."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            file1 = os.path.join(tmp_dir, "test1.exe")
            file2 = os.path.join(tmp_dir, "test2.dll")
            with open(file1, "wb") as f:
                f.write(b"MZ\x90\x00" + b"\x00" * 512)
            with open(file2, "wb") as f:
                f.write(b"MZ\x90\x00" + b"\x00" * 512)

            audit = self.sig_intel.audit_directory(tmp_dir, pattern="*.*", recursive=False)
            self.assertEqual(audit["status"], "ok")
            self.assertEqual(audit["metrics"]["total_scanned"], 2)
            self.assertEqual(audit["metrics"]["unsigned"], 2)
            self.assertEqual(audit["metrics"]["trusted_embedded"], 0)
            self.assertEqual(audit["metrics"]["trusted_catalog"], 0)
            self.assertEqual(audit["metrics"]["scan_errors"], 0)
            self.assertEqual(len(audit["files"]), 2)
            self.assertEqual(len(audit["errors"]), 0)

    def test_audit_directory_tracks_malformed_errors(self):
        """Verify that audit_directory reports corrupted PE files in metrics and errors list."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_clean = os.path.join(tmp_dir, "clean.exe")
            file_corrupt = os.path.join(tmp_dir, "corrupt.exe")
            with open(file_clean, "wb") as f:
                f.write(b"MZ" + b"\x00" * 100)
            # Create corrupted file with invalid PE offset
            with open(file_corrupt, "wb") as f:
                f.write(b"MZ" + b"\x00" * 58 + struct.pack("<I", 0xFFFFFFFF) + b"\x00" * 50)

            original_verify = WindowsSignatureIntelligence.verify_file

            def mock_verify(path, check_catalog=True, verify_revocation=False):
                if "corrupt.exe" in path:
                    raise IOError("Simulated corrupted I/O disk sector failure")
                return original_verify(path, check_catalog=check_catalog, verify_revocation=verify_revocation)

            with patch.object(WindowsSignatureIntelligence, "verify_file", side_effect=mock_verify):
                audit = WindowsSignatureIntelligence.audit_directory(tmp_dir, pattern="*.exe", recursive=False)
                self.assertEqual(audit["status"], "completed_with_errors")
                self.assertEqual(audit["metrics"]["total_scanned"], 2)
                self.assertEqual(audit["metrics"]["scan_errors"], 1)
                self.assertEqual(len(audit["errors"]), 1)
                self.assertIn("corrupt.exe", audit["errors"][0]["file_name"])

    def test_verify_driver_dummy(self):
        """Verify verify_driver returns clean schema and device correlation on dummy driver."""
        with tempfile.NamedTemporaryFile(suffix=".sys", delete=False) as f:
            f.write(b"MZ\x90\x00" + b"\x00" * 512)
            dummy_path = f.name

        try:
            res = self.sig_intel.verify_driver(dummy_path)
            self.assertFalse(res["is_signed"])
            self.assertTrue(res["is_driver"])
            self.assertIn("device_correlation", res)
            self.assertEqual(res["device_correlation"]["driver_name"], os.path.basename(dummy_path).lower())
        finally:
            if os.path.exists(dummy_path):
                os.unlink(dummy_path)

    @unittest.skipUnless(os.name == "nt", "Live Win32 Authenticode tests require Windows NT")
    def test_live_win32_embedded_authenticode(self):
        """Verify live Windows embedded Authenticode verification on sys.executable."""
        res = self.sig_intel.verify_file(sys.executable, check_catalog=True)
        self.assertIn(res["trust_status"], ["TRUSTED", "UNSIGNED"])
        if res["is_signed"]:
            self.assertTrue(res["is_verified"])
            self.assertEqual(res["signature_type"], "EMBEDDED_AUTHENTICODE")
            self.assertGreater(len(res["certificate_chain"]), 0)
            subject = res["certificate_chain"][0].get("subject", "")
            self.assertTrue(len(subject) > 0)

    @unittest.skipUnless(os.name == "nt", "Live Win32 tampered binary test requires Windows NT")
    def test_live_win32_tampered_binary_detection(self):
        """Verify that altering 1 byte of a signed PE binary triggers TRUST_E_BAD_DIGEST (TAMPERED)."""
        # Find a small signed Windows binary or sys.executable
        candidate = sys.executable
        orig = self.sig_intel.verify_file(candidate, check_catalog=True)
        if not orig.get("is_verified") or orig.get("signature_type") != "EMBEDDED_AUTHENTICODE":
            self.skipTest("sys.executable is not embedded-signed on this environment")

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            tmp_path = f.name

        try:
            shutil.copyfile(candidate, tmp_path)
            # Verify copy before mutation
            pre_rep = self.sig_intel.verify_file(tmp_path, check_catalog=False)
            self.assertTrue(pre_rep["is_verified"])
            self.assertEqual(pre_rep["trust_status"], "TRUSTED")

            # Tamper 1 byte at offset 0x200
            with open(tmp_path, "r+b") as f:
                f.seek(0x200)
                byte = f.read(1)
                f.seek(0x200)
                f.write(bytes([byte[0] ^ 0xFF]))

            # Post-tamper verification
            tampered_rep = self.sig_intel.verify_file(tmp_path, check_catalog=False)
            self.assertFalse(tampered_rep["is_verified"])
            self.assertTrue(tampered_rep["is_signed"])
            self.assertEqual(tampered_rep["trust_status"], "TAMPERED")
            self.assertEqual(tampered_rep["win32_status_code"], "0x80096010")  # TRUST_E_BAD_DIGEST
            self.assertIn("BINARY_HASH_MISMATCH_TAMPERED", tampered_rep["risk_flags"])
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    @unittest.skipUnless(os.name == "nt", "Live Win32 Security Catalog tests require Windows NT")
    def test_live_win32_catalog_verification(self):
        """Strictly verify live Windows Security Catalog resolution and atomic WINTRUST_CATALOG_INFO verification."""
        candidates = [
            r"C:\Windows\System32\notepad.exe",
            r"C:\Windows\System32\drivers\1394ohci.sys",
            r"C:\Windows\System32\drivers\AcpiDev.sys"
        ]
        target = None
        for cand in candidates:
            if os.path.exists(cand):
                target = cand
                break

        if not target:
            self.skipTest("No catalog candidate found on system")

        res = self.sig_intel.verify_file(target, check_catalog=True)
        # Strict assertions: Must be verified via Security Catalog with valid .cat file
        self.assertTrue(res["found_in_catalog"])
        self.assertTrue(res["signature_present"])
        self.assertTrue(res["is_signed"])
        self.assertTrue(res["is_verified"])
        self.assertEqual(res["signature_type"], "SECURITY_CATALOG")
        self.assertEqual(res["trust_status"], "TRUSTED")
        self.assertEqual(res["win32_status_code"], "0x0")
        self.assertIsNotNone(res["catalog_file"])
        self.assertTrue(res["catalog_file"].lower().endswith(".cat"))
        self.assertTrue(len(res["catalog_member_hash"]) > 0)
        self.assertTrue(res["is_microsoft_system_binary"])

    @unittest.skipUnless(os.name == "nt", "Live Win32 driver verification requires Windows NT")
    def test_live_win32_driver_verification(self):
        """Verify live Windows kernel driver verification on acpi.sys."""
        acpi_path = r"C:\Windows\System32\drivers\acpi.sys"
        if not os.path.exists(acpi_path):
            self.skipTest("acpi.sys not found")

        res = self.sig_intel.verify_driver(acpi_path)
        self.assertTrue(res["is_signed"])
        self.assertTrue(res["is_verified"])
        self.assertEqual(res["trust_status"], "TRUSTED")
        self.assertIn(res["signature_type"], ["EMBEDDED_AUTHENTICODE", "SECURITY_CATALOG"])
        self.assertIn("device_correlation", res)
        self.assertEqual(res["device_correlation"]["driver_name"], "acpi.sys")

    @unittest.skipUnless(os.name == "nt", "Live Win32 driver audit requires Windows NT")
    def test_live_win32_driver_audit_sample(self):
        """Audit drivers in System32\\drivers and strictly assert presence of verified trusted drivers."""
        drivers_dir = r"C:\Windows\System32\drivers"
        if not os.path.exists(drivers_dir):
            self.skipTest("drivers directory not found")

        audit = self.sig_intel.audit_directory(drivers_dir, pattern="*.sys", max_files=15)
        self.assertEqual(audit["metrics"]["total_scanned"], 15)
        # Strictly verify that at least one driver is cryptographically trusted
        trusted_count = audit["metrics"]["trusted_embedded"] + audit["metrics"]["trusted_catalog"]
        self.assertGreater(trusted_count, 0, "Host drivers audit must identify at least one verified trusted driver")
        self.assertEqual(len(audit["files"]), 15)

    def test_cli_sig_commands_registered(self):
        """Verify sig-verify and sig-audit are in WIN_INTEL_COMMANDS."""
        from cli import WIN_INTEL_COMMANDS
        self.assertIn("sig-verify", WIN_INTEL_COMMANDS)
        self.assertIn("sig-audit", WIN_INTEL_COMMANDS)

    def test_cli_sig_verify_dispatch(self):
        """Test CLI command sig-verify dispatch."""
        from cli import main as cli_main
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            with patch("sys.argv", ["bintra", "sig-verify", sys.executable, "--format", "json"]):
                try:
                    cli_main()
                except SystemExit:
                    pass
        output = f.getvalue().strip()
        self.assertTrue(len(output) > 0)
        parsed = json.loads(output)
        self.assertIn("is_signed", parsed)
        self.assertIn("trust_status", parsed)

    def test_cli_sig_audit_dispatch(self):
        """Test CLI command sig-audit dispatch."""
        from cli import main as cli_main
        import io
        from contextlib import redirect_stdout

        with tempfile.TemporaryDirectory() as tmp_dir:
            file1 = os.path.join(tmp_dir, "test1.sys")
            with open(file1, "wb") as f:
                f.write(b"MZ\x90\x00" + b"\x00" * 512)

            f = io.StringIO()
            with redirect_stdout(f):
                with patch("sys.argv", ["bintra", "sig-audit", tmp_dir, "--limit", "2", "--format", "json"]):
                    try:
                        cli_main()
                    except SystemExit:
                        pass
            output = f.getvalue().strip()
            self.assertTrue(len(output) > 0)
            parsed = json.loads(output)
            self.assertIn("metrics", parsed)
            self.assertEqual(parsed["metrics"]["total_scanned"], 1)

    def test_mcp_bintra_inspect_binary_enrichment(self):
        """Verify bintra_inspect_binary enriches security_authenticode."""
        from mcp_server import BintraMcpServer

        server = BintraMcpServer()
        res = server.dispatch_tool("bintra_inspect_binary", {"file_path": sys.executable})
        self.assertIn("security_authenticode", res)
        sec = res["security_authenticode"]
        self.assertIn("is_signed", sec)
        self.assertIn("trust_status", sec)
        self.assertIn("signature_type", sec)


if __name__ == "__main__":
    unittest.main()
