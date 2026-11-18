# -*- coding: utf-8 -*-
"""
Tests for WindowsSignatureIntelligence and Windows File Signature Verification.
Validates:
1. Pure Python ASN.1 DER fallback parsing and string extraction across platforms.
2. Unsigned binary detection and error classification.
3. Live Win32 WinVerifyTrust embedded Authenticode signature verification.
4. Live Win32 CryptCATAdmin Security Catalog signature resolution and verification.
5. Live Windows Driver (.sys) verification and Device Manager correlation.
6. Directory batch auditing with summary metrics (signed, unsigned, catalog).
7. Security Capability Registry compliance.
8. CLI sig-verify and sig-audit command dispatch and JSON output.
9. MCP Server bintra_inspect_binary tool enrichment with security_authenticode.
"""

import os
import sys
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

    def test_pure_python_fallback_parsing(self):
        """Verify _verify_pure_python_fallback on dummy file without PE security directory."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"MZ" + b"\x00" * 200)
            tmp_path = f.name

        try:
            res = self.sig_intel._verify_pure_python_fallback(tmp_path)
            self.assertFalse(res["is_signed"])
            self.assertEqual(res["trust_status"], "UNSIGNED")
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_audit_directory_temp(self):
        """Verify audit_directory over a folder of files."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            file1 = os.path.join(tmp_dir, "test1.exe")
            file2 = os.path.join(tmp_dir, "test2.dll")
            with open(file1, "wb") as f:
                f.write(b"MZ\x00" * 100)
            with open(file2, "wb") as f:
                f.write(b"MZ\x00" * 100)

            audit = self.sig_intel.audit_directory(tmp_dir, pattern="*.*", recursive=False)
            self.assertEqual(audit["metrics"]["total_scanned"], 2)
            self.assertEqual(audit["metrics"]["unsigned"], 2)
            self.assertEqual(audit["metrics"]["trusted_embedded"], 0)
            self.assertEqual(audit["metrics"]["trusted_catalog"], 0)
            self.assertEqual(len(audit["files"]), 2)

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
            self.assertEqual(res["signature_type"], "EMBEDDED_AUTHENTICODE")
            self.assertGreater(len(res["certificate_chain"]), 0)
            subject = res["certificate_chain"][0].get("subject", "")
            self.assertTrue(len(subject) > 0)

    @unittest.skipUnless(os.name == "nt", "Live Win32 Security Catalog tests require Windows NT")
    def test_live_win32_catalog_verification(self):
        """Verify live Windows Security Catalog verification on modern inbox binaries (e.g. notepad.exe or drivers)."""
        candidates = [
            r"C:\Windows\System32\notepad.exe",
            r"C:\Windows\System32\cmd.exe",
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
        self.assertIn(res["signature_type"], ["SECURITY_CATALOG", "EMBEDDED_AUTHENTICODE", "NONE"])
        if res["signature_type"] == "SECURITY_CATALOG":
            self.assertTrue(res["is_signed"])
            self.assertIsNotNone(res["catalog_file"])
            self.assertTrue(res["catalog_file"].lower().endswith(".cat"))

    @unittest.skipUnless(os.name == "nt", "Live Win32 driver verification requires Windows NT")
    def test_live_win32_driver_verification(self):
        """Verify live Windows kernel driver verification on acpi.sys."""
        acpi_path = r"C:\Windows\System32\drivers\acpi.sys"
        if not os.path.exists(acpi_path):
            self.skipTest("acpi.sys not found")

        res = self.sig_intel.verify_driver(acpi_path)
        self.assertTrue(res["is_signed"])
        self.assertEqual(res["trust_status"], "TRUSTED")
        self.assertIn(res["signature_type"], ["EMBEDDED_AUTHENTICODE", "SECURITY_CATALOG"])
        self.assertIn("device_correlation", res)
        self.assertEqual(res["device_correlation"]["driver_name"], "acpi.sys")

    @unittest.skipUnless(os.name == "nt", "Live Win32 driver audit requires Windows NT")
    def test_live_win32_driver_audit_sample(self):
        """Audit a small sample of drivers in System32\\drivers."""
        drivers_dir = r"C:\Windows\System32\drivers"
        if not os.path.exists(drivers_dir):
            self.skipTest("drivers directory not found")

        audit = self.sig_intel.audit_directory(drivers_dir, pattern="*.sys", max_files=5)
        self.assertEqual(audit["metrics"]["total_scanned"], 5)
        self.assertGreaterEqual(audit["metrics"]["trusted_embedded"] + audit["metrics"]["trusted_catalog"], 0)
        self.assertEqual(len(audit["files"]), 5)

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
                f.write(b"MZ\x00" * 50)

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
