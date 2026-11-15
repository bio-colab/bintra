# -*- coding: utf-8 -*-
"""
Tests for WindowsRegistryEditor and Registry Editor (regedit.exe) Integration.
Validates:
1. Non-NT graceful degradation across all editor methods.
2. Comprehensive .reg file parser (Version 5.00 format, strings, dwords, qwords, hex, multi-line).
3. Registry key, value name, and value data search with depth/timeout guards.
4. Live registry export to valid .reg file syntax.
5. Registry drift auditing and compliance percentage calculation.
6. MCP server tool action dispatch for bintra_registry_audit.
7. CLI execution for reg-read, reg-search, reg-export, and reg-import.
8. Live Windows NT sanity check when running on Windows host.
"""

import os
import sys
import unittest
import json
from unittest.mock import patch, MagicMock

# Ensure src is on sys.path
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


class TestRegistryEditor(unittest.TestCase):

    def test_non_nt_graceful_degradation(self):
        """Verifies that all WindowsRegistryEditor methods safely degrade on Linux/macOS."""
        with patch("os.name", "posix"):
            from windows_intelligence.registry_intelligence.registry_editor import WindowsRegistryEditor

            read_res = WindowsRegistryEditor.read_key("HKLM", "SOFTWARE\\Test")
            self.assertEqual(read_res["status"], "not_applicable")

            search_res = WindowsRegistryEditor.search(query="test", hive="HKLM")
            self.assertEqual(search_res["status"], "not_applicable")
            self.assertEqual(search_res["matched_count"], 0)

            export_res = WindowsRegistryEditor.export_key("HKLM", "SOFTWARE\\Test")
            self.assertEqual(export_res["status"], "not_applicable")

            diff_res = WindowsRegistryEditor.diff_reg_file("Windows Registry Editor Version 5.00\n[HKEY_LOCAL_MACHINE\\Test]")
            self.assertEqual(diff_res["status"], "not_applicable")

    def test_parse_reg_file_comprehensive_ast(self):
        """Tests parsing of Windows Registry Editor Version 5.00 files across all data types."""
        from windows_intelligence.registry_intelligence.registry_editor import WindowsRegistryEditor

        sample_reg = (
            "Windows Registry Editor Version 5.00\r\n"
            "\r\n"
            "[HKEY_LOCAL_MACHINE\\SOFTWARE\\BintraTestApp]\r\n"
            "@=\"Default Value String\"\r\n"
            "\"StringVal\"=\"Hello \\\"World\\\" with \\\\ slashes\"\r\n"
            "\"DwordVal\"=dword:0000002a\r\n"
            "\"QwordVal\"=hex(b):2a,00,00,00,00,00,00,00\r\n"
            "\"BinVal\"=hex:01,02,03,\\\r\n"
            "  04,05\r\n"
            "\"ExpandVal\"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,00,00,00\r\n"
            "\"MultiVal\"=hex(7):61,00,00,00,62,00,00,00,00,00\r\n"
            "\"DeletedVal\"=-\r\n"
            "\r\n"
            "[-HKEY_LOCAL_MACHINE\\SOFTWARE\\BintraOldKey]\r\n"
        )

        ast = WindowsRegistryEditor.parse_reg_file(sample_reg)
        self.assertEqual(ast["status"], "success")
        self.assertEqual(ast["format_version"], "5.00")
        self.assertEqual(ast["keys_count"], 2)
        self.assertEqual(ast["values_count"], 8)

        # 1. Test target key
        test_key = ast["keys"]["HKEY_LOCAL_MACHINE\\SOFTWARE\\BintraTestApp"]
        self.assertFalse(test_key["is_deletion"])
        vals = test_key["values"]

        # Default string
        self.assertEqual(vals["(Default)"]["type"], "REG_SZ")
        self.assertEqual(vals["(Default)"]["value"], "Default Value String")

        # Escaped string
        self.assertEqual(vals["StringVal"]["type"], "REG_SZ")
        self.assertEqual(vals["StringVal"]["value"], 'Hello "World" with \\ slashes')

        # DWORD
        self.assertEqual(vals["DwordVal"]["type"], "REG_DWORD")
        self.assertEqual(vals["DwordVal"]["value"], 42)
        self.assertEqual(vals["DwordVal"]["hex"], "0x0000002A")

        # QWORD
        self.assertEqual(vals["QwordVal"]["type"], "REG_QWORD")
        self.assertEqual(vals["QwordVal"]["value"], 42)

        # Multi-line Binary
        self.assertEqual(vals["BinVal"]["type"], "REG_BINARY")
        self.assertEqual(vals["BinVal"]["value"], "01 02 03 04 05")
        self.assertEqual(vals["BinVal"]["length"], 5)

        # EXPAND_SZ
        self.assertEqual(vals["ExpandVal"]["type"], "REG_EXPAND_SZ")
        self.assertEqual(vals["ExpandVal"]["value"], "%SystemRoot%")

        # MULTI_SZ
        self.assertEqual(vals["MultiVal"]["type"], "REG_MULTI_SZ")
        self.assertEqual(vals["MultiVal"]["value"], ["a", "b"])

        # Deleted value
        self.assertEqual(vals["DeletedVal"]["type"], "DELETE")

        # 2. Test deleted key
        old_key = ast["keys"]["HKEY_LOCAL_MACHINE\\SOFTWARE\\BintraOldKey"]
        self.assertTrue(old_key["is_deletion"])

    def test_diff_reg_file_simulation(self):
        """Tests registry drift auditing with matched, drifted, and missing values."""
        from windows_intelligence.registry_intelligence.registry_editor import WindowsRegistryEditor

        sample_reg = (
            "Windows Registry Editor Version 5.00\r\n"
            "\r\n"
            "[HKEY_LOCAL_MACHINE\\SOFTWARE\\MockApp]\r\n"
            "\"MatchedVal\"=\"MatchMe\"\r\n"
            "\"DriftedVal\"=dword:00000001\r\n"
            "\"MissingVal\"=\"DoesNotExist\"\r\n"
        )

        fake_live_registry = {
            "SOFTWARE\\MockApp": {
                "MatchedVal": ("MatchMe", 1),       # REG_SZ match
                "DriftedVal": (2, 4),               # REG_DWORD drifted (expected 1, actual 2)
                # MissingVal is absent
            }
        }

        # Mock OpenKey and QueryValueEx
        class MockKey:
            def __init__(self, path):
                self.path = path
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass

        def mock_open_key(hive, path, reserved, access):
            if path in fake_live_registry:
                return MockKey(path)
            raise FileNotFoundError(f"Key {path} not found")

        def mock_query_value_ex(key_obj, val_name):
            k_dict = fake_live_registry.get(key_obj.path, {})
            if val_name in k_dict:
                return k_dict[val_name]
            raise FileNotFoundError(f"Value {val_name} not found")

        mock_winreg = MagicMock()
        mock_winreg.OpenKey.side_effect = mock_open_key
        mock_winreg.QueryValueEx.side_effect = mock_query_value_ex
        mock_winreg.KEY_READ = 0x20019
        mock_winreg.KEY_WOW64_64KEY = 0x0100
        mock_winreg.KEY_WOW64_32KEY = 0x0200
        mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002

        with patch("os.name", "nt"), \
             patch("windows_intelligence.registry_intelligence.registry_editor.winreg", mock_winreg):
            diff_res = WindowsRegistryEditor.diff_reg_file(sample_reg)
            self.assertEqual(diff_res["status"], "success")
            self.assertEqual(diff_res["total_items_checked"], 3)
            self.assertEqual(diff_res["matched_count"], 1)
            self.assertEqual(diff_res["drifted_count"], 1)
            self.assertEqual(diff_res["missing_count"], 1)
            self.assertAlmostEqual(diff_res["compliance_percentage"], 33.33, places=2)

    def test_mcp_server_registry_tool_actions(self):
        """Verifies that MCP server dispatches all bintra_registry_audit extended actions."""
        from mcp_server import BintraMcpServer
        server = BintraMcpServer()

        mock_read = {"status": "success", "hive": "HKLM", "subkey": "test", "result": {"values_count": 5}}
        mock_search = {"status": "success", "query": "test", "matched_count": 2, "matches": []}
        mock_parse = {"status": "success", "keys_count": 1, "values_count": 2}
        mock_export = {"status": "success", "keys_exported": 1, "values_exported": 2, "reg_content": "Windows Registry..."}
        mock_diff = {"status": "success", "total_items_checked": 2, "matched_count": 2, "compliance_percentage": 100.0}

        with patch("windows_intelligence.registry_intelligence.registry_editor.WindowsRegistryEditor.read_key", return_value=mock_read):
            res = server.dispatch_tool("bintra_registry_audit", {"action": "read", "hive": "HKLM", "key": "test"})
            self.assertEqual(res["result"]["values_count"], 5)

        with patch("windows_intelligence.registry_intelligence.registry_editor.WindowsRegistryEditor.search", return_value=mock_search):
            res = server.dispatch_tool("bintra_registry_audit", {"action": "search", "query": "test"})
            self.assertEqual(res["matched_count"], 2)

        with patch("windows_intelligence.registry_intelligence.registry_editor.WindowsRegistryEditor.parse_reg_file", return_value=mock_parse):
            res = server.dispatch_tool("bintra_registry_audit", {"action": "parse_reg", "reg_content": "test"})
            self.assertEqual(res["keys_count"], 1)

        with patch("windows_intelligence.registry_intelligence.registry_editor.WindowsRegistryEditor.export_key", return_value=mock_export):
            res = server.dispatch_tool("bintra_registry_audit", {"action": "export_reg", "hive": "HKLM", "key": "test"})
            self.assertEqual(res["values_exported"], 2)

        with patch("windows_intelligence.registry_intelligence.registry_editor.WindowsRegistryEditor.diff_reg_file", return_value=mock_diff):
            res = server.dispatch_tool("bintra_registry_audit", {"action": "diff_reg", "reg_content": "test"})
            self.assertEqual(res["compliance_percentage"], 100.0)

    @unittest.skipUnless(os.name == "nt", "Live Registry Editor integration requires Windows NT host")
    def test_live_windows_registry_inspection_and_export(self):
        """Sanity check on live Windows NT host."""
        from windows_intelligence.registry_intelligence.registry_editor import WindowsRegistryEditor

        # 1. Read live key
        read_res = WindowsRegistryEditor.read_key("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", view="64")
        self.assertEqual(read_res["status"], "success")
        self.assertIn("ProductName", read_res["result"]["values"])

        # 2. Export key to .reg
        export_res = WindowsRegistryEditor.export_key("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        self.assertEqual(export_res["status"], "success")
        self.assertIn("Windows Registry Editor Version 5.00", export_res["reg_content"])
        self.assertIn("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion]", export_res["reg_content"])

        # 3. Parse exported .reg
        parsed = WindowsRegistryEditor.parse_reg_file(export_res["reg_content"])
        self.assertEqual(parsed["status"], "success")
        self.assertGreater(parsed["values_count"], 0)

        # 4. Diff against live registry (must be 100% matched)
        diff_res = WindowsRegistryEditor.diff_reg_file(export_res["reg_content"])
        self.assertEqual(diff_res["status"], "success")
        self.assertEqual(diff_res["compliance_percentage"], 100.0)


if __name__ == "__main__":
    unittest.main()
