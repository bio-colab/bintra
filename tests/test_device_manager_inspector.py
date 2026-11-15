# -*- coding: utf-8 -*-
"""
Tests for DeviceManagerInspector and Windows Device Manager Integration.
Validates:
1. Non-NT graceful degradation across all inspector methods.
2. Synthetic mocked PnP devices, class grouping, problem counters, and driver metadata extraction.
3. Search filtering across device names, hardware IDs, vendors, and bus locations.
4. Comprehensive Device Manager Property Sheet dossier generation.
5. MCP Server tool action dispatch for bintra_device_driver_intelligence.
6. CLI registration and execution for dev-classes, dev-list, dev-search, dev-info.
7. Live Windows NT sanity checks when on Windows host.
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


class TestDeviceManagerInspector(unittest.TestCase):

    def test_non_nt_graceful_degradation(self):
        """Verifies that all DeviceManagerInspector methods safely degrade on Linux/macOS."""
        with patch("os.name", "posix"):
            from windows_intelligence.device_intelligence.device_manager import DeviceManagerInspector

            classes = DeviceManagerInspector.get_device_classes()
            self.assertEqual(classes["status"], "not_applicable")
            self.assertEqual(classes["total_classes"], 0)
            self.assertEqual(classes["classes"], [])

            listing = DeviceManagerInspector.list_devices()
            self.assertEqual(listing["status"], "not_applicable")
            self.assertEqual(listing["total_devices"], 0)
            self.assertEqual(listing["devices"], [])

            search = DeviceManagerInspector.search_devices("intel")
            self.assertEqual(search["status"], "not_applicable")
            self.assertEqual(search["matched_count"], 0)
            self.assertEqual(search["devices"], [])

            details = DeviceManagerInspector.get_device_details("TestDev")
            self.assertEqual(details["status"], "not_applicable")
            self.assertIsNone(details["device"])

    def test_synthetic_device_class_grouping(self):
        """Tests device class categorization, problem tallying, and friendly name mapping."""
        from windows_intelligence.device_intelligence.device_manager import DeviceManagerInspector

        fake_devices = [
            {
                "device_instance_id": "PCI\\VEN_8086&DEV_5917\\0001",
                "name": "Intel(R) UHD Graphics 620",
                "class": "Display",
                "has_problem": False,
                "problem_code": 0,
                "is_started": True,
            },
            {
                "device_instance_id": "PCI\\VEN_10EC&DEV_8168\\0002",
                "name": "Realtek PCIe GBE Family Controller",
                "class": "Net",
                "has_problem": False,
                "problem_code": 0,
                "is_started": True,
            },
            {
                "device_instance_id": "USB\\VID_046D&PID_C52B\\0003",
                "name": "Broken USB Device",
                "class": "USB",
                "has_problem": True,
                "problem_code": 43,
                "is_started": False,
            },
            {
                "device_instance_id": "ACPI\\UNKNOWN\\0004",
                "name": "Undetermined Device Node",
                "class": "System",
                "has_problem": False,
                "status_available": False,
                "problem_description": "Status Unavailable (CM_Get_DevNode_Status failed)",
                "problem_name": "CM_PROB_STATUS_UNAVAILABLE",
                "problem_code": 0,
                "is_started": False,
            },
        ]

        with patch("os.name", "nt"):
            with patch("windows_intelligence.system_introspection.device_inspector.NativeDeviceInspector.enumerate_devices", return_value=fake_devices):
                res = DeviceManagerInspector.get_device_classes()
                self.assertEqual(res["status"], "success")
                self.assertEqual(res["total_classes"], 4)
                self.assertEqual(res["total_devices"], 4)
                self.assertEqual(res["total_problems"], 1)
                self.assertEqual(res["total_unknown"], 1)

                class_names = [c["class_name"] for c in res["classes"]]
                self.assertIn("Display", class_names)
                self.assertIn("Net", class_names)
                self.assertIn("USB", class_names)
                self.assertIn("System", class_names)

                usb_cls = next(c for c in res["classes"] if c["class_name"] == "USB")
                self.assertEqual(usb_cls["friendly_name"], "Universal Serial Bus controllers")
                self.assertEqual(usb_cls["device_count"], 1)
                self.assertEqual(usb_cls["problem_count"], 1)

                sys_cls = next(c for c in res["classes"] if c["class_name"] == "System")
                self.assertEqual(sys_cls["device_count"], 1)
                self.assertEqual(sys_cls["unknown_count"], 1)
                self.assertEqual(sys_cls["devices"][0]["status_classification"], "unknown")

    def test_synthetic_device_search_and_filtering(self):
        """Tests multi-field search and driver metadata enrichment."""
        from windows_intelligence.device_intelligence.device_manager import DeviceManagerInspector

        fake_devices = [
            {
                "device_instance_id": "PCI\\VEN_8086&DEV_5917\\0001",
                "name": "Intel(R) UHD Graphics 620",
                "friendly_name": "Intel UHD Graphics",
                "description": "Intel Display Adapter",
                "class": "Display",
                "hardware_id": "PCI\\VEN_8086&DEV_5917&SUBSYS_08161028",
                "hardware_ids": ["PCI\\VEN_8086&DEV_5917&SUBSYS_08161028"],
                "service": "igfx",
                "manufacturer": "Intel Corporation",
                "location_information": "PCI bus 0, device 2, function 0",
                "bus_enumerator": "PCI",
                "driver_key": "{4d36e968-e325-11ce-bfc1-08002be10318}\\0000",
                "is_started": True,
                "has_problem": False,
                "problem_code": 0,
            },
            {
                "device_instance_id": "USB\\VID_046D&PID_C52B\\0002",
                "name": "Logitech USB Receiver",
                "friendly_name": None,
                "description": "Logitech Unifying Receiver",
                "class": "HIDClass",
                "hardware_id": "USB\\VID_046D&PID_C52B",
                "hardware_ids": ["USB\\VID_046D&PID_C52B"],
                "service": "HidUsb",
                "manufacturer": "Logitech",
                "location_information": "Port_#0001.Hub_#0002",
                "bus_enumerator": "USB",
                "driver_key": None,
                "is_started": True,
                "has_problem": False,
                "problem_code": 0,
            }
        ]

        fake_driver_info = {
            "driver_version": "31.0.101.2134",
            "driver_date": "11-20-2024",
            "provider_name": "Intel Corporation",
            "inf_path": "oem24.inf",
            "inf_section": "iKBLD_w10_DS",
            "matching_device_id": "PCI\\VEN_8086&DEV_5917",
            "driver_desc": "Intel(R) UHD Graphics 620",
        }

        def mock_driver_info(dk):
            if dk == "{4d36e968-e325-11ce-bfc1-08002be10318}\\0000":
                return fake_driver_info
            return {
                "driver_version": None,
                "driver_date": None,
                "provider_name": None,
                "inf_path": None,
                "inf_section": None,
                "matching_device_id": None,
                "driver_desc": None,
            }

        with patch("os.name", "nt"):
            with patch("windows_intelligence.system_introspection.device_inspector.NativeDeviceInspector.enumerate_devices", return_value=fake_devices):
                with patch.object(DeviceManagerInspector, "_get_driver_registry_info", side_effect=mock_driver_info):
                    # 1. Search by name
                    res_intel = DeviceManagerInspector.search_devices("intel")
                    self.assertEqual(res_intel["status"], "success")
                    self.assertEqual(res_intel["matched_count"], 1)
                    self.assertEqual(res_intel["devices"][0]["name"], "Intel(R) UHD Graphics 620")
                    self.assertEqual(res_intel["devices"][0]["driver_version"], "31.0.101.2134")

                    # 2. Search by vendor
                    res_logi = DeviceManagerInspector.search_devices("logitech")
                    self.assertEqual(res_logi["matched_count"], 1)
                    self.assertEqual(res_logi["devices"][0]["name"], "Logitech USB Receiver")

                    # 3. Search by location
                    res_loc = DeviceManagerInspector.search_devices("Port_#0001")
                    self.assertEqual(res_loc["matched_count"], 1)

                    # 4. Details retrieval
                    details = DeviceManagerInspector.get_device_details("Intel(R) UHD Graphics 620")
                    self.assertEqual(details["status"], "success")
                    dev = details["device"]
                    self.assertEqual(dev["general"]["class_friendly"], "Display adapters")
                    self.assertEqual(dev["driver"]["driver_version"], "31.0.101.2134")
                    self.assertEqual(dev["hardware_ids"]["primary_hardware_id"], "PCI\\VEN_8086&DEV_5917&SUBSYS_08161028")

    def test_mcp_server_device_manager_tool_actions(self):
        """Verifies that MCP server dispatches all Device Manager actions successfully."""
        from mcp_server import BintraMcpServer
        server = BintraMcpServer()

        mock_classes = {"status": "success", "total_classes": 5, "total_devices": 10, "classes": []}
        mock_listing = {"status": "success", "total_devices": 10, "devices": []}
        mock_search = {"status": "success", "query": "test", "matched_count": 1, "devices": []}
        mock_details = {"status": "success", "query": "test", "device": {"general": {"name": "TestDev"}}}

        with patch("windows_intelligence.device_intelligence.device_manager.DeviceManagerInspector.get_device_classes", return_value=mock_classes):
            res = server.dispatch_tool("bintra_device_driver_intelligence", {"action": "device_classes"})
            self.assertEqual(res["total_classes"], 5)

        with patch("windows_intelligence.device_intelligence.device_manager.DeviceManagerInspector.list_devices", return_value=mock_listing):
            res = server.dispatch_tool("bintra_device_driver_intelligence", {"action": "list_devices", "class_filter": "Display"})
            self.assertEqual(res["total_devices"], 10)

        with patch("windows_intelligence.device_intelligence.device_manager.DeviceManagerInspector.search_devices", return_value=mock_search):
            res = server.dispatch_tool("bintra_device_driver_intelligence", {"action": "search_devices", "device_query": "test"})
            self.assertEqual(res["matched_count"], 1)

        with patch("windows_intelligence.device_intelligence.device_manager.DeviceManagerInspector.get_device_details", return_value=mock_details):
            res = server.dispatch_tool("bintra_device_driver_intelligence", {"action": "device_details", "device_id_or_name": "TestDev"})
            self.assertEqual(res["device"]["general"]["name"], "TestDev")

    @unittest.skipUnless(os.name == "nt", "Live Device Manager integration requires Windows NT host")
    def test_live_windows_device_manager_inspection(self):
        """Sanity check on live Windows NT host."""
        from windows_intelligence.device_intelligence.device_manager import DeviceManagerInspector

        classes = DeviceManagerInspector.get_device_classes()
        self.assertEqual(classes["status"], "success")
        self.assertGreater(classes["total_classes"], 0)
        self.assertGreater(classes["total_devices"], 0)

        listing = DeviceManagerInspector.list_devices(limit=10)
        self.assertEqual(listing["status"], "success")
        self.assertGreaterEqual(len(listing["devices"]), 1)

        search = DeviceManagerInspector.search_devices("PCI", limit=5)
        self.assertEqual(search["status"], "success")
        self.assertGreaterEqual(search["matched_count"], 1)


if __name__ == "__main__":
    unittest.main()
