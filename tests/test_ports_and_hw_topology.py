# -*- coding: utf-8 -*-
"""
Tests for Bintra Hardware Introspection, Port Diagnostics, and Bus Topology:
1. PortInspector (Serial COM, Parallel LPT, and USB UART bridges).
2. NativeDeviceInspector (Bus hierarchy tree, Mermaid diagram, and read-only storage IOCTL).
3. ETW hardware payload decoders and diagnostic providers.
4. MCP Server tool registrations (bintra_port_audit, bintra_hardware_topology).
"""

import os
import sys
import unittest
from pathlib import Path

# Ensure src is on sys.path
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from windows_intelligence.system_introspection.port_inspector import PortInspector
from windows_intelligence.system_introspection.device_inspector import NativeDeviceInspector
from windows_intelligence.device_intelligence.device_identity import DeviceIdentity
from windows_intelligence.runtime_telemetry.etw_capture_engine import EtwLiveCaptureSession
from windows_intelligence.runtime_telemetry.etw_controller import EtwController
import mcp_server


class TestPortsAndHardwareTopology(unittest.TestCase):
    """Authoritative validation for Bintra port inspection, bus topology, and hardware ETW."""

    def test_port_inspector_structure_and_degradation(self):
        """Validates PortInspector returns valid contract and gracefully degrades if non-Windows."""
        serial_rep = PortInspector.audit_serial_ports()
        self.assertIn("status", serial_rep)
        self.assertIn("ports", serial_rep)

        par_rep = PortInspector.audit_parallel_ports()
        self.assertIn("status", par_rep)
        self.assertIn("ports", par_rep)

        all_rep = PortInspector.audit_all_ports()
        self.assertIn("status", all_rep)
        self.assertIn("serial_ports", all_rep)
        self.assertIn("parallel_ports", all_rep)

    def test_usb_serial_bridge_vendor_identification(self):
        """Validates matching of known USB-to-UART bridge hardware IDs (FTDI, CH340, CP210x, PL2303)."""
        test_cases = [
            ("USB\\VID_0403&PID_6001\\FT123456", "FTDI", "FTDI FT232R USB-to-UART Bridge"),
            ("USB\\VID_1A86&PID_7523\\5&6789", "QinHeng", "QinHeng CH340 / CH340G USB-to-Serial"),
            ("USB\\VID_10C4&PID_EA60\\0001", "Silicon Laboratories", "Silicon Labs CP2102/CP2103/CP2104 USB-to-UART Bridge"),
            ("USB\\VID_067B&PID_2303\\1234", "Prolific Technology", "Prolific PL2303 USB-to-Serial Bridge"),
            ("USB\\VID_303A&PID_1001\\ESP32", "Espressif", "Espressif ESP32-C3/S3 Built-in USB JTAG/Serial"),
            ("USB\\VID_2E8A&PID_000A\\RP2040", "Raspberry Pi", "Raspberry Pi Pico RP2040 USB CDC Serial"),
        ]
        for hw_id, expected_mfr_substr, expected_ctrl in test_cases:
            match = DeviceIdentity.parse_device_instance(hw_id)
            self.assertIn(expected_mfr_substr, match["vendor_name"])
            self.assertEqual(match["serial_bridge_model"], expected_ctrl)

    def test_device_topology_generation_formats(self):
        """Validates hierarchical PnP bus topology generation across json, tree, and mermaid formats."""
        # 1. JSON format
        res_json = NativeDeviceInspector.build_device_topology(max_devices=50, format="json")
        self.assertIn("status", res_json)
        self.assertIn("roots", res_json)
        self.assertEqual(res_json.get("format"), "json")

        # 2. Indented ASCII tree format
        res_tree = NativeDeviceInspector.build_device_topology(max_devices=50, format="tree")
        self.assertIn("status", res_tree)
        self.assertIn("rendered", res_tree)
        self.assertEqual(res_tree.get("format"), "tree")
        if res_tree.get("status") == "success" and res_tree.get("total_nodes", 0) > 0:
            self.assertTrue("── " in res_tree["rendered"] or len(res_tree["rendered"]) > 0)

        # 3. Mermaid graph TD format
        res_mermaid = NativeDeviceInspector.build_device_topology(max_devices=50, format="mermaid")
        self.assertIn("status", res_mermaid)
        self.assertIn("rendered", res_mermaid)
        self.assertEqual(res_mermaid.get("format"), "mermaid")
        if res_mermaid.get("status") == "success" and res_mermaid.get("total_nodes", 0) > 0:
            self.assertTrue(res_mermaid["rendered"].startswith("graph TD"))

    def test_device_topology_bus_filter(self):
        """Validates bus-specific filtering on device topology (e.g. USB or PCI)."""
        res_usb = NativeDeviceInspector.build_device_topology(max_devices=100, bus_filter="USB", format="tree")
        self.assertIn("status", res_usb)
        if res_usb.get("status") == "success" and res_usb.get("total_nodes", 0) > 0:
            self.assertIn("USB", res_usb["rendered"].upper())

    def test_storage_device_inspection(self):
        """Validates non-destructive, read-only storage device inspection contract."""
        storage_rep = NativeDeviceInspector.audit_storage_devices(max_drives=4)
        self.assertIn("status", storage_rep)
        self.assertIn("physical_drives", storage_rep)
        self.assertIn("logical_volumes", storage_rep)
        self.assertIn("summary", storage_rep)

        if storage_rep["status"] == "success" and storage_rep["physical_drives"]:
            drive0 = storage_rep["physical_drives"][0]
            self.assertIn("bus_type", drive0)
            self.assertIn("product_id", drive0)
            self.assertIn("device_path", drive0)

    def test_etw_payload_decoding_and_hardware_providers(self):
        """Validates ETW payload decoding and inclusion of hardware diagnostic providers."""
        # Check providers in EtwController catalog
        providers = EtwController.CATALOG_DIAGNOSTIC_PROVIDERS
        self.assertIn("Microsoft-Windows-Kernel-PnP", providers)
        self.assertIn("Microsoft-Windows-USB-USBHUB3", providers)
        self.assertIn("Microsoft-Windows-USB-UCX", providers)
        self.assertIn("Microsoft-Windows-Kernel-Disk", providers)

        # Check payload string decoding
        raw_utf16 = "C:\\Windows\\System32\\drivers\\test.sys\x00".encode("utf-16le")
        decoded_info = EtwLiveCaptureSession.decode_raw_payload(raw_utf16)
        self.assertTrue(decoded_info.get("decoded"))
        self.assertIn("target_module", decoded_info)
        self.assertIn("test.sys", decoded_info["target_module"])

        raw_ascii = b"USB\\VID_0403&PID_6001\\1234\x00"
        decoded_ascii = EtwLiveCaptureSession.decode_raw_payload(raw_ascii)
        self.assertTrue(decoded_ascii.get("decoded"))
        self.assertIn("hardware_id", decoded_ascii)
        self.assertIn("VID_0403", decoded_ascii["hardware_id"])

    def test_mcp_port_and_topology_tools_dispatch(self):
        """Validates MCP registration and dispatch for bintra_port_audit and bintra_hardware_topology."""
        server = mcp_server.BintraMcpServer()

        # Check tool registration
        tool_names = [t["name"] for t in mcp_server.TOOLS_REGISTRY]
        self.assertIn("bintra_port_audit", tool_names)
        self.assertIn("bintra_hardware_topology", tool_names)

        # Call bintra_port_audit
        port_res = server.dispatch_tool("bintra_port_audit", {"port_type": "all"})
        self.assertIsInstance(port_res, dict)
        self.assertIn("status", port_res)

        # Call bintra_hardware_topology
        topo_res = server.dispatch_tool("bintra_hardware_topology", {"format": "tree", "max_devices": 20})
        self.assertIsInstance(topo_res, dict)
        self.assertIn("status", topo_res)


if __name__ == "__main__":
    unittest.main()
