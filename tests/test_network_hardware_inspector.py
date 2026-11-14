# -*- coding: utf-8 -*-
"""
Verification tests for Bintra Network Hardware Intelligence and Deep Driver Reverse Engineering Engine.
Tests:
1. Non-Windows NT platform graceful degradation
2. Network adapter enumeration and telemetry parsing
3. Deep multi-layer device-to-driver dissection (PCIe Bus -> NDIS -> Registry -> SCM -> PE32+ -> KASLR)
4. DriverStore path expansion and driver filename resolution
5. MCP tool registration and capability mapping
6. CLI command registration and arguments parsing
"""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from windows_intelligence.system_introspection.network_inspector import NetworkHardwareInspector


class TestNetworkHardwareInspector(unittest.TestCase):
    def test_non_windows_graceful_degradation(self):
        with patch("os.name", "posix"):
            res = NetworkHardwareInspector.audit_network_adapters()
            self.assertEqual(res["status"], "not_applicable")
            self.assertEqual(res["total_adapters"], 0)
            self.assertEqual(res["adapters"], [])
            self.assertIn("Windows NT", res["message"])

    def test_synonym_and_physical_preference_scoring(self):
        mock_pnp = [
            {
                "name": "WAN Miniport (IP)",
                "device_instance_id": "SWD\\MSRRAS\\MS_NDISWANIP",
                "service": "NdisWan",
                "class": "Net",
            },
            {
                "name": "Microsoft Wi-Fi Direct Virtual Adapter",
                "device_instance_id": "{5D624F94-8850-40C3-A3FA-A4FD2080BAF3}\\VWIFIMP_WFD\\5&3B4E10EE&0&11",
                "service": "vwifimp",
                "class": "Net",
            },
            {
                "name": "Intel(R) Dual Band Wireless-AC 8265",
                "device_instance_id": "PCI\\VEN_8086&DEV_24FD&SUBSYS_00508086&REV_78\\50E085FFFF1644AF00",
                "hardware_id": "PCI\\VEN_8086&DEV_24FD&SUBSYS_00508086&REV_78",
                "parent_device_id": "PCI\\VEN_8086&DEV_9D12\\3&11583659&0&E2",
                "service": "Netwtw06",
                "driver_key": "{4d36e972-e325-11ce-bfc1-08002be10318}\\0002",
                "class": "Net",
                "is_started": True,
                "has_problem": False,
                "problem_code": 0,
                "problem_description": "Healthy",
            },
        ]
        mock_ndis = {
            "status": "success",
            "total_adapters": 1,
            "adapters": [
                {
                    "interface_guid": "{B499737D-84F2-433F-B4CF-E7780121B408}",
                    "friendly_name": "Wi-Fi",
                    "description": "Intel(R) Dual Band Wireless-AC 8265",
                    "physical_mac_address": "50-E0-85-16-44-AF",
                    "is_wireless": True,
                    "is_connected": True,
                    "operational_status": "UP (Connected / Operational)",
                    "receive_link_speed_mbps": 468.0,
                    "transmit_link_speed_mbps": 468.0,
                    "ipv4_addresses": ["192.168.0.194"],
                }
            ],
            "epistemic_classification": "WIN32_IPHLPAPI_ADAPTERS_ADDRESSES",
        }

        with patch("windows_intelligence.system_introspection.device_inspector.NativeDeviceInspector.enumerate_devices", return_value=mock_pnp):
            with patch.object(NetworkHardwareInspector, "audit_network_adapters", return_value=mock_ndis):
                with patch("windows_intelligence.system_introspection.service_inspector.ServiceManagerInspector.get_service_config", return_value={"binary_path": "\\SystemRoot\\System32\\drivers\\Netwtw06.sys", "display_name": "Intel Wireless", "start_type": "DEMAND"}):
                    with patch("windows_intelligence.system_introspection.service_inspector.ServiceManagerInspector.enumerate_services", return_value=[{"service_name": "Netwtw06", "state": "RUNNING"}]):
                        with patch("windows_intelligence.system_introspection.driver_inspector.KernelDriverInspector.enumerate_loaded_drivers", return_value=[{"driver_name": "netwtw06.sys", "kernel_image_base": "0xfffff8014f200000", "kernel_base_int": 0xfffff8014f200000, "file_path": r"C:\Windows\System32\drivers\Netwtw06.sys", "file_exists": True}]):
                            with patch("os.path.isfile", return_value=True):
                                with patch("os.path.getsize", return_value=8902224):
                                    with patch("binary_neural_engine.BinaryFormatInspector.inspect", return_value={"format": "PE", "image_base": "0x140000000", "entry_point_rva": "0x4de00", "sections": [{"name": ".text"}, {"name": ".rdata"}], "imports": {"modules": {"ntoskrnl.exe": ["IoCreateDevice"], "NDIS.SYS": ["NdisMRegisterMiniportDriver"]}}}):
                                        with patch("pe_deep_forensics.PeDeepForensicsInspector.inspect", return_value={"architecture": "x64 (PE32+)", "pdata_functions": {"total_runtime_functions": 16255}, "pdb_correlation": {"rsds_records": [{"guid": "02771930-74A3-4464-B90B-51390F4B58CF"}]}}):
                                            # Test query "wifi" targets physical adapter, not virtual adapter
                                            res = NetworkHardwareInspector.deep_dissect_network_device(target_query="wifi")
                                            self.assertEqual(res["status"], "success")
                                            self.assertEqual(res["device_name"], "Intel(R) Dual Band Wireless-AC 8265")

                                            # Layer 1
                                            self.assertEqual(res["layer_1_physical_bus"]["device_instance_id"], "PCI\\VEN_8086&DEV_24FD&SUBSYS_00508086&REV_78\\50E085FFFF1644AF00")
                                            self.assertTrue(res["layer_1_physical_bus"]["is_started"])

                                            # Layer 2
                                            self.assertEqual(res["layer_2_ndis_telemetry"]["physical_mac_address"], "50-E0-85-16-44-AF")
                                            self.assertEqual(res["layer_2_ndis_telemetry"]["receive_link_speed_mbps"], 468.0)

                                            # Layer 4
                                            self.assertEqual(res["layer_4_scm_service"]["service_name"], "Netwtw06")
                                            self.assertEqual(res["layer_4_scm_service"]["state"], "RUNNING")

                                            # Layer 5
                                            l5 = res["layer_5_driver_binary_forensics"]
                                            self.assertEqual(l5["architecture"], "x64 (PE32+)")
                                            self.assertEqual(l5["total_pdata_functions"], 16255)
                                            self.assertEqual(l5["entry_point_rva"], "0x4de00")

                                            # Layer 6: KASLR Slide & Live DriverEntry VA
                                            l6 = res["layer_6_runtime_kaslr"]
                                            self.assertEqual(l6["live_kernel_base_hex"], "0xfffff8014f200000")
                                            self.assertEqual(l6["preferred_image_base_hex"], "0x140000000")
                                            self.assertEqual(l6["kaslr_slide_hex"], hex(0xfffff8014f200000 - 0x140000000))
                                            self.assertEqual(l6["driver_entry_rva"], "0x4de00")
                                            self.assertEqual(l6["live_driver_entry_va"], hex(0xfffff8014f200000 + 0x4de00))
                                            self.assertTrue(l6["aslr_mitigation_active"])

    def test_driver_store_path_and_name_mismatch_correlation(self):
        # Ethernet scenario: service name is e1dexpress, binary is e1d.sys inside DriverStore
        mock_pnp = [
            {
                "name": "Intel(R) Ethernet Connection (4) I219-LM",
                "device_instance_id": "PCI\\VEN_8086&DEV_15D7&SUBSYS_08161028&REV_21\\3&11583659&0&FE",
                "service": "e1dexpress",
                "class": "Net",
            }
        ]
        mock_scm_cfg = {
            "binary_path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\e1d.inf_amd64_9b9691c91d28fd9b\\e1d.sys",
            "display_name": "Intel PRO/1000",
            "start_type": "DEMAND"
        }
        mock_loaded_drivers = [
            {
                "driver_name": "e1d.sys",
                "kernel_image_base": "0xfffff8014fb50000",
                "kernel_base_int": 0xfffff8014fb50000,
                "file_path": r"C:\Windows\System32\DriverStore\FileRepository\e1d.inf_amd64_9b9691c91d28fd9b\e1d.sys",
                "file_exists": True,
            }
        ]

        with patch("windows_intelligence.system_introspection.device_inspector.NativeDeviceInspector.enumerate_devices", return_value=mock_pnp):
            with patch.object(NetworkHardwareInspector, "audit_network_adapters", return_value={"total_adapters": 0, "adapters": []}):
                with patch("windows_intelligence.system_introspection.service_inspector.ServiceManagerInspector.get_service_config", return_value=mock_scm_cfg):
                    with patch("windows_intelligence.system_introspection.service_inspector.ServiceManagerInspector.enumerate_services", return_value=[{"service_name": "e1dexpress", "state": "RUNNING"}]):
                        with patch("windows_intelligence.system_introspection.driver_inspector.KernelDriverInspector.enumerate_loaded_drivers", return_value=mock_loaded_drivers):
                            with patch("os.path.isfile", return_value=True):
                                with patch("os.path.getsize", return_value=625296):
                                    with patch("binary_neural_engine.BinaryFormatInspector.inspect", return_value={"format": "PE", "image_base": "0x140000000", "entry_point_rva": "0x91000", "sections": [{"name": ".text"}], "imports": {"modules": {}}}):
                                        with patch("pe_deep_forensics.PeDeepForensicsInspector.inspect", return_value={"architecture": "x64 (PE32+)", "pdata_functions": {"total_runtime_functions": 1067}, "pdb_correlation": {}}):
                                            res = NetworkHardwareInspector.deep_dissect_network_device(target_query="ethernet")
                                            self.assertEqual(res["status"], "success")
                                            self.assertEqual(res["device_name"], "Intel(R) Ethernet Connection (4) I219-LM")
                                            self.assertEqual(res["layer_4_scm_service"]["service_name"], "e1dexpress")
                                            self.assertEqual(res["layer_5_driver_binary_forensics"]["total_pdata_functions"], 1067)
                                            self.assertEqual(res["layer_6_runtime_kaslr"]["live_driver_entry_va"], hex(0xfffff8014fb50000 + 0x91000))

    def test_mcp_registration_and_dispatch(self):
        from mcp_server import TOOLS_REGISTRY, BintraMcpServer
        tool_names = [t["name"] for t in TOOLS_REGISTRY]
        self.assertIn("bintra_network_audit", tool_names)
        self.assertIn("bintra_network_hardware_dissect", tool_names)

        # Verify capability / security metadata map
        server = BintraMcpServer()
        cap_entry_audit = server.TOOL_SECURITY_METADATA.get("bintra_network_audit")
        self.assertIsNotNone(cap_entry_audit)
        self.assertEqual(cap_entry_audit[0], "cap.device.query")

        cap_entry_dissect = server.TOOL_SECURITY_METADATA.get("bintra_network_hardware_dissect")
        self.assertIsNotNone(cap_entry_dissect)
        self.assertEqual(cap_entry_dissect[0], "cap.device.query")

    def test_cli_command_registration(self):
        from cli import WIN_INTEL_COMMANDS
        self.assertIn("hw-net", WIN_INTEL_COMMANDS)
        self.assertIn("hw-dissect", WIN_INTEL_COMMANDS)


if __name__ == "__main__":
    unittest.main()
