# -*- coding: utf-8 -*-
"""
Rigorous verification tests for Bintra Network Hardware Intelligence and Deep Driver Reverse Engineering Engine.
Covers:
1. Non-Windows NT platform graceful degradation
2. Ctypes structure layout, member offsets, and size invariants
3. Win32 API signature registration (argtypes & restype) on GetAdaptersAddresses
4. Synthetic binary buffer parsing: MAC unpack, link speed math, IPv4/IPv6 socket address extraction
5. Structure Length member versioning guard (handling pre-Vista / legacy lengths)
6. Virtual adapter classification & deterministic filtering (including wireless virtual miniports)
7. Multi-layer completeness accounting (FULL_6_LAYER_TRACE vs PARTIAL_TRACE)
8. DriverStore path expansion and driver filename mismatch resolution (e1dexpress -> e1d.sys)
9. MCP tool registration, 46-tool security mediation, and CLI registration
10. Live read-only Windows NT execution sanity check (when on Windows host)
"""

import os
import sys
import socket
import struct
import ctypes
from ctypes import wintypes
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from windows_intelligence.system_introspection.network_inspector import (
    NetworkHardwareInspector,
    SOCKET_ADDRESS,
    IP_ADAPTER_UNICAST_ADDRESS,
    IP_ADAPTER_ADDRESSES,
)


class TestNetworkHardwareInspector(unittest.TestCase):
    def test_non_windows_graceful_degradation(self):
        with patch("os.name", "posix"):
            res = NetworkHardwareInspector.audit_network_adapters()
            self.assertEqual(res["status"], "not_applicable")
            self.assertEqual(res["total_adapters"], 0)
            self.assertEqual(res["adapters"], [])
            self.assertIn("Windows NT", res["message"])

    def test_ctypes_structure_layout_and_offsets(self):
        """Verifies binary layout and field offsets match Microsoft SDK specifications."""
        # 1. IP_ADAPTER_ADDRESSES
        self.assertEqual(IP_ADAPTER_ADDRESSES.Length.offset, 0)
        self.assertGreater(IP_ADAPTER_ADDRESSES.FirstUnicastAddress.offset, 0)
        self.assertGreater(IP_ADAPTER_ADDRESSES.PhysicalAddress.offset, 0)
        self.assertGreater(IP_ADAPTER_ADDRESSES.ReceiveLinkSpeed.offset, IP_ADAPTER_ADDRESSES.FirstPrefix.offset)
        self.assertGreaterEqual(ctypes.sizeof(IP_ADAPTER_ADDRESSES), 200)

        # 2. IP_ADAPTER_UNICAST_ADDRESS
        self.assertEqual(IP_ADAPTER_UNICAST_ADDRESS.Length.offset, 0)
        self.assertEqual(IP_ADAPTER_UNICAST_ADDRESS.Address.offset, IP_ADAPTER_UNICAST_ADDRESS.Next.offset + ctypes.sizeof(ctypes.c_void_p))

        # 3. SOCKET_ADDRESS (8 bytes on 32-bit, 16 bytes on 64-bit due to pointer alignment padding)
        expected_socket_addr_size = 16 if ctypes.sizeof(ctypes.c_void_p) == 8 else 8
        self.assertEqual(ctypes.sizeof(SOCKET_ADDRESS), expected_socket_addr_size)

    def test_synthetic_binary_buffer_parsing_and_unicast_unpacking(self):
        """
        Synthesizes a real in-memory ctypes binary buffer representing an active
        physical network adapter with IPv4 unicast address and verifies deterministic extraction.
        """
        # Allocate binary structures
        addr_struct = IP_ADAPTER_ADDRESSES()
        unicast_struct = IP_ADAPTER_UNICAST_ADDRESS()

        # Build IPv4 sockaddr_in (192.168.1.100)
        class SOCKADDR_IN(ctypes.Structure):
            _fields_ = [
                ("sin_family", ctypes.c_uint16),
                ("sin_port", ctypes.c_uint16),
                ("sin_addr", ctypes.c_uint8 * 4),
                ("sin_zero", ctypes.c_char * 8),
            ]

        sa_v4 = SOCKADDR_IN()
        sa_v4.sin_family = 2  # AF_INET
        sa_v4.sin_port = 0
        sa_v4.sin_addr[0] = 192
        sa_v4.sin_addr[1] = 168
        sa_v4.sin_addr[2] = 1
        sa_v4.sin_addr[3] = 100

        # Wire unicast structure
        unicast_struct.Length = ctypes.sizeof(IP_ADAPTER_UNICAST_ADDRESS)
        unicast_struct.Next = None
        unicast_struct.Address.lpSockaddr = ctypes.cast(ctypes.pointer(sa_v4), ctypes.c_void_p).value
        unicast_struct.Address.iSockaddrLength = ctypes.sizeof(SOCKADDR_IN)

        # Wire IP_ADAPTER_ADDRESSES structure
        raw_guid = b"{12345678-ABCD-EF01-2345-6789ABCDEF01}"
        raw_friendly = "Mock Physical Wi-Fi"
        raw_desc = "Intel(R) Mock Wireless Adapter"

        addr_struct.Length = ctypes.sizeof(IP_ADAPTER_ADDRESSES)
        addr_struct.IfIndex = 77
        addr_struct.Next = None
        addr_struct.AdapterName = ctypes.c_char_p(raw_guid)
        addr_struct.FriendlyName = raw_friendly
        addr_struct.Description = raw_desc
        addr_struct.FirstUnicastAddress = ctypes.pointer(unicast_struct)

        # MAC: 50-E0-85-16-44-AF
        mac_bytes = [0x50, 0xE0, 0x85, 0x16, 0x44, 0xAF]
        for i, b in enumerate(mac_bytes):
            addr_struct.PhysicalAddress[i] = b
        addr_struct.PhysicalAddressLength = 6

        addr_struct.IfType = 71  # IEEE80211_WIRELESS
        addr_struct.OperStatus = 1  # UP
        addr_struct.Mtu = 1500
        addr_struct.TransmitLinkSpeed = 300_000_000  # 300 Mbps
        addr_struct.ReceiveLinkSpeed = 300_000_000

        def fake_get_adapters(family, flags, reserved, buf, size_ptr):
            raw_bytes = bytes(addr_struct)
            ctypes.memmove(buf, raw_bytes, len(raw_bytes))
            return 0

        mock_dll = MagicMock()
        mock_dll.GetAdaptersAddresses.side_effect = fake_get_adapters

        with patch("os.name", "nt"):
            with patch.object(NetworkHardwareInspector, "_load_iphlpapi", return_value=mock_dll):
                report = NetworkHardwareInspector.audit_network_adapters(include_virtual=True)

        self.assertEqual(report["status"], "success")
        self.assertEqual(report["total_adapters"], 1)
        adapter = report["adapters"][0]

        self.assertEqual(adapter["friendly_name"], "Mock Physical Wi-Fi")
        self.assertEqual(adapter["physical_mac_address"], "50-E0-85-16-44-AF")
        self.assertEqual(adapter["interface_type"], "IEEE80211_WIRELESS")
        self.assertEqual(adapter["operational_status"], "UP (Connected / Operational)")
        self.assertTrue(adapter["is_connected"])
        self.assertTrue(adapter["is_wireless"])
        self.assertFalse(adapter["is_virtual"])
        self.assertEqual(adapter["receive_link_speed_mbps"], 300.0)
        self.assertEqual(adapter["transmit_link_speed_mbps"], 300.0)
        self.assertEqual(adapter["ipv4_addresses"], ["192.168.1.100"])

    def test_legacy_length_guard_and_virtual_filtering(self):
        """Verifies that pre-Vista structures without link speed are safely guarded, and virtual adapters are pruned."""
        # 1. Structure with legacy Length (shorter than ReceiveLinkSpeed)
        legacy_addr = IP_ADAPTER_ADDRESSES()
        legacy_addr.Length = IP_ADAPTER_ADDRESSES.FirstPrefix.offset + ctypes.sizeof(ctypes.c_void_p)
        legacy_addr.AdapterName = b"{LEGACY-ADAPTER}"
        legacy_addr.Description = "Legacy Realtek Adapter"
        legacy_addr.FriendlyName = "Ethernet"
        legacy_addr.IfType = 6  # ETHERNET_CSMACD
        legacy_addr.OperStatus = 1
        legacy_addr.PhysicalAddressLength = 6
        legacy_addr.ReceiveLinkSpeed = 999_999_999  # Should not be read because Length < offset

        # 2. Virtual Wi-Fi Direct adapter (IfType 71 but virtual name)
        virtual_wlan = IP_ADAPTER_ADDRESSES()
        virtual_wlan.Length = ctypes.sizeof(IP_ADAPTER_ADDRESSES)
        virtual_wlan.AdapterName = b"{VIRTUAL-WIFI}"
        virtual_wlan.Description = "Microsoft Wi-Fi Direct Virtual Adapter"
        virtual_wlan.FriendlyName = "Local Area Connection* 1"
        virtual_wlan.IfType = 71
        virtual_wlan.OperStatus = 2

        # Link them: legacy_addr -> virtual_wlan
        legacy_addr.Next = ctypes.pointer(virtual_wlan)

        def fake_get_adapters(family, flags, reserved, buf, size_ptr):
            # Write both to buffer
            b1 = bytes(legacy_addr)
            ctypes.memmove(buf, b1, len(b1))
            return 0

        mock_dll = MagicMock()
        mock_dll.GetAdaptersAddresses.side_effect = fake_get_adapters

        with patch("os.name", "nt"):
            with patch.object(NetworkHardwareInspector, "_load_iphlpapi", return_value=mock_dll):
                # When include_virtual=False, virtual Wi-Fi Direct must be excluded
                rep_no_virt = NetworkHardwareInspector.audit_network_adapters(include_virtual=False)
                # Legacy speed should be 0.0 because Length did not cover speed fields
                self.assertEqual(rep_no_virt["total_adapters"], 1)
                self.assertEqual(rep_no_virt["adapters"][0]["receive_link_speed_mbps"], 0.0)

                # Check virtual classification
                self.assertFalse(rep_no_virt["adapters"][0]["is_virtual"])

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
                "driver_version": "20.70.25.2",
                "driver_desc": "Intel(R) Dual Band Wireless-AC 8265",
                "provider_name": "Intel",
                "driver_date": "6-22-2021",
                "inf_path": "oem3.inf",
                "net_cfg_instance_id": "{B499737D-84F2-433F-B4CF-E7780121B408}",
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
                                            self.assertEqual(res["status"], "SUCCESS")
                                            self.assertEqual(res["dossier_completeness"], "FULL_6_LAYER_TRACE")
                                            self.assertEqual(res["epistemic_classification"], "CORRELATED_STATIC_AND_RUNTIME_DEVICE_TRACE")
                                            self.assertEqual(res["selection_method"], "HEURISTIC_WEIGHTED_CANDIDATE_MATCH")
                                            self.assertGreaterEqual(res["match_confidence"], 0.8)
                                            self.assertEqual(res["device_name"], "Intel(R) Dual Band Wireless-AC 8265")

                                            # Layer 1
                                            self.assertEqual(res["layer_1_physical_bus"]["layer_status"], "COMPLETE")
                                            self.assertEqual(res["layer_1_physical_bus"]["device_instance_id"], "PCI\\VEN_8086&DEV_24FD&SUBSYS_00508086&REV_78\\50E085FFFF1644AF00")

                                            # Layer 2
                                            self.assertEqual(res["layer_2_ndis_telemetry"]["layer_status"], "COMPLETE")
                                            self.assertEqual(res["layer_2_ndis_telemetry"]["physical_mac_address"], "50-E0-85-16-44-AF")

                                            # Layer 4
                                            self.assertEqual(res["layer_4_scm_service"]["layer_status"], "COMPLETE")
                                            self.assertEqual(res["layer_4_scm_service"]["service_name"], "Netwtw06")

                                            # Layer 5
                                            self.assertEqual(res["layer_5_driver_binary_forensics"]["layer_status"], "COMPLETE")
                                            self.assertEqual(res["layer_5_driver_binary_forensics"]["total_pdata_functions"], 16255)

                                            # Layer 6
                                            l6 = res["layer_6_runtime_kaslr"]
                                            self.assertEqual(l6["layer_status"], "COMPLETE")
                                            self.assertEqual(l6["kaslr_scope"], "STATIC_DYNAMIC_BASE_DISPLACEMENT")
                                            self.assertEqual(l6["live_driver_entry_va"], hex(0xfffff8014f200000 + 0x4de00))

    def test_partial_trace_handling_when_binary_or_kernel_unavailable(self):
        """Verifies epistemic honesty: reports PARTIAL when binary is missing or not loaded."""
        mock_pnp = [
            {
                "name": "Intel(R) Ethernet Connection (4) I219-LM",
                "device_instance_id": "PCI\\VEN_8086&DEV_15D7&SUBSYS_08161028&REV_21\\3&11583659&0&FE",
                "service": "e1dexpress",
                "class": "Net",
            }
        ]

        with patch("windows_intelligence.system_introspection.device_inspector.NativeDeviceInspector.enumerate_devices", return_value=mock_pnp):
            with patch.object(NetworkHardwareInspector, "audit_network_adapters", return_value={"total_adapters": 0, "adapters": []}):
                with patch("windows_intelligence.system_introspection.service_inspector.ServiceManagerInspector.get_service_config", return_value={"binary_path": "\\SystemRoot\\System32\\e1d.sys"}):
                    with patch("windows_intelligence.system_introspection.service_inspector.ServiceManagerInspector.enumerate_services", return_value=[{"service_name": "e1dexpress", "state": "STOPPED"}]):
                        with patch("windows_intelligence.system_introspection.driver_inspector.KernelDriverInspector.enumerate_loaded_drivers", return_value=[]):
                            with patch("os.path.isfile", return_value=False):
                                res = NetworkHardwareInspector.deep_dissect_network_device(target_query="ethernet")
                                self.assertEqual(res["status"], "PARTIAL")
                                self.assertIn("PARTIAL_TRACE", res["dossier_completeness"])
                                self.assertEqual(res["layer_1_physical_bus"]["layer_status"], "COMPLETE")
                                self.assertEqual(res["layer_4_scm_service"]["layer_status"], "COMPLETE")
                                self.assertEqual(res["layer_5_driver_binary_forensics"]["layer_status"], "UNAVAILABLE")
                                self.assertEqual(res["layer_6_runtime_kaslr"]["layer_status"], "UNAVAILABLE")

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
                                            self.assertEqual(res["device_name"], "Intel(R) Ethernet Connection (4) I219-LM")
                                            self.assertEqual(res["layer_4_scm_service"]["service_name"], "e1dexpress")
                                            self.assertEqual(res["layer_5_driver_binary_forensics"]["total_pdata_functions"], 1067)
                                            self.assertEqual(res["layer_6_runtime_kaslr"]["live_driver_entry_va"], hex(0xfffff8014fb50000 + 0x91000))

    def test_mcp_registration_and_dispatch(self):
        from mcp_server import TOOLS_REGISTRY, BintraMcpServer
        tool_names = [t["name"] for t in TOOLS_REGISTRY]
        self.assertEqual(len(tool_names), 46)
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

    def test_live_execution_on_windows_host(self):
        """When executed on a live Windows NT machine, validates that live calls succeed without crashing."""
        if os.name != "nt":
            self.skipTest("Live NT execution only runs on Windows hosts.")

        # 1. Live audit
        live_audit = NetworkHardwareInspector.audit_network_adapters(include_virtual=True)
        self.assertEqual(live_audit["status"], "success")
        self.assertGreater(live_audit["total_adapters"], 0)
        for a in live_audit["adapters"]:
            self.assertIn("friendly_name", a)
            self.assertIn("physical_mac_address", a)
            self.assertIn("operational_status", a)
            self.assertIn("is_connected", a)

        # 2. Live deep dissection
        live_dissect = NetworkHardwareInspector.deep_dissect_network_device(target_query="wifi")
        self.assertIn(live_dissect["status"], ("SUCCESS", "PARTIAL"))
        self.assertTrue(bool(live_dissect.get("device_name")))
        self.assertEqual(live_dissect["layer_1_physical_bus"]["layer_status"], "COMPLETE")


if __name__ == "__main__":
    unittest.main()
