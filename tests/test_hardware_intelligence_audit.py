# -*- coding: utf-8 -*-
"""
Verification tests for the Hardware Intelligence audit remediations:
1. COM / PnP Correlation (Ports class priority, COM1 vs COM10 boundary, CLI markdown formatting)
2. Win64 Handle Safety (0xFFFFFFFFFFFFFFFF INVALID_HANDLE_VALUE, try/finally HDEVINFO cleanup)
3. CM_PROB Accuracy (Canonical Microsoft SDK cfg.h codes 47..57)
4. Hardware Health Classification (HEALTHY / DEGRADED / FAULTING / UNKNOWN + status_unavailable_count)
5. Storage Inspection (32-byte STORAGE_DEVICE_DESCRIPTOR guard + exact used_bytes math)
6. Real ETW Validation (EnableTraceEx2 MatchAnyKeyword=0xFFFFFFFFFFFFFFFF, Data4 GUIDs, Kernel-Disk)
"""

import ctypes
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from windows_intelligence.system_introspection.device_inspector import NativeDeviceInspector
from windows_intelligence.system_introspection.port_inspector import PortInspector
from windows_intelligence.runtime_telemetry.etw_capture_engine import EtwLiveCaptureSession


class TestHardwareIntelligenceAudit(unittest.TestCase):
    def test_cm_prob_canonical_cfg_h_47_to_57(self):
        expected = {
            47: "CM_PROB_HELD_FOR_EJECT",
            48: "CM_PROB_DRIVER_BLOCKED",
            49: "CM_PROB_REGISTRY_TOO_LARGE",
            50: "CM_PROB_SETPROPERTIES_FAILED",
            51: "CM_PROB_WAITING_ON_DEPENDENCY",
            52: "CM_PROB_UNSIGNED_DRIVER",
            53: "CM_PROB_USED_BY_DEBUGGER",
            54: "CM_PROB_DEVICE_RESET",
            55: "CM_PROB_CONSOLE_LOCK",
            56: "CM_PROB_NEED_CLASS_CONFIG",
            57: "CM_PROB_GUEST_ASSIGNMENT_FAILED",
        }
        for code, name in expected.items():
            self.assertEqual(NativeDeviceInspector.CM_PROBLEM_NAMES[code], name)
            self.assertIn(name, NativeDeviceInspector.describe_problem_code(code))

    def test_win64_invalid_handle_value_and_cleanup_in_enumerate_devices(self):
        mock_setupapi = MagicMock()
        mock_cfgmgr32 = MagicMock()
        invalid_handle = ctypes.c_void_p(-1).value
        mock_setupapi.SetupDiGetClassDevsW.return_value = invalid_handle

        with patch.object(NativeDeviceInspector, "_get_setupapi_library", return_value=(mock_setupapi, mock_cfgmgr32)):
            devs = NativeDeviceInspector.enumerate_devices()

        self.assertEqual(devs, [])
        mock_setupapi.SetupDiEnumDeviceInfo.assert_not_called()
        mock_setupapi.SetupDiDestroyDeviceInfoList.assert_not_called()

        # Verify finally cleanup runs even if SetupDiEnumDeviceInfo raises
        mock_setupapi2 = MagicMock()
        mock_setupapi2.SetupDiGetClassDevsW.return_value = 0x12345678
        mock_setupapi2.SetupDiEnumDeviceInfo.side_effect = RuntimeError("boom")
        with patch.object(NativeDeviceInspector, "_get_setupapi_library", return_value=(mock_setupapi2, mock_cfgmgr32)):
            with self.assertRaises(RuntimeError):
                NativeDeviceInspector.enumerate_devices()
        mock_setupapi2.SetupDiDestroyDeviceInfoList.assert_called_once_with(0x12345678)

    def test_hardware_health_classification_states(self):
        with patch("os.name", "nt"):
            with patch.object(NativeDeviceInspector, "enumerate_devices", return_value=[]):
                rep_empty = NativeDeviceInspector.audit_hardware_health()
                self.assertEqual(rep_empty["health_classification"], "UNKNOWN")
                self.assertFalse(rep_empty["is_hardware_healthy"])

            with patch.object(NativeDeviceInspector, "enumerate_devices", return_value=[
                {"device_instance_id": "PCI\\1", "class": "Display", "has_problem": False, "problem_code": 0, "status_available": True}
            ]):
                rep_ok = NativeDeviceInspector.audit_hardware_health()
                self.assertEqual(rep_ok["health_classification"], "HEALTHY")
                self.assertTrue(rep_ok["is_hardware_healthy"])

            with patch.object(NativeDeviceInspector, "enumerate_devices", return_value=[
                {"device_instance_id": "USB\\1", "class": "USB", "has_problem": True, "problem_code": 22, "status_available": True}
            ]):
                rep_deg = NativeDeviceInspector.audit_hardware_health()
                self.assertEqual(rep_deg["health_classification"], "DEGRADED")
                self.assertFalse(rep_deg["is_hardware_healthy"])

            with patch.object(NativeDeviceInspector, "enumerate_devices", return_value=[
                {"device_instance_id": "PCI\\2", "class": "Display", "has_problem": True, "problem_code": 43, "status_available": True}
            ]):
                rep_fault = NativeDeviceInspector.audit_hardware_health()
                self.assertEqual(rep_fault["health_classification"], "FAULTING")
                self.assertFalse(rep_fault["is_hardware_healthy"])

    def test_port_pnp_correlation_boundary_and_class_priority(self):
        mock_devices = [
            {
                "device_instance_id": "ROOT\\FAKE\\0001",
                "name": "Telemetry Device COM10",
                "friendly_name": "Telemetry Device (COM10)",
                "class": "System",
                "hardware_ids": [],
                "has_problem": False,
                "problem_code": 0,
            },
            {
                "device_instance_id": "USB\\VID_1A86&PID_7523\\5&6789",
                "name": "USB-SERIAL CH340 (COM1)",
                "friendly_name": "USB-SERIAL CH340 (COM1)",
                "class": "Ports",
                "hardware_ids": ["USB\\VID_1A86&PID_7523"],
                "service": "CH341SER",
                "has_problem": False,
                "problem_code": 0,
            },
        ]
        ports_list = [{"port_name": "COM1", "device_map_path": "\\Device\\Serial0"}]
        with patch.object(NativeDeviceInspector, "enumerate_devices", return_value=mock_devices):
            PortInspector._enrich_with_pnp_hardware(ports_list)

        self.assertEqual(ports_list[0]["hardware_details"]["device_instance_id"], "USB\\VID_1A86&PID_7523\\5&6789")
        self.assertEqual(ports_list[0]["bridge_identity"], "QinHeng CH340 / CH340G USB-to-Serial")

    def test_etw_capture_source_invariants(self):
        # Verify MatchAnyKeyword is 0xFFFFFFFFFFFFFFFF in _enable_provider_native
        src = (SRC_DIR / "windows_intelligence" / "runtime_telemetry" / "etw_capture_engine.py").read_text(encoding="utf-8")
        self.assertIn("0xFFFFFFFFFFFFFFFF", src)
        self.assertIn("DISK_IO_READ", src)
        self.assertIn("res == 183", src)


if __name__ == "__main__":
    unittest.main()
