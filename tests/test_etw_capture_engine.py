# -*- coding: utf-8 -*-
"""
Test Suite for Real-Time ETW Capture & Telemetry Timeline Engine.
Verifies session lifecycle, event buffering, PID filtering,
timeline correlation (churn & late DLL injection), and MCP / CLI integration.
"""

import os
import sys
import time
import unittest

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from security import ExecutionGuard, Capability
from windows_intelligence.runtime_telemetry import (
    EtwLiveCaptureSession,
    EtwEventRecord,
    EtwTimelineCorrelator,
)


class TestEtwCaptureEngine(unittest.TestCase):
    """Verifies ETW live capture session management and timeline correlation invariants."""

    def test_etw_event_record_serialization(self):
        """Verifies EtwEventRecord field extraction and dictionary formatting."""
        ev = EtwEventRecord(
            timestamp=1700000000.1234,
            provider_name="Microsoft-Windows-Kernel-Process",
            event_id=1,
            pid=1234,
            tid=5678,
            event_type="PROCESS_START",
            details={"image_name": "worker.exe", "command_line": "--worker 1"}
        )
        d = ev.to_dict()
        self.assertEqual(d["provider_name"], "Microsoft-Windows-Kernel-Process")
        self.assertEqual(d["pid"], 1234)
        self.assertEqual(d["tid"], 5678)
        self.assertEqual(d["event_type"], "PROCESS_START")
        self.assertIn("image_name", d["details"])
        self.assertIn(":", d["time_str"])

    def test_session_lifecycle_and_ring_buffer(self):
        """Verifies session startup, event ingestion, PID filtering, and teardown."""
        session = EtwLiveCaptureSession(session_name="TestDiagnosticTrace", target_pid=4242, max_buffer_events=10)
        start_res = session.start_session()
        self.assertTrue(session.is_running)
        self.assertIn(start_res["status"], ["success", "non_elevated"])

        t0 = time.time()
        # Ingest events: matching PID and non-matching PID
        ev_match = EtwEventRecord(t0, "Microsoft-Windows-Kernel-Process", 1, 4242, 100, "THREAD_START")
        ev_other = EtwEventRecord(t0 + 0.1, "Microsoft-Windows-Kernel-Process", 1, 9999, 200, "THREAD_START")
        ev_global = EtwEventRecord(t0 + 0.2, "Microsoft-Windows-Kernel-Memory", 10, 0, 0, "SYSTEM_MEMORY_LOW")

        session.record_event(ev_match)
        session.record_event(ev_other)  # Should be filtered out by target_pid=4242
        session.record_event(ev_global)  # Should be preserved (pid=0 global)

        timeline = session.get_timeline()
        self.assertEqual(len(timeline), 2)
        pids = [e["pid"] for e in timeline]
        self.assertIn(4242, pids)
        self.assertNotIn(9999, pids)

        stop_res = session.stop_session()
        self.assertFalse(session.is_running)
        self.assertEqual(stop_res["status"], "stopped")

    def test_context_manager_clean_teardown(self):
        """Verifies that EtwLiveCaptureSession context manager closes handles automatically."""
        with EtwLiveCaptureSession(session_name="CtxTestTrace") as s:
            self.assertTrue(s.is_running)
        self.assertFalse(s.is_running)

    def test_timeline_correlator_memory_churn_detection(self):
        """Verifies correlation engine flags memory churn preceding a crash."""
        crash_t = time.time()
        events = [
            EtwEventRecord(crash_t - 2.5, "Kernel-Memory", 1, 1000, 10, "VIRTUAL_ALLOC", details={"size": 65536}).to_dict(),
            EtwEventRecord(crash_t - 1.2, "Kernel-Memory", 2, 1000, 10, "VIRTUAL_FREE", details={"size": 65536}).to_dict(),
            EtwEventRecord(crash_t - 0.3, "Kernel-Process", 3, 1000, 10, "THREAD_CRASH", details={"code": "0xc0000005"}).to_dict(),
        ]

        report = EtwTimelineCorrelator.correlate_crash_timeline(events, crash_timestamp=crash_t)
        self.assertEqual(report["events_count"], 3)
        self.assertEqual(report["temporal_verdict"], "TEMPORAL_MEMORY_CHURN_DETECTED")
        self.assertTrue(any(f["category"] == "MEMORY_DEALLOCATION" for f in report["causality_findings"]))

        # Check Markdown generation
        md_text = EtwTimelineCorrelator.format_markdown(report)
        self.assertIn("# REA-Neural ETW Diagnostic Timeline Correlation", md_text)
        self.assertIn("TEMPORAL_MEMORY_CHURN_DETECTED", md_text)

    def test_timeline_correlator_late_module_injection_detection(self):
        """Verifies detection of dynamic modules loaded immediately prior to a fault."""
        crash_t = time.time()
        events = [
            EtwEventRecord(crash_t - 1.0, "Kernel-Process", 5, 2000, 20, "IMAGE_LOAD", details={"image_name": "injected_hook.dll"}).to_dict()
        ]
        report = EtwTimelineCorrelator.correlate_crash_timeline(events, crash_timestamp=crash_t)
        self.assertEqual(report["temporal_verdict"], "LATE_MODULE_INJECTION_DETECTED")
        self.assertTrue(any(f["category"] == "DYNAMIC_IMAGE_LOAD" for f in report["causality_findings"]))

    def test_mcp_etw_capture_tool_dispatch(self):
        """Verifies that native MCP server exposes and dispatches rea_etw_capture."""
        from mcp_server import ReaMcpServer
        server = ReaMcpServer()

        tool_names = [t["name"] for t in server.handle_tools_list({})["tools"]]
        self.assertIn("rea_etw_capture", tool_names)

        # Check security metadata
        cap, mode, target = server.TOOL_SECURITY_METADATA["rea_etw_capture"]
        self.assertEqual(cap, "cap.event_log.read")
        self.assertEqual(mode, "READ")

        # Execute short capture
        res = server.dispatch_tool("rea_etw_capture", {"duration_seconds": 0.1})
        self.assertIn("events_count", res)
        self.assertIn("temporal_verdict", res)
        self.assertIn("session_info", res)

    def test_event_log_collector_generic_query(self):
        """Verifies generic event query on Windows Event Log channels."""
        from windows_intelligence.runtime_telemetry.event_log_collector import EventLogCollector
        evs = EventLogCollector.query_events("Application", limit=5)
        self.assertIsInstance(evs, list)
        if evs:
            e0 = evs[0]
            self.assertIn("time_created", e0)
            self.assertIn("provider_name", e0)
            self.assertIn("event_id", e0)
            self.assertIn("level", e0)

    def test_etw_controller_dynamic_provider_enumeration(self):
        """Verifies dynamic ETW provider enumeration via TDH."""
        from windows_intelligence.runtime_telemetry.etw_controller import EtwController
        res = EtwController.enumerate_registered_providers(limit=10)
        self.assertIn(res["status"], ["success", "not_applicable"])
        if res["status"] == "success":
            self.assertGreater(res["total_system_providers"], 100)
            self.assertGreaterEqual(len(res["providers"]), 1)

    def test_etw_controller_active_kernel_providers(self):
        """Verifies querying active kernel ETW provider GUIDs."""
        from windows_intelligence.runtime_telemetry.etw_controller import EtwController
        res = EtwController.audit_active_kernel_providers(limit=10)
        self.assertIn(res["status"], ["success", "not_applicable"])
        if res["status"] == "success":
            self.assertGreater(res["active_kernel_providers_count"], 100)
            self.assertGreaterEqual(len(res["sample_guids"]), 1)

    def test_etw_controller_query_provider_instances(self):
        """Verifies querying instance PIDs and enable counts for a specific provider."""
        from windows_intelligence.runtime_telemetry.etw_controller import EtwController
        res = EtwController.query_provider_instances("{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}")
        self.assertIn(res["status"], ["active", "dormant", "not_applicable"])

    def test_timeline_correlator_extended_causality(self):
        """Verifies detection of RestartManager file lock contention and GPU TDR resets."""
        crash_t = time.time()
        events = [
            EtwEventRecord(crash_t - 2.0, "Microsoft-Windows-RestartManager", 10000, 1234, 10, "RESTART_MANAGER_LOCK").to_dict(),
            EtwEventRecord(crash_t - 0.5, "Microsoft-Windows-DXGI", 1, 1234, 10, "DEVICE_REMOVED").to_dict(),
        ]
        report = EtwTimelineCorrelator.correlate_crash_timeline(events, crash_timestamp=crash_t)
        self.assertIn(report["temporal_verdict"], ["GRAPHICS_PIPELINE_RESET_DETECTED", "FILE_LOCK_CONTENTION_DETECTED"])
        cats = [f["category"] for f in report["causality_findings"]]
        self.assertIn("RESOURCE_LOCK_CONTENTION", cats)
        self.assertIn("GRAPHICS_TDR_DEVICE_REMOVAL", cats)


if __name__ == "__main__":
    unittest.main()
