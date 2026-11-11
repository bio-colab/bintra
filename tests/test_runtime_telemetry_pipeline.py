# -*- coding: utf-8 -*-
"""
End-to-End Pipeline Integration Test for Bintra Runtime Telemetry & Crash Intelligence.
Validates the complete 4-stage pipeline execution:
Stage 1: Virtual Memory VAD Mapping & Spatial Bounds Classification
Stage 2: Deterministic Crash Root Cause Analysis (MiniDump + Disassembly + Registers)
Stage 3: Event Tracing for Windows (ETW) Timeline Correlation
Stage 4: Symbiotic Live IPC Bridge & Ghidra Database Mutation Queueing
Strictly mediated by ExecutionGuard reference monitor.
"""

import os
import sys
import json
import time
import tempfile
import unittest

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from security import ExecutionGuard, Capability
from windows_intelligence.runtime_telemetry import (
    VirtualMemoryInspector,
    ProcessMemoryMapSnapshot,
    ProcessMemoryRegion,
    CrashRootCauseAnalyzer,
    EtwLiveCaptureSession,
    EtwEventRecord,
    EtwTimelineCorrelator,
)
from ghidra_live_bridge import (
    GhidraLiveBridgeServer,
    GhidraLiveBridgeClient,
    get_or_create_bridge,
    stop_active_bridge
)


class TestRuntimeTelemetryPipeline(unittest.TestCase):
    """End-to-end integration verification across all 4 telemetry and crash analysis stages."""

    def setUp(self):
        self.temp_ws = tempfile.TemporaryDirectory()
        self.scope = ExecutionGuard.scoped_session(workspace_dir=self.temp_ws.name)
        self.scope.__enter__()

    def tearDown(self):
        stop_active_bridge()
        try:
            self.scope.__exit__(None, None, None)
        finally:
            self.temp_ws.cleanup()

    def test_complete_four_stage_pipeline_integration(self):
        """
        Executes and verifies full dataflow from live process memory mapping
        through crash RCA and ETW timeline correlation into live Ghidra mutation queue.
        """
        # =====================================================================
        # STAGE 1: Virtual Memory Inspection & Classification
        # =====================================================================
        snapshot = ProcessMemoryMapSnapshot(pid=1337, process_name="test_target.exe")
        # Add PE Image text section
        snapshot.add_region(ProcessMemoryRegion(
            base_address=0x140000000,
            allocation_base=0x140000000,
            region_size=0x10000,
            state=0x1000,       # MEM_COMMIT
            protect=0x20,       # PAGE_EXECUTE_READ
            alloc_protect=0x80, # PAGE_EXECUTE_WRITECOPY
            mem_type=0x1000000, # MEM_IMAGE
            category="IMAGE_TEXT"
        ))
        # Add Heap region
        snapshot.add_region(ProcessMemoryRegion(
            base_address=0x0000021000000000,
            allocation_base=0x0000021000000000,
            region_size=0x100000,
            state=0x1000,       # MEM_COMMIT
            protect=0x04,       # PAGE_READWRITE
            alloc_protect=0x04,
            mem_type=0x20000,   # MEM_PRIVATE
            category="HEAP"
        ))

        # Classify addresses
        cls_null = snapshot.classify_address(0x0000000000000018)
        self.assertEqual(cls_null["category"], "NULL_PAGE_TRAP")
        self.assertEqual(cls_null["status"], "FAULT_NULL_DEREFERENCE")
        self.assertEqual(cls_null["offset_from_null"], 0x18)

        cls_code = snapshot.classify_address(0x140001020)
        self.assertEqual(cls_code["category"], "IMAGE_TEXT")

        vad_summary = snapshot.compute_summary()
        self.assertEqual(vad_summary["wx_regions_count"], 0)

        # =====================================================================
        # STAGE 2: Automated Crash Root-Cause Analysis (RCA)
        # =====================================================================
        mock_dump_data = {
            "status": "success",
            "exception_info": {
                "exception_code": "0xc0000005",
                "exception_name": "STATUS_ACCESS_VIOLATION",
                "fault_address": "0x140001020",
                "fault_module": "test_target.exe",
                "fault_offset": "0x1020",
                "access_violation_details": {
                    "access_type": "READ",
                    "target_virtual_address": "0x0000000000000018"
                }
            },
            "thread_registers": {
                "arch": "x86-64",
                "RIP": "0x0000000140001020",
                "RAX": "0x0000000000000001",
                "RBX": "0x0000021000001000",
                "RCX": "0x0000000000000000",  # Culprit: NULL
                "RDX": "0x0000000000000020",
                "RSP": "0x000000F012345678",
                "RBP": "0x000000F012345690",
                "RSI": "0x0000000000000000",
                "RDI": "0x0000000000000000",
                "R8": "0x0000000000000000",
                "R9": "0x0000000000000000",
                "R10": "0x0000000000000000",
                "R11": "0x0000000000000000",
                "R12": "0x0000000000000000",
                "R13": "0x0000000000000000",
                "R14": "0x0000000000000000",
                "R15": "0x0000000000000000"
            },
            "modules": [
                {"name": "test_target.exe", "base_address": "0x140000000", "size": "0x10000"}
            ]
        }

        # Analyze crash with mock dump
        rca_report = CrashRootCauseAnalyzer.analyze_crash(mock_dump_data)
        self.assertEqual(rca_report["status"], "success")
        self.assertEqual(rca_report["exception_name"], "STATUS_ACCESS_VIOLATION")
        self.assertIn("NULL_POINTER_DEREFERENCE", rca_report["root_cause_classification"])
        self.assertIn("NULL", rca_report["remediation_advice"])

        # =====================================================================
        # STAGE 3: Real-Time ETW Capture & Causality Timeline
        # =====================================================================
        session = EtwLiveCaptureSession(session_name="IntegrationPipelineTrace", target_pid=1337)
        session.start_session()
        t_base = time.time()

        # Ingest timeline: allocation followed by deallocation (churn)
        session.record_event(EtwEventRecord(
            timestamp=t_base,
            provider_name="Microsoft-Windows-Kernel-Process",
            event_id=1,
            pid=1337,
            tid=100,
            event_type="THREAD_START"
        ))
        session.record_event(EtwEventRecord(
            timestamp=t_base + 0.1,
            provider_name="Microsoft-Windows-Kernel-Memory",
            event_id=98,
            pid=1337,
            tid=100,
            event_type="VIRTUAL_FREE",
            details={"address": "0x0000021000000000", "size": "0x100000"}
        ))
        session.stop_session()

        timeline = session.get_timeline(pid=1337)
        etw_correlation = EtwTimelineCorrelator.correlate_crash_timeline(timeline, crash_timestamp=t_base + 0.2)
        self.assertEqual(etw_correlation["temporal_verdict"], "TEMPORAL_MEMORY_CHURN_DETECTED")
        self.assertGreaterEqual(len(etw_correlation["causality_findings"]), 1)

        # =====================================================================
        # STAGE 4: Ghidra Live Bridge Injection & Verification
        # =====================================================================
        bridge_server = GhidraLiveBridgeServer(port=0, auth_token="pipe-token-42")
        bridge_server.start()

        try:
            client = GhidraLiveBridgeClient(
                bridge_url=f"http://127.0.0.1:{bridge_server.port}",
                auth_token="pipe-token-42"
            )

            # 1. Register Ghidra client
            reg = client.call_rpc("ghidra.register_client", {
                "program_name": "test_target.exe",
                "image_base": "0x140000000",
                "architecture": "x86_64"
            })
            self.assertEqual(reg["status"], "registered")

            # 2. Inject Stage 1 VAD Map
            inj_vad = bridge_server.inject_vad_snapshot(snapshot.to_dict())
            self.assertEqual(inj_vad["status"], "queued")

            # 3. Inject Stage 2 Crash RCA Report
            inj_rca = bridge_server.inject_crash_rca(rca_report)
            self.assertEqual(inj_rca["status"], "queued")
            self.assertEqual(inj_rca["fault_rva"], "0x1020")
            self.assertIn("NULL_POINTER_DEREFERENCE", inj_rca["root_cause"])

            # 4. Inject Stage 3 ETW Timeline Correlation
            inj_etw = bridge_server.inject_etw_timeline(etw_correlation)
            self.assertEqual(inj_etw["status"], "queued")
            self.assertEqual(inj_etw["verdict"], "TEMPORAL_MEMORY_CHURN_DETECTED")

            # 5. Ghidra script polls queued commands
            poll_res = client.call_rpc("ghidra.poll_commands")
            cmds = poll_res["commands"]
            self.assertEqual(len(cmds), 4)

            # Verify actions received in exact order
            self.assertEqual(cmds[0]["action"], "SET_PROGRAM_NOTE")
            self.assertIn("BINTRA_VAD_SPATIAL_LAYOUT", cmds[0]["details"]["title"])

            self.assertEqual(cmds[1]["action"], "SET_PLATE_COMMENT")
            self.assertEqual(cmds[1]["details"]["address"], "0x1020")
            self.assertIn("NULL_POINTER_DEREFERENCE", cmds[1]["details"]["comment"])

            self.assertEqual(cmds[2]["action"], "CREATE_BOOKMARK")
            self.assertEqual(cmds[2]["details"]["category"], "BINTRA_CRASH_FAULT")

            self.assertEqual(cmds[3]["action"], "SET_PROGRAM_NOTE")
            self.assertIn("BINTRA_ETW_PRE_CRASH_TIMELINE", cmds[3]["details"]["title"])

            # 6. Verify server queue is completely drained
            empty_poll = client.call_rpc("ghidra.poll_commands")
            self.assertEqual(empty_poll["count"], 0)

        finally:
            bridge_server.stop()


if __name__ == "__main__":
    unittest.main()
