# -*- coding: utf-8 -*-
"""
Test Suite for Ghidra Live Bidirectional IPC Bridge.
Verifies server lifecycle, authentication token gating, client registration,
command queueing/polling, diagnostic injection (Crash RCA, VAD, ETW),
and MCP / CLI integration.
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
from ghidra_live_bridge import (
    GhidraLiveBridgeServer,
    GhidraLiveBridgeClient,
    get_or_create_bridge,
    get_active_bridge,
    stop_active_bridge
)


class TestGhidraLiveBridge(unittest.TestCase):
    """Verifies bidirectional communication and diagnostic annotation between REA-Neural and Ghidra."""

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

    def test_server_lifecycle_and_discovery_marker(self):
        """Verifies server start on dynamic port, marker creation, and clean shutdown."""
        # Use port 0 for automatic free port allocation
        server = GhidraLiveBridgeServer(port=0, auth_token="test-token-1234")
        marker = os.path.join(self.temp_ws.name, ".rea_bridge.json")
        res = server.start(marker_path=marker)

        try:
            self.assertTrue(server.is_running)
            self.assertGreater(server.port, 0)
            self.assertEqual(res["auth_token"], "test-token-1234")
            self.assertTrue(os.path.exists(marker))

            with open(marker, "r", encoding="utf-8") as f:
                marker_data = json.load(f)
            self.assertEqual(marker_data["port"], server.port)
            self.assertEqual(marker_data["auth_token"], "test-token-1234")

            # Ping test
            client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{server.port}", auth_token="test-token-1234")
            ping_res = client.call_rpc("ping")
            self.assertEqual(ping_res["status"], "ok")
            self.assertEqual(ping_res["bridge_version"], "7.4.0")
        finally:
            stop_res = server.stop()
            self.assertFalse(server.is_running)
            self.assertEqual(stop_res["status"], "stopped")
            self.assertFalse(os.path.exists(marker))

    def test_auth_token_enforcement(self):
        """Verifies unauthenticated or forged token calls are strictly rejected."""
        server = GhidraLiveBridgeServer(port=0, auth_token="secret-gate-token")
        server.start()
        try:
            # 1. Unauthenticated client (no token)
            unauth_client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{server.port}", auth_token=None)
            # ping is public handshake
            p = unauth_client.call_rpc("ping")
            self.assertEqual(p["status"], "ok")

            # Protected method fails without token
            with self.assertRaises(RuntimeError) as ctx:
                unauth_client.call_rpc("get_status")
            self.assertIn("Authentication failed", str(ctx.exception))

            # 2. Forged token client
            forged_client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{server.port}", auth_token="bad-token")
            with self.assertRaises(RuntimeError) as ctx2:
                forged_client.call_rpc("get_status")
            self.assertIn("Authentication failed", str(ctx2.exception))

            # 3. Valid token succeeds
            valid_client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{server.port}", auth_token="secret-gate-token")
            st = valid_client.call_rpc("get_status")
            self.assertTrue(st["is_running"])
            self.assertEqual(st["auth_token"], "secret-gate-token")
        finally:
            server.stop()

    def test_client_registration_and_status(self):
        """Verifies Ghidra client handshake and heartbeat tracking."""
        server = GhidraLiveBridgeServer(port=0, auth_token="tok-reg-1")
        server.start()
        try:
            client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{server.port}", auth_token="tok-reg-1")
            status_before = client.call_rpc("get_status")
            self.assertFalse(status_before["client_connected"])

            # Register client
            reg_info = {
                "program_name": "target_fault.exe",
                "image_base": "0x140000000",
                "architecture": "x86_64",
                "ghidra_version": "12.0"
            }
            reg_res = client.call_rpc("ghidra.register_client", reg_info)
            self.assertEqual(reg_res["status"], "registered")

            # Check status after registration
            status_after = client.call_rpc("get_status")
            self.assertTrue(status_after["client_connected"])
            self.assertEqual(status_after["client_metadata"]["program_name"], "target_fault.exe")
            self.assertEqual(status_after["client_metadata"]["image_base"], "0x140000000")
        finally:
            server.stop()

    def test_diagnostic_injections_and_queue_drainage(self):
        """Verifies Crash RCA, VAD map, and ETW timeline queueing and drainage by Ghidra."""
        server = GhidraLiveBridgeServer(port=0, auth_token="tok-diag-2")
        server.start()
        try:
            # 1. Inject Crash RCA
            rca_mock = {
                "fault_rva": "0x140001020",
                "exception_name": "STATUS_ACCESS_VIOLATION",
                "exception_code": "0xc0000005",
                "root_cause_classification": "NULL_POINTER_DEREFERENCE",
                "confidence": "HIGH",
                "culprit_register": "RCX",
                "culprit_register_value": "0x0000000000000000",
                "target_address": "0x0000000000000000",
                "access_type": "READ",
                "remediation_advice": "Check null pointer before dereferencing RCX."
            }
            q_rca = server.inject_crash_rca(rca_mock)
            self.assertEqual(q_rca["status"], "queued")
            self.assertEqual(q_rca["actions_queued"], 2)

            # 2. Inject VAD Snapshot
            vad_mock = {
                "pid": 5555,
                "process_name": "worker.exe",
                "summary": {
                    "commit_mb": 128.5,
                    "image_mb": 32.0,
                    "heap_mb": 45.0,
                    "wx_regions_count": 0,
                    "total_regions": 64
                }
            }
            q_vad = server.inject_vad_snapshot(vad_mock)
            self.assertEqual(q_vad["status"], "queued")

            # 3. Inject ETW Timeline
            timeline_mock = {
                "temporal_verdict": "VIRTUAL_FREE_CHURN_DETECTED",
                "causality_findings": [
                    {"category": "MEMORY_CHURN", "description": "Deallocation within 200ms of fault"}
                ],
                "events_count": 42
            }
            q_etw = server.inject_etw_timeline(timeline_mock)
            self.assertEqual(q_etw["status"], "queued")

            # Ghidra polls commands
            client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{server.port}", auth_token="tok-diag-2")
            poll_res = client.call_rpc("ghidra.poll_commands")
            cmds = poll_res["commands"]
            self.assertEqual(len(cmds), 4)

            actions = [c["action"] for c in cmds]
            self.assertEqual(actions, ["SET_PLATE_COMMENT", "CREATE_BOOKMARK", "SET_PROGRAM_NOTE", "SET_PROGRAM_NOTE"])

            # Verify queue was cleared upon polling
            poll_empty = client.call_rpc("ghidra.poll_commands")
            self.assertEqual(poll_empty["count"], 0)
        finally:
            server.stop()

    def test_mcp_tool_ghidra_live_bridge(self):
        """Verifies rea_ghidra_live_bridge execution through ReaMcpServer."""
        from mcp_server import ReaMcpServer
        mcp = ReaMcpServer()

        # 1. Start action
        start_req = {
            "name": "rea_ghidra_live_bridge",
            "arguments": {
                "action": "start",
                "port": 0,
                "auth_token": "mcp-bridge-token"
            }
        }
        res_start = mcp.handle_tools_call(start_req)
        self.assertFalse(res_start.get("isError", False))
        data_start = json.loads(res_start["content"][0]["text"])
        self.assertTrue(data_start.get("is_running"))

        # 2. Status action
        status_req = {
            "name": "rea_ghidra_live_bridge",
            "arguments": {"action": "status"}
        }
        res_status = mcp.handle_tools_call(status_req)
        self.assertFalse(res_status.get("isError", False))
        data_status = json.loads(res_status["content"][0]["text"])
        self.assertTrue(data_status.get("is_running"))
        self.assertEqual(data_status.get("auth_token"), "mcp-bridge-token")

        # 3. Stop action
        stop_req = {
            "name": "rea_ghidra_live_bridge",
            "arguments": {"action": "stop"}
        }
        res_stop = mcp.handle_tools_call(stop_req)
        self.assertFalse(res_stop.get("isError", False))
        data_stop = json.loads(res_stop["content"][0]["text"])
        self.assertEqual(data_stop.get("status"), "stopped")


if __name__ == "__main__":
    unittest.main()
