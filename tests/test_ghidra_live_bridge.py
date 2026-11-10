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

    def test_structure_dissection_injection(self):
        """Verifies structure dissection injection queues composite struct, bookmark, and note."""
        server = GhidraLiveBridgeServer(port=0, auth_token="tok-struct-1")
        server.start()
        try:
            struct_mock = {
                "pid": 1337,
                "base_address": "0x00007FF712340000",
                "structure_name": "EntityActor",
                "size_analyzed": 64,
                "fields_count": 3,
                "fields": [
                    {"offset": "0x0", "offset_bytes": 0, "inferred_type": "void**", "description": "vtable"},
                    {"offset": "0x8", "offset_bytes": 8, "inferred_type": "int32_t", "description": "health"},
                    {"offset": "0x10", "offset_bytes": 16, "inferred_type": "void*", "description": "p_name"}
                ],
                "c_struct_definition": "struct EntityActor {\n    void** vtable;\n    int32_t health;\n    void* p_name;\n};"
            }
            res = server.inject_structure_dissection(struct_mock)
            self.assertEqual(res["status"], "queued")
            self.assertEqual(res["structure_name"], "EntityActor")
            self.assertEqual(res["actions_queued"], 3)

            # Client polling
            client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{server.port}", auth_token="tok-struct-1")
            poll = client.poll_commands()
            cmds = poll["commands"]
            self.assertEqual(len(cmds), 3)

            action_types = [c["action"] for c in cmds]
            self.assertIn("APPLY_DATA_STRUCTURE", action_types)
            self.assertIn("CREATE_BOOKMARK", action_types)
            self.assertIn("SET_PROGRAM_NOTE", action_types)

            apply_cmd = [c for c in cmds if c["action"] == "APPLY_DATA_STRUCTURE"][0]
            self.assertEqual(apply_cmd["details"]["name"], "EntityActor")
            self.assertEqual(len(apply_cmd["details"]["fields"]), 3)
        finally:
            server.stop()

    def test_pointer_chains_injection(self):
        """Verifies multi-level pointer scan path injection into Ghidra."""
        server = GhidraLiveBridgeServer(port=0, auth_token="tok-ptr-1")
        server.start()
        try:
            pointer_mock = {
                "pid": 2048,
                "target_address": "0x00007FF799990000",
                "paths_count": 2,
                "paths": [
                    {
                        "depth": 1,
                        "base_module": "target.exe",
                        "base_rva": "0x14500",
                        "offsets": ["0x20"],
                        "expression": "[target.exe+0x14500] + 0x20"
                    },
                    {
                        "depth": 2,
                        "base_module": "target.exe",
                        "base_rva": "0x14510",
                        "offsets": ["0x10", "0x8"],
                        "expression": "[[target.exe+0x14510] + 0x10] + 0x8"
                    }
                ]
            }
            res = server.inject_pointer_chains(pointer_mock)
            self.assertEqual(res["status"], "queued")
            self.assertEqual(res["paths_queued"], 2)
            # 2 paths * 2 (plate + bookmark) + 1 program note = 5
            self.assertEqual(res["actions_queued"], 5)

            client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{server.port}", auth_token="tok-ptr-1")
            poll = client.poll_commands()
            cmds = poll["commands"]
            self.assertEqual(len(cmds), 5)

            actions = [c["action"] for c in cmds]
            self.assertEqual(actions.count("SET_PLATE_COMMENT"), 2)
            self.assertEqual(actions.count("CREATE_BOOKMARK"), 2)
            self.assertEqual(actions.count("SET_PROGRAM_NOTE"), 1)
        finally:
            server.stop()

    def test_client_convenience_methods(self):
        """Verifies typed client convenience methods against running server."""
        server = GhidraLiveBridgeServer(port=0, auth_token="tok-conv-1")
        server.start()
        try:
            client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{server.port}", auth_token="tok-conv-1")
            ping = client.ping()
            self.assertEqual(ping["status"], "ok")

            st = client.get_status()
            self.assertTrue(st["is_running"])

            reg = client.register_client("app.exe", "0x140000000", "x86_64")
            self.assertEqual(reg["status"], "registered")

            struct_mock = {
                "base_address": "0x14001000",
                "structure_name": "TestStruct",
                "fields": [],
                "c_struct_definition": "struct TestStruct {};"
            }
            inj_s = client.inject_structure_dissection(struct_mock)
            self.assertEqual(inj_s["status"], "queued")

            ptr_mock = {
                "target_address": "0x14002000",
                "paths": [{"base_rva": "0x100", "expression": "[app.exe+0x100]", "base_module": "app.exe"}]
            }
            inj_p = client.inject_pointer_chains(ptr_mock)
            self.assertEqual(inj_p["status"], "queued")

            poll = client.poll_commands()
            self.assertGreater(poll["count"], 0)
        finally:
            server.stop()

    def test_tempdir_discovery_marker(self):
        """Verifies discovery marker is published to system temp dir and cleaned up on stop."""
        server = GhidraLiveBridgeServer(port=0, auth_token="tok-temp-1")
        server.start()
        temp_marker = os.path.join(tempfile.gettempdir(), ".rea_bridge.json")
        try:
            self.assertTrue(os.path.isfile(temp_marker))
            with open(temp_marker, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["port"], server.port)
            self.assertEqual(data["auth_token"], "tok-temp-1")
        finally:
            server.stop()
            self.assertFalse(os.path.isfile(temp_marker))

    def test_mcp_extended_bridge_actions(self):
        """Verifies inject_struct and inject_pointers via ReaMcpServer."""
        from mcp_server import ReaMcpServer
        mcp = ReaMcpServer()

        # Start bridge
        mcp.handle_tools_call({
            "name": "rea_ghidra_live_bridge",
            "arguments": {"action": "start", "port": 0, "auth_token": "mcp-ext-tok"}
        })

        try:
            # Inject struct
            res_struct = mcp.handle_tools_call({
                "name": "rea_ghidra_live_bridge",
                "arguments": {
                    "action": "inject_struct",
                    "struct_report": {
                        "base_address": "0x7FF70001",
                        "structure_name": "MCPDissected",
                        "fields": [],
                        "c_struct_definition": "struct MCPDissected {};"
                    }
                }
            })
            self.assertFalse(res_struct.get("isError", False))
            data_s = json.loads(res_struct["content"][0]["text"])
            self.assertEqual(data_s["status"], "queued")

            # Inject pointers
            res_ptr = mcp.handle_tools_call({
                "name": "rea_ghidra_live_bridge",
                "arguments": {
                    "action": "inject_pointers",
                    "pointer_report": {
                        "target_address": "0x7FF70002",
                        "paths": [{"base_rva": "0x50", "expression": "[mcp.exe+0x50]"}]
                    }
                }
            })
            self.assertFalse(res_ptr.get("isError", False))
            data_p = json.loads(res_ptr["content"][0]["text"])
            self.assertEqual(data_p["status"], "queued")
        finally:
            mcp.handle_tools_call({
                "name": "rea_ghidra_live_bridge",
                "arguments": {"action": "stop"}
            })


if __name__ == "__main__":
    unittest.main()
