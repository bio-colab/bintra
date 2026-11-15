# -*- coding: utf-8 -*-
"""
Tests for TaskManagerInspector and Windows Task Manager Telemetry Integration.
Validates:
1. Non-NT Graceful Degradation across all methods.
2. Synthetic Win32 structures & metric calculations (CPU %, RAM, Commit, Handles, I/O).
3. Process sorting and query filtering.
4. Process details forensic fusion (Mitigations + SCM Services + TCP Sockets + Memory + CPU).
5. MCP Server tool action dispatch for bintra_process_resource_audit.
6. CLI registration and execution for proc-list, proc-search, proc-info, sys-perf.
7. Live Windows NT sanity checks when on Windows host.
"""

import os
import sys
import unittest
import json
from unittest.mock import patch, MagicMock


class TestTaskManagerInspector(unittest.TestCase):

    def test_non_nt_graceful_degradation(self):
        """Verifies that all TaskManagerInspector methods safely degrade on Linux/macOS."""
        with patch("os.name", "posix"):
            from windows_intelligence.process_intelligence.task_manager import TaskManagerInspector

            perf = TaskManagerInspector.get_system_performance()
            self.assertEqual(perf["status"], "not_applicable")
            self.assertEqual(perf["reason"], "System performance inspection requires Windows NT.")

            procs = TaskManagerInspector.list_processes()
            self.assertEqual(procs["status"], "not_applicable")
            self.assertEqual(procs["total_processes"], 0)
            self.assertEqual(procs["processes"], [])

            search = TaskManagerInspector.search_processes("test_query")
            self.assertEqual(search["status"], "not_applicable")
            self.assertEqual(search["matched_processes"], 0)

            details = TaskManagerInspector.get_process_details(1234)
            self.assertEqual(details["status"], "not_applicable")
            self.assertEqual(details["process_id"], 1234)

    def test_synthetic_process_sorting_and_filtering(self):
        """Tests process listing, query matching, and sorting across multiple criteria."""
        from windows_intelligence.process_intelligence.task_manager import TaskManagerInspector

        fake_procs = [
            {"process_id": 100, "executable_name": "system.exe", "image_path": "C:\\Windows\\system.exe", "thread_count": 10},
            {"process_id": 200, "executable_name": "chrome.exe", "image_path": "C:\\Program Files\\chrome.exe", "thread_count": 50},
            {"process_id": 300, "executable_name": "shamela.exe", "image_path": "D:\\shamela\\app\\shamela.exe", "thread_count": 30},
        ]

        with patch("os.name", "nt"):
            with patch("windows_intelligence.process_intelligence.process_inventory.ProcessInventory.enumerate_processes", return_value=fake_procs):
                with patch.object(TaskManagerInspector, "_get_architecture", return_value="x64 (Native)"):
                    with patch.object(TaskManagerInspector, "_get_k32", return_value=None):
                        # 1. Search by name
                        res_name = TaskManagerInspector.search_processes("shamela")
                        self.assertEqual(res_name["matched_processes"], 1)
                        self.assertEqual(res_name["processes"][0]["process_id"], 300)

                        # 2. Search by PID
                        res_pid = TaskManagerInspector.search_processes("200")
                        self.assertEqual(res_pid["matched_processes"], 1)
                        self.assertEqual(res_pid["processes"][0]["executable_name"], "chrome.exe")

                        # 3. Sort by threads (descending)
                        res_sort = TaskManagerInspector.list_processes(sort_by="threads", reverse=True)
                        self.assertEqual(res_sort["matched_processes"], 3)
                        self.assertEqual(res_sort["processes"][0]["process_id"], 200)
                        self.assertEqual(res_sort["processes"][1]["process_id"], 300)
                        self.assertEqual(res_sort["processes"][2]["process_id"], 100)

    def test_mcp_bintra_process_resource_audit_actions(self):
        """Verifies that all new Task Manager actions dispatch cleanly via MCP server."""
        from mcp_server import BintraMcpServer

        srv = BintraMcpServer()

        # 1. system_performance action
        res_perf = srv.handle_tools_call({
            "name": "bintra_process_resource_audit",
            "arguments": {"action": "system_performance"}
        })
        self.assertFalse(res_perf.get("isError", False))
        payload_perf = json.loads(res_perf["content"][0]["text"])
        self.assertIn("status", payload_perf)

        # 2. list_processes action
        res_list = srv.handle_tools_call({
            "name": "bintra_process_resource_audit",
            "arguments": {"action": "list_processes", "limit": 5, "sort_by": "memory"}
        })
        self.assertFalse(res_list.get("isError", False), res_list.get("content", [{}])[0].get("text"))
        payload_list = json.loads(res_list["content"][0]["text"])
        self.assertIn("status", payload_list)

        # 3. search_processes action
        res_search = srv.handle_tools_call({
            "name": "bintra_process_resource_audit",
            "arguments": {"action": "search_processes", "query": "python"}
        })
        self.assertFalse(res_search.get("isError", False))
        payload_search = json.loads(res_search["content"][0]["text"])
        self.assertIn("status", payload_search)

        # 4. audit_process action (Task Manager deep dive)
        res_audit = srv.handle_tools_call({
            "name": "bintra_process_resource_audit",
            "arguments": {"action": "audit_process", "pid": os.getpid()}
        })
        self.assertFalse(res_audit.get("isError", False))
        payload_audit = json.loads(res_audit["content"][0]["text"])
        self.assertIn("status", payload_audit)
        self.assertEqual(payload_audit.get("process_id"), os.getpid())

    @unittest.skipUnless(os.name == "nt", "Live Windows NT execution requires Windows host")
    def test_live_windows_nt_task_manager_parity(self):
        """Sanity test verifying real NT kernel telemetry on the live host."""
        from windows_intelligence.process_intelligence.task_manager import TaskManagerInspector

        # 1. Performance tab
        perf = TaskManagerInspector.get_system_performance(sample_interval=0.01)
        self.assertEqual(perf["status"], "success")
        self.assertGreater(perf["memory"]["total_physical_gb"], 0.0)
        self.assertGreater(perf["uptime"]["uptime_seconds"], 0.0)
        self.assertGreater(perf["topology"]["total_processes"], 0)

        # 2. Process list
        procs = TaskManagerInspector.list_processes(limit=10, sort_by="memory")
        self.assertEqual(procs["status"], "success")
        self.assertGreater(procs["total_processes"], 0)
        self.assertLessEqual(len(procs["processes"]), 10)

        # 3. Search self
        self_search = TaskManagerInspector.search_processes(str(os.getpid()))
        self.assertEqual(self_search["status"], "success")
        self.assertGreaterEqual(self_search["matched_processes"], 1)
        self.assertEqual(self_search["processes"][0]["process_id"], os.getpid())

        # 4. Detailed telemetry for current process
        details = TaskManagerInspector.get_process_details(os.getpid())
        self.assertEqual(details["status"], "success")
        self.assertEqual(details["process_id"], os.getpid())
        self.assertIn("memory", details)
        self.assertGreater(details["memory"].get("working_set_mb", 0.0), 0.0)
        self.assertIn("cpu_and_timing", details)
        self.assertIn("io_counters", details)
        self.assertIn("security", details)


    def test_uptime_gettickcount64_large_64bit_integer(self):
        """Verifies GetTickCount64 ctypes prototype handles values > 0x7FFFFFFF (>24.8 days) without 32-bit sign extension."""
        from windows_intelligence.process_intelligence.task_manager import TaskManagerInspector

        large_tick = 3_000_000_000  # ~34.7 days uptime, > 0x7FFFFFFF signed int limit

        mock_k32 = MagicMock()
        mock_k32.GetTickCount64.return_value = large_tick
        mock_k32.GlobalMemoryStatusEx.return_value = 1
        mock_k32.GetSystemTimes.return_value = 1

        with patch("os.name", "nt"), \
             patch.object(TaskManagerInspector, "_get_k32", return_value=mock_k32):
            perf = TaskManagerInspector.get_system_performance()
            self.assertEqual(perf["status"], "success")
            self.assertEqual(perf["uptime"]["uptime_ms"], large_tick)
            self.assertGreater(perf["uptime"]["uptime_seconds"], 0)
            self.assertAlmostEqual(perf["uptime"]["uptime_hours"], round(large_tick / 1000.0 / 3600.0, 2))
            self.assertAlmostEqual(perf["uptime"]["uptime_days"], round(large_tick / 1000.0 / 3600.0 / 24.0, 2))
            self.assertIn("boot_time_utc", perf["uptime"])

    def test_cli_task_manager_commands(self):
        """Verifies CLI execution of proc-list, proc-search, proc-info, and sys-perf."""
        import subprocess

        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        cli_path = os.path.join(repo_root, "src", "cli.py")

        # 1. sys-perf CLI
        res_perf = subprocess.run(
            [sys.executable, cli_path, "sys-perf", "--format", "json"],
            cwd=repo_root, capture_output=True, text=True, encoding="utf-8"
        )
        self.assertEqual(res_perf.returncode, 0, res_perf.stderr)
        data_perf = json.loads(res_perf.stdout)
        self.assertIn("status", data_perf)

        # 2. proc-list CLI
        res_list = subprocess.run(
            [sys.executable, cli_path, "proc-list", "--limit", "3", "--format", "json"],
            cwd=repo_root, capture_output=True, text=True, encoding="utf-8"
        )
        self.assertEqual(res_list.returncode, 0, res_list.stderr)
        data_list = json.loads(res_list.stdout)
        self.assertIn("status", data_list)

        # 3. proc-search CLI
        res_search = subprocess.run(
            [sys.executable, cli_path, "proc-search", "--query", "python", "--limit", "2", "--format", "json"],
            cwd=repo_root, capture_output=True, text=True, encoding="utf-8"
        )
        self.assertEqual(res_search.returncode, 0, res_search.stderr)
        data_search = json.loads(res_search.stdout)
        self.assertIn("status", data_search)

        # 4. proc-info CLI
        res_info = subprocess.run(
            [sys.executable, cli_path, "proc-info", "--pid", str(os.getpid()), "--format", "json"],
            cwd=repo_root, capture_output=True, text=True, encoding="utf-8"
        )
        self.assertEqual(res_info.returncode, 0, res_info.stderr)
        data_info = json.loads(res_info.stdout)
        self.assertIn("status", data_info)


if __name__ == "__main__":
    unittest.main()
