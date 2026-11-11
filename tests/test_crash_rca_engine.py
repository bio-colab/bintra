# -*- coding: utf-8 -*-
"""
Test Suite for Automated Crash Root-Cause Analysis (RCA) Engine.
Verifies deterministic attribution of Access Violations (0xC0000005),
null-pointer dereferences, poison pattern detection (Use-After-Free),
instruction blame extraction, and MCP / CLI integration.
"""

import os
import sys
import unittest

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from security import ExecutionGuard, Capability
from windows_intelligence.runtime_telemetry import (
    CrashRootCauseAnalyzer,
    MiniDumpParser,
)


class TestCrashRootCauseAnalyzer(unittest.TestCase):
    """Verifies CrashRootCauseAnalyzer logic, register blame, and spatial classification."""

    def test_deterministic_null_pointer_dereference_attribution(self):
        """Verifies mathematical proof of NULL pointer dereference when base register is 0x0."""
        # Synthetic dump record representing a crash on `mov rax, qword ptr [rcx + 0x28]`
        synthetic_dump = {
            "status": "success",
            "format": "MINIDUMP",
            "exception_info": {
                "exception_code": "0xc0000005",
                "exception_name": "STATUS_ACCESS_VIOLATION",
                "fault_module": "target.exe",
                "fault_offset": "0x1050",
                "access_violation_details": {
                    "access_type": "READ",
                    "target_virtual_address": "0x28",
                    "is_null_pointer_dereference": True
                },
                "thread_registers": {
                    "arch": "x64",
                    "rip": "0x140001050",
                    "rsp": "0x500001000",
                    "rbp": "0x500001050",
                    "rax": "0x140000000",
                    "rcx": "0x0",  # Culprit NULL register
                    "rdx": "0x100"
                }
            },
            "modules": [
                {
                    "name": "target.exe",
                    "base_address": "0x140000000",
                    "size": 0x20000,
                    "path": r"C:\fake\target.exe"
                }
            ]
        }

        # Analyze crash
        report = CrashRootCauseAnalyzer.analyze_crash(synthetic_dump)

        self.assertEqual(report["status"], "success")
        self.assertEqual(report["exception_code"], "0xC0000005")
        self.assertEqual(report["access_type"], "READ")
        self.assertIn("NULL_PAGE_TRAP", report["memory_spatial_classification"]["category"])

        # Check attribution
        blame = report["blame_details"]
        self.assertIn("NULL_POINTER_DEREFERENCE", report["root_cause_classification"])
        self.assertEqual(int(report["target_address"], 16), 0x28)

        # Check remediation
        remediation = report["remediation_advice"]
        self.assertIn("nullptr", remediation)

        # Check Markdown formatting
        md_text = CrashRootCauseAnalyzer.format_markdown(report)
        self.assertIn("# Bintra Automated Crash Root-Cause Analysis (RCA)", md_text)
        self.assertIn("STATUS_ACCESS_VIOLATION", md_text)

    def test_poisoned_heap_use_after_free_attribution(self):
        """Verifies detection of MSVC 0xDDDDDDDDDDDDDDDD dead heap block pattern."""
        synthetic_uaf_dump = {
            "status": "success",
            "format": "MINIDUMP",
            "exception_info": {
                "exception_code": "0xc0000005",
                "exception_name": "STATUS_ACCESS_VIOLATION",
                "fault_module": "server_worker.dll",
                "fault_offset": "0x40A0",
                "access_violation_details": {
                    "access_type": "READ",
                    "target_virtual_address": "0xdddddddddddddddd",
                    "is_null_pointer_dereference": False
                },
                "thread_registers": {
                    "arch": "x64",
                    "rip": "0x1800040A0",
                    "rsp": "0x700002000",
                    "rbp": "0x700002050",
                    "rax": "0xdddddddddddddddd",
                    "rcx": "0x180000000"
                }
            },
            "modules": [
                {
                    "name": "server_worker.dll",
                    "base_address": "0x180000000",
                    "size": 0x50000,
                    "path": r"C:\fake\server_worker.dll"
                }
            ]
        }

        report = CrashRootCauseAnalyzer.analyze_crash(synthetic_uaf_dump)
        self.assertEqual(report["status"], "success")
        self.assertEqual(report["memory_spatial_classification"]["category"], "POISONED_POINTER")
        self.assertIn("MSVC_DEAD_FREED_HEAP_BLOCK", report["memory_spatial_classification"]["pattern"])
        self.assertEqual(report["root_cause_classification"], "USE_AFTER_FREE_OR_UNINITIALIZED")

    def test_operand_attribute_culprit_register_simulation(self):
        """Verifies operand parsing logic against simulated disassembly window."""
        disasm_report = {
            "available": True,
            "offending_instruction": {
                "rva": "0x1050",
                "mnemonic": "mov",
                "op_str": "rax, qword ptr [rcx + 0x28]",
                "is_faulting_instruction": True
            }
        }
        registers = {
            "arch": "x64",
            "rcx": "0x0",
            "rax": "0x140000000"
        }
        spatial_verdict = {
            "category": "NULL_PAGE_TRAP",
            "is_null_trap": True
        }

        blame = CrashRootCauseAnalyzer._attribute_culprit_register(
            disasm_report=disasm_report,
            registers=registers,
            target_vaddr=0x28,
            access_type="READ",
            spatial_verdict=spatial_verdict
        )

        self.assertEqual(blame["root_cause"], "DETERMINISTIC_NULL_POINTER_DEREFERENCE")
        self.assertEqual(blame["confidence"], "CONFIDENT_DETERMINISTIC")
        self.assertEqual(blame["culprit_register"], "RCX")
        self.assertEqual(blame["displacement"], "0x28")
        self.assertEqual(blame["operand_expression"], "[rcx+0x28]")

    def test_mcp_crash_rca_dispatch(self):
        """Verifies that native MCP server exposes bintra_crash_rca and dispatches cleanly."""
        from mcp_server import BintraMcpServer
        server = BintraMcpServer()

        tool_names = [t["name"] for t in server.handle_tools_list({})["tools"]]
        self.assertIn("bintra_crash_rca", tool_names)

        # Test tool metadata
        cap, mode, target = server.TOOL_SECURITY_METADATA["bintra_crash_rca"]
        self.assertEqual(cap, "cap.minidump.read")
        self.assertEqual(mode, "READ")
        self.assertEqual(target, "dmp_path")


if __name__ == "__main__":
    unittest.main()
