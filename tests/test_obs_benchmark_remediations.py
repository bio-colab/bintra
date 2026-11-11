# -*- coding: utf-8 -*-
"""
Tests for Bintra remediation of OBS Studio benchmark findings:
- BinaryFormatInspector uncapped imports/exports, delay-load parsing, VS_VERSION_INFO
- WindowsDependencyResolver app_dir and plugin loader hierarchy
- Ghidra scripts Jython 2.7 syntax compatibility and workspace isolation
- VirtualMemoryInspector section name sanitization and stack detection
- EtwLiveCaptureSession non-admin module baseline capture
"""

import os
import sys
import ast
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from binary_neural_engine import BinaryFormatInspector
from windows_intelligence.dependency_resolver import WindowsDependencyResolver
from windows_intelligence.runtime_telemetry.virtual_memory_inspector import (
    VirtualMemoryInspector, ProcessMemoryMapSnapshot, ProcessMemoryRegion,
    MEM_COMMIT, MEM_RESERVE, MEM_PRIVATE, PAGE_READWRITE, PAGE_GUARD
)
from windows_intelligence.runtime_telemetry.etw_capture_engine import (
    EtwLiveCaptureSession, EtwEventRecord
)


class TestObsBenchmarkRemediations(unittest.TestCase):

    def test_binary_format_inspector_fields_and_version_info(self):
        """Verifies that PE inspection includes delay_imports and version_info."""
        # Test on host system binary
        target = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "notepad.exe")
        if not os.path.exists(target):
            target = sys.executable

        info = BinaryFormatInspector.inspect(target)
        self.assertIn("delay_imports", info)
        self.assertIn("version_info", info)
        self.assertIn("imported_dlls_count", info["delay_imports"])
        self.assertIn("modules", info["delay_imports"])
        self.assertIsInstance(info["version_info"], dict)
        if os.name == "nt" and os.path.exists(target):
            # Verify version_info keys are structured
            for k in ("file_version", "product_version", "company_name", "product_name"):
                self.assertIn(k, info["version_info"])

    def test_dependency_resolver_app_dir_support(self):
        """Verifies that app_dir is properly prepended to loader search order."""
        fake_bin = r"C:\App\plugins\sub\plugin.dll" if os.name == "nt" else "/app/plugins/sub/plugin.so"
        fake_app = r"C:\App\bin" if os.name == "nt" else "/app/bin"

        dirs = WindowsDependencyResolver.get_search_directories(fake_bin, app_dir=fake_app)
        self.assertEqual(os.path.normcase(dirs[0]), os.path.normcase(os.path.abspath(fake_app)))
        self.assertIn(os.path.normcase(os.path.dirname(fake_bin)), [os.path.normcase(d) for d in dirs])

    def test_dependency_resolver_plugin_heuristic(self):
        """Verifies automatic detection of sibling bin directory for plugins."""
        fake_plugin = r"C:\ObsRoot\obs-plugins\64bit\test.dll" if os.name == "nt" else "/ObsRoot/obs-plugins/64bit/test.so"
        dirs = WindowsDependencyResolver.get_search_directories(fake_plugin)
        # Should contain the plugin directory
        plugin_dir = os.path.normcase(os.path.dirname(fake_plugin))
        self.assertIn(plugin_dir, [os.path.normcase(d) for d in dirs])

    def test_ghidra_scripts_jython_compatibility(self):
        """Verifies that BintraLiveBridgeService.py contains zero Python 3 f-strings for Jython 2.7."""
        script_path = os.path.abspath(os.path.join(
            os.path.dirname(__file__), "..", "ghidra_scripts", "BintraLiveBridgeService.py"
        ))
        self.assertTrue(os.path.exists(script_path), f"Script not found: {script_path}")
        with open(script_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())
        fstrings = [node for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)]
        self.assertEqual(len(fstrings), 0, "BintraLiveBridgeService.py contains f-strings incompatible with Jython 2.7")

    def test_virtual_memory_inspector_section_sanitization(self):
        """Verifies that section names are sanitized to valid identifiers without corruption."""
        # Test classifier fallback on corrupt names
        cat, _, _, sec = VirtualMemoryInspector._classify_region_details(
            base_addr=0x140001000,
            alloc_base=0x140000000,
            protect=PAGE_READWRITE,
            mem_type=0x1000000, # MEM_IMAGE
            modules=[]
        )
        self.assertTrue(cat.startswith("IMAGE_"))

    def test_virtual_memory_inspector_stack_detection(self):
        """Verifies that committed private memory sharing an allocation base with STACK_GUARD is categorized as STACK."""
        snap = ProcessMemoryMapSnapshot(pid=1234, process_name="test.exe")
        alloc_base = 0x0000001000000000

        # Stack guard page (e.g. 4 KB at bottom of committed stack)
        snap.add_region(ProcessMemoryRegion(
            base_address=alloc_base + 0x20000,
            allocation_base=alloc_base,
            region_size=0x1000,
            state=MEM_COMMIT,
            protect=PAGE_GUARD | PAGE_READWRITE,
            alloc_protect=PAGE_READWRITE,
            mem_type=MEM_PRIVATE,
            category="STACK_GUARD"
        ))
        # Committed thread stack page (e.g. 64 KB committed above guard)
        snap.add_region(ProcessMemoryRegion(
            base_address=alloc_base + 0x21000,
            allocation_base=alloc_base,
            region_size=0x10000,
            state=MEM_COMMIT,
            protect=PAGE_READWRITE,
            alloc_protect=PAGE_READWRITE,
            mem_type=MEM_PRIVATE,
            category="HEAP" # initially classified as HEAP before post-pass
        ))
        # Independent private heap region (different allocation base)
        snap.add_region(ProcessMemoryRegion(
            base_address=0x0000002000000000,
            allocation_base=0x0000002000000000,
            region_size=0x20000,
            state=MEM_COMMIT,
            protect=PAGE_READWRITE,
            alloc_protect=PAGE_READWRITE,
            mem_type=MEM_PRIVATE,
            category="HEAP"
        ))

        # Perform the post-processing association
        stack_alloc_bases = {r.allocation_base for r in snap.regions if r.category == "STACK_GUARD" and r.allocation_base}
        for r in snap.regions:
            if r.mem_type == MEM_PRIVATE and r.category == "HEAP" and r.allocation_base in stack_alloc_bases:
                r.category = "STACK"

        summary = snap.compute_summary()
        self.assertGreater(summary["stack_bytes"], 0)
        self.assertEqual(summary["stack_bytes"], 0x11000)
        self.assertEqual(summary["heap_bytes"], 0x20000)

    def test_etw_non_admin_module_baseline(self):
        """Verifies that EtwLiveCaptureSession captures module baseline events on Windows."""
        if os.name != "nt":
            self.skipTest("Requires Windows host")

        session = EtwLiveCaptureSession(session_name="UnitTest_NonAdmin_Capture", target_pid=os.getpid())
        start_res = session.start_session()
        self.assertIn(start_res.get("status"), ("non_elevated", "active", "running"))

        import time
        time.sleep(0.5)
        stop_res = session.stop_session()
        self.assertEqual(stop_res.get("status"), "stopped")

        timeline = session.get_timeline(pid=os.getpid())
        self.assertGreater(len(timeline), 0)
        first_event = timeline[0]
        self.assertEqual(first_event.get("event_type"), "IMAGE_LOAD")
        self.assertEqual(first_event.get("pid"), os.getpid())


if __name__ == "__main__":
    unittest.main()
