# -*- coding: utf-8 -*-
"""
Test Suite for REA-Neural Passive Virtual Memory & VAD Layout Inspector.
Verifies spatial memory mapping, page classification, W^X auditing,
null-pointer trap detection, snapshot diffing, and ExecutionGuard mediation.
"""

import os
import sys
import unittest

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from security import ExecutionGuard, Capability
from windows_intelligence.runtime_telemetry import (
    VirtualMemoryInspector,
    ProcessMemoryMapSnapshot,
    ProcessMemoryRegion,
    ProcessMemoryScanner,
    PointerScanner,
    StructureDissector,
)
from windows_intelligence.runtime_telemetry.virtual_memory_inspector import (
    MEM_COMMIT,
    MEM_RESERVE,
    MEM_FREE,
    MEM_IMAGE,
    MEM_PRIVATE,
    MEM_MAPPED,
    PAGE_READONLY,
    PAGE_READWRITE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
    PAGE_GUARD,
    PAGE_NOACCESS,
)


class TestVirtualMemoryInspector(unittest.TestCase):
    """Verifies core VAD inspector and spatial memory analysis invariants."""

    def setUp(self):
        self.pid = os.getpid()

    def test_memory_region_properties_and_classification(self):
        """Verifies ProcessMemoryRegion boundary math, protection parsing, and W^X detection."""
        # Clean read-execute code region
        r_code = ProcessMemoryRegion(
            base_address=0x140001000,
            allocation_base=0x140000000,
            region_size=0x4000,
            state=MEM_COMMIT,
            protect=PAGE_EXECUTE_READ,
            alloc_protect=PAGE_EXECUTE_WRITECOPY,
            mem_type=MEM_IMAGE,
            category="IMAGE_TEXT",
            module_name="target.exe",
            section_name=".text",
            rva=0x1000
        )
        self.assertEqual(r_code.end_address, 0x140005000)
        self.assertTrue(r_code.contains(0x140001000))
        self.assertTrue(r_code.contains(0x140004FFF))
        self.assertFalse(r_code.contains(0x140005000))
        self.assertTrue(r_code.is_executable())
        self.assertFalse(r_code.is_writable())
        self.assertFalse(r_code.is_wx())
        self.assertEqual(r_code.state_str(), "MEM_COMMIT")
        self.assertEqual(r_code.type_str(), "MEM_IMAGE")
        self.assertIn("PAGE_EXECUTE_READ", r_code.protect_str())

        # W^X hazardous region (both writable and executable)
        r_wx = ProcessMemoryRegion(
            base_address=0x20000000,
            allocation_base=0x20000000,
            region_size=0x1000,
            state=MEM_COMMIT,
            protect=PAGE_EXECUTE_READWRITE,
            alloc_protect=PAGE_EXECUTE_READWRITE,
            mem_type=MEM_PRIVATE,
            category="JIT_OR_DYNAMIC_CODE"
        )
        self.assertTrue(r_wx.is_executable())
        self.assertTrue(r_wx.is_writable())
        self.assertTrue(r_wx.is_wx())

        # Stack guard page
        r_guard = ProcessMemoryRegion(
            base_address=0x50000000,
            allocation_base=0x50000000,
            region_size=0x1000,
            state=MEM_COMMIT,
            protect=PAGE_READWRITE | PAGE_GUARD,
            alloc_protect=PAGE_READWRITE,
            mem_type=MEM_PRIVATE,
            category="STACK_GUARD"
        )
        self.assertTrue(r_guard.is_guard_page())
        self.assertIn("PAGE_GUARD", r_guard.protect_str())

    def test_snapshot_summary_and_address_classification(self):
        """Verifies ProcessMemoryMapSnapshot aggregation and multi-class address categorization."""
        snap = ProcessMemoryMapSnapshot(pid=1234, process_name="test_app.exe", architecture="x86-64")

        # Add image sections
        snap.add_region(ProcessMemoryRegion(0x140000000, 0x140000000, 0x1000, MEM_COMMIT, PAGE_READONLY, PAGE_READONLY, MEM_IMAGE, "IMAGE_HEADER", "test_app.exe"))
        snap.add_region(ProcessMemoryRegion(0x140001000, 0x140000000, 0x10000, MEM_COMMIT, PAGE_EXECUTE_READ, PAGE_EXECUTE_READ, MEM_IMAGE, "IMAGE_TEXT", "test_app.exe", section_name=".text"))
        snap.add_region(ProcessMemoryRegion(0x140011000, 0x140000000, 0x5000, MEM_COMMIT, PAGE_READWRITE, PAGE_READWRITE, MEM_IMAGE, "IMAGE_DATA", "test_app.exe", section_name=".data"))

        # Add heap and stack
        snap.add_region(ProcessMemoryRegion(0x20000000000, 0x20000000000, 0x80000, MEM_COMMIT, PAGE_READWRITE, PAGE_READWRITE, MEM_PRIVATE, "HEAP"))
        snap.add_region(ProcessMemoryRegion(0x50000000000, 0x50000000000, 0x20000, MEM_COMMIT, PAGE_READWRITE, PAGE_READWRITE, MEM_PRIVATE, "STACK"))

        # Add uncommitted reserved page
        snap.add_region(ProcessMemoryRegion(0x60000000000, 0x60000000000, 0x100000, MEM_RESERVE, PAGE_NOACCESS, PAGE_NOACCESS, MEM_PRIVATE, "RESERVED"))

        summary = snap.compute_summary()
        self.assertEqual(summary["total_regions"], 6)
        self.assertGreater(summary["commit_bytes"], 0)
        self.assertGreater(summary["image_bytes"], 0)
        self.assertGreater(summary["heap_bytes"], 0)
        self.assertGreater(summary["stack_bytes"], 0)
        self.assertEqual(summary["wx_regions_count"], 0)

        # 1. Null Pointer Trap test
        cls_null = snap.classify_address(0x0)
        self.assertEqual(cls_null["status"], "FAULT_NULL_DEREFERENCE")
        self.assertEqual(cls_null["category"], "NULL_PAGE_TRAP")

        cls_null_off = snap.classify_address(0x48)
        self.assertEqual(cls_null_off["status"], "FAULT_NULL_DEREFERENCE")
        self.assertEqual(cls_null_off["offset_from_null"], 0x48)

        # 2. Kernel Boundary test
        cls_kern = snap.classify_address(0xFFFF800000000000)
        self.assertEqual(cls_kern["status"], "FAULT_KERNEL_BOUNDARY")
        self.assertEqual(cls_kern["category"], "KERNEL_SPACE")

        # 3. Image Code (.text) test
        cls_code = snap.classify_address(0x1400025A0)
        self.assertEqual(cls_code["status"], "COMMITTED")
        self.assertEqual(cls_code["category"], "IMAGE_TEXT")
        self.assertEqual(cls_code["module_name"], "test_app.exe")
        self.assertEqual(cls_code["section_name"], ".text")
        self.assertEqual(cls_code["rva"], "0x25A0")
        self.assertTrue(cls_code["is_executable"])

        # 4. Heap test
        cls_heap = snap.classify_address(0x20000010000)
        self.assertEqual(cls_heap["status"], "COMMITTED")
        self.assertEqual(cls_heap["category"], "HEAP")
        self.assertTrue(cls_heap["is_writable"])

        # 5. Unmapped wild pointer test
        cls_wild = snap.classify_address(0x30000000000)
        self.assertEqual(cls_wild["status"], "UNMAPPED_FREE")
        self.assertEqual(cls_wild["category"], "UNALLOCATED_SPACE")

    def test_snapshot_diffing(self):
        """Verifies differential memory snapshot delta calculation (new allocations, deallocations, and net growth)."""
        snap_a = ProcessMemoryMapSnapshot(pid=999, process_name="diff_test.exe")
        snap_a.add_region(ProcessMemoryRegion(0x10000, 0x10000, 0x4000, MEM_COMMIT, PAGE_READWRITE, PAGE_READWRITE, MEM_PRIVATE, "HEAP"))
        snap_a.add_region(ProcessMemoryRegion(0x20000, 0x20000, 0x8000, MEM_COMMIT, PAGE_READONLY, PAGE_READONLY, MEM_IMAGE, "IMAGE_TEXT"))

        snap_b = ProcessMemoryMapSnapshot(pid=999, process_name="diff_test.exe")
        # 0x10000 changed protection to RWX (W^X violation)
        snap_b.add_region(ProcessMemoryRegion(0x10000, 0x10000, 0x4000, MEM_COMMIT, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, MEM_PRIVATE, "HEAP"))
        # 0x20000 was deallocated (not in B)
        # 0x30000 is a new dynamic allocation of 64 KB
        snap_b.add_region(ProcessMemoryRegion(0x30000, 0x30000, 0x10000, MEM_COMMIT, PAGE_READWRITE, PAGE_READWRITE, MEM_PRIVATE, "HEAP"))

        delta = VirtualMemoryInspector.diff_snapshots(snap_a, snap_b)
        self.assertEqual(delta["new_allocations_count"], 1)
        self.assertEqual(delta["deallocations_count"], 1)
        self.assertEqual(delta["protection_modifications_count"], 1)
        self.assertEqual(delta["modified_protection"][0]["base_address"], "0x0000000000010000")
        self.assertIn("PAGE_EXECUTE_READWRITE", delta["modified_protection"][0]["new_protect"])
        # Net growth = 0x10000 - 0x8000 = 0x8000 = 32768 bytes
        self.assertEqual(delta["net_commit_delta_bytes"], 32768)

    def test_live_process_memory_inspection(self):
        """Verifies passive live memory inspection on the active Python process under ExecutionGuard."""
        snapshot = VirtualMemoryInspector.inspect_process(self.pid)
        self.assertEqual(snapshot.pid, self.pid)
        self.assertGreater(len(snapshot.regions), 0)

        sum_data = snapshot.compute_summary()
        self.assertGreater(sum_data["commit_bytes"], 0)
        self.assertGreater(sum_data["total_regions"], 0)

        # Classify the address of this test object (must reside in committed memory)
        obj_addr = id(self)
        classification = snapshot.classify_address(obj_addr)
        self.assertIn(classification["status"], ["COMMITTED", "MEM_COMMIT"])

    def test_mcp_vad_inspect_dispatch(self):
        """Verifies that the native MCP server exposes and dispatches rea_vad_inspect tool."""
        from mcp_server import ReaMcpServer
        server = ReaMcpServer()

        # Check tool registration
        tool_names = [t["name"] for t in server.handle_tools_list({})["tools"]]
        self.assertIn("rea_vad_inspect", tool_names)

        # Execute tool call
        result = server.dispatch_tool("rea_vad_inspect", {"pid": self.pid})
        self.assertEqual(result["pid"], self.pid)
        self.assertIn("summary", result)
        self.assertGreater(result["summary"]["commit_bytes"], 0)

        # Execute address classification via MCP
        null_res = server.dispatch_tool("rea_vad_inspect", {"pid": self.pid, "address": "0x0"})
        self.assertEqual(null_res["status"], "FAULT_NULL_DEREFERENCE")

    def test_read_process_memory_safe_chunking(self):
        """Verifies safe, read-only memory reading via kernel32.ReadProcessMemory."""
        import ctypes
        import struct
        test_val = ctypes.c_int32(133742)
        val_addr = ctypes.addressof(test_val)

        raw = VirtualMemoryInspector.read_process_memory(self.pid, val_addr, 4)
        self.assertEqual(len(raw), 4)
        (recovered_int,) = struct.unpack("<i", raw)
        self.assertEqual(recovered_int, 133742)

    def test_process_memory_scanner_first_and_next_scan(self):
        """Verifies First Scan and Next Scan differential value filtering."""
        import ctypes
        test_val = ctypes.c_int32(987654)
        val_addr = ctypes.addressof(test_val)

        # 1. First Scan: find exact value
        res_first = ProcessMemoryScanner.first_scan(
            pid=self.pid,
            data_type="int32",
            scan_type="EXACT_VALUE",
            value=987654,
            writable_only=True
        )
        self.assertIn("session_id", res_first)
        self.assertGreaterEqual(res_first["total_candidates"], 1)

        sid = res_first["session_id"]

        # Modify value in place
        test_val.value = 987700

        # 2. Next Scan: find INCREASED_VALUE
        res_next = ProcessMemoryScanner.next_scan(
            session_id=sid,
            scan_type="INCREASED_VALUE"
        )
        self.assertGreaterEqual(res_next["surviving_count"], 1)
        surv_addrs = [c["address_int"] for c in res_next["candidates_sample"]]
        self.assertIn(val_addr, surv_addrs)

    def test_structure_dissector_inferred_types(self):
        """Verifies runtime structure dissection and C struct generation."""
        import ctypes
        class DummyEntity(ctypes.Structure):
            _fields_ = [
                ("flags", ctypes.c_int32),
                ("health", ctypes.c_float),
                ("score", ctypes.c_uint64),
                ("magic", ctypes.c_uint64)
            ]
        entity = DummyEntity(flags=1, health=100.0, score=5000, magic=0xDEADBEEF)
        entity_addr = ctypes.addressof(entity)

        report = StructureDissector.dissect(pid=self.pid, base_address=entity_addr, size=24)
        self.assertEqual(report["status"], "success")
        self.assertEqual(report["fields_count"], 3)
        self.assertIn("struct Reconstructed_", report["c_struct_definition"])
        self.assertIn("field_0x0", report["c_struct_definition"])

    def test_diff_snapshots_mutations(self):
        """Verifies diff_snapshots tracking of region resizing, type mutations, and protection."""
        snap_a = ProcessMemoryMapSnapshot(self.pid, "test.exe")
        r1 = ProcessMemoryRegion(0x1000, 0x1000, 0x1000, MEM_COMMIT, PAGE_READWRITE, PAGE_READWRITE, MEM_PRIVATE, "HEAP")
        snap_a.add_region(r1)

        snap_b = ProcessMemoryMapSnapshot(self.pid, "test.exe")
        r2 = ProcessMemoryRegion(0x1000, 0x1000, 0x2000, MEM_COMMIT, PAGE_READONLY, PAGE_READWRITE, MEM_PRIVATE, "HEAP")
        snap_b.add_region(r2)

        diff = VirtualMemoryInspector.diff_snapshots(snap_a, snap_b)
        self.assertEqual(diff["mutated_regions_count"], 1)
        self.assertEqual(diff["protection_modifications_count"], 1)
        self.assertEqual(diff["mutated_regions"][0]["mutations"]["new_size"], 0x2000)
        self.assertEqual(diff["mutated_regions"][0]["mutations"]["old_size"], 0x1000)

    def test_pointer_scanner_resolution(self):
        """Verifies multi-level static/dynamic pointer resolution."""
        import ctypes
        target_obj = (ctypes.c_uint64 * 4)(10, 20, 30, 40)
        target_addr = ctypes.addressof(target_obj)

        res = PointerScanner.find_pointer_paths(
            pid=self.pid,
            target_address=target_addr,
            max_depth=2,
            max_offset=0x1000
        )
        self.assertEqual(res["pid"], self.pid)
        self.assertIn("paths", res)
        self.assertIsInstance(res["paths"], list)


if __name__ == "__main__":
    unittest.main()
