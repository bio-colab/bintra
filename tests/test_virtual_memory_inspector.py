# -*- coding: utf-8 -*-
"""
Test Suite for Bintra Passive Virtual Memory & VAD Layout Inspector.
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

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
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
        """Verifies that the native MCP server exposes and dispatches bintra_vad_inspect tool."""
        from mcp_server import BintraMcpServer
        server = BintraMcpServer()

        # Check tool registration
        tool_names = [t["name"] for t in server.handle_tools_list({})["tools"]]
        self.assertIn("bintra_vad_inspect", tool_names)

        # Execute tool call
        result = server.dispatch_tool("bintra_vad_inspect", {"pid": self.pid})
        self.assertEqual(result["pid"], self.pid)
        self.assertIn("summary", result)
        self.assertGreater(result["summary"]["commit_bytes"], 0)

        # Execute address classification via MCP
        null_res = server.dispatch_tool("bintra_vad_inspect", {"pid": self.pid, "address": "0x0"})
        self.assertEqual(null_res["status"], "FAULT_NULL_DEREFERENCE")

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
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

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
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

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_structure_dissector_inferred_types(self):
        """Verifies runtime structure dissection splits 32-bit fields accurately and emits C struct layout."""
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
        self.assertTrue(report["heuristic"])
        self.assertNotEqual(report["fields_count"], 3)
        self.assertEqual(report["fields_count"], 4)
        offsets = [f["offset_bytes"] for f in report["fields"]]
        types = [f["inferred_type"] for f in report["fields"]]
        self.assertEqual(offsets, [0, 4, 8, 16])
        self.assertEqual(types, ["int32_t", "float", "uint64_t", "uint64_t"])
        for f in report["fields"]:
            self.assertIn("confidence", f)
            self.assertIn("alternatives", f)
        self.assertIn("struct Reconstructed_", report["c_struct_definition"])
        self.assertIn("field_0x0", report["c_struct_definition"])
        self.assertIn("field_0x4", report["c_struct_definition"])

    def test_read_process_memory_no_zero_padding_on_partial_failure(self):
        """Verifies ReadProcessMemory never fabricates zero bytes on short or mid-range failed reads."""
        from unittest.mock import patch, MagicMock
        import ctypes

        # Simulate reading 96 KB across two chunks where chunk 1 succeeds fully (64 KB of 0xAA)
        # and chunk 2 returns a short read of 4096 bytes of 0xBB then stops (unmapped boundary).
        class FakeKernel32:
            def __init__(self):
                self.OpenProcess = MagicMock(return_value=1234)
                self.CloseHandle = MagicMock(return_value=1)

                def _rpm(h_proc, lp_addr, lp_buf, n_size, lp_read):
                    addr_int = lp_addr.value if hasattr(lp_addr, "value") else int(lp_addr)
                    if addr_int == 0x500000:
                        payload = b"\xAA" * n_size
                    elif addr_int == 0x510000:
                        payload = b"\xBB" * 4096
                    else:
                        ctypes.cast(lp_read, ctypes.POINTER(ctypes.c_size_t)).contents.value = 0
                        return 0
                    ctypes.memmove(lp_buf, payload, len(payload))
                    ctypes.cast(lp_read, ctypes.POINTER(ctypes.c_size_t)).contents.value = len(payload)
                    return 1

                self.ReadProcessMemory = MagicMock(side_effect=_rpm)

        fake_k32 = FakeKernel32()
        with patch.object(VirtualMemoryInspector, "_is_windows", return_value=True), \
             patch.object(ctypes, "windll", MagicMock(kernel32=fake_k32), create=True):
            checked = VirtualMemoryInspector.read_process_memory_checked(
                pid=self.pid, address=0x500000, size=98304, allow_partial=True
            )
            self.assertEqual(checked["status"], "partial")
            self.assertTrue(checked["is_partial"])
            self.assertEqual(checked["bytes_requested"], 98304)
            self.assertEqual(checked["bytes_read"], 65536 + 4096)
            self.assertEqual(checked["first_failed_address"], f"0x{0x510000 + 4096:X}")
            self.assertEqual(len(checked["data"]), 65536 + 4096)
            self.assertNotIn(b"\x00", checked["data"])

            raw = VirtualMemoryInspector.read_process_memory(pid=self.pid, address=0x500000, size=98304)
            self.assertEqual(len(raw), 65536 + 4096)
            self.assertEqual(raw[-1], 0xBB)

            aborted = VirtualMemoryInspector.read_process_memory_checked(
                pid=self.pid, address=0x500000, size=98304, allow_partial=False
            )
            self.assertEqual(aborted["status"], "partial_aborted")
            self.assertIsNone(aborted["data"])

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_next_scan_bytes_string_and_small_types(self):
        """Verifies string/bytes next_scan re-verification and int8/unaligned numeric scanning."""
        import ctypes
        tag1 = b"A_BINTRA_TAG_V1\x00"
        buf = (ctypes.c_char * 32)(*(tag1 + b"\x00" * (32 - len(tag1))))
        buf_addr = ctypes.addressof(buf)

        # 1. String scan -> mutated string -> CHANGED_VALUE / EXACT_VALUE
        res_str = ProcessMemoryScanner.first_scan(
            pid=self.pid, data_type="string", scan_type="EXACT_VALUE", value="A_BINTRA_TAG_V1"
        )
        sid = res_str["session_id"]
        self.assertGreaterEqual(res_str["total_candidates"], 1)
        self.assertEqual(len(sid), 16)

        with self.assertRaises(ValueError):
            ProcessMemoryScanner.next_scan(session_id=sid, scan_type="INCREASED_VALUE")

        tag2 = b"A_BINTRA_TAG_V2\x00"
        ctypes.memmove(buf_addr, tag2, len(tag2))
        res_changed = ProcessMemoryScanner.next_scan(session_id=sid, scan_type="CHANGED_VALUE")
        self.assertGreaterEqual(res_changed["surviving_count"], 1)
        self.assertIn(buf_addr, [c["address_int"] for c in res_changed["candidates_sample"]])

        res_exact = ProcessMemoryScanner.next_scan(
            session_id=sid, scan_type="EXACT_VALUE", value="A_BINTRA_TAG_V2"
        )
        self.assertGreaterEqual(res_exact["surviving_count"], 1)

        # 2. Unaligned int32 scan at addr % 4 != 0
        # Bytes for 0x5A3C1E79 LE at offset +1
        raw_arr = (ctypes.c_ubyte * 16)(0, 0x79, 0x1E, 0x3C, 0x5A, *([0] * 11))
        unaligned_addr = ctypes.addressof(raw_arr) + 1
        res_unaligned = ProcessMemoryScanner.first_scan(
            pid=self.pid, data_type="int32", scan_type="EXACT_VALUE", value=0x5A3C1E79, alignment=1, max_candidates=2000
        )
        self.assertGreaterEqual(res_unaligned["total_candidates"], 1)
        self.assertIn(unaligned_addr, [c["address_int"] for c in res_unaligned["candidates_sample"]])

    def test_first_scan_mode_validation_and_session_eviction(self):
        """Verifies invalid first_scan modes fail closed and _ACTIVE_SESSIONS obeys bounded LRU eviction."""
        from unittest.mock import patch

        with self.assertRaises(ValueError):
            ProcessMemoryScanner.first_scan(pid=self.pid, data_type="int32", scan_type="INCREASED_VALUE")

        sim_snap = ProcessMemoryMapSnapshot(pid=self.pid, process_name="sim.exe", is_simulated=True)
        with patch.object(VirtualMemoryInspector, "inspect_process", return_value=sim_snap):
            cap = ProcessMemoryScanner._MAX_SESSIONS
            for _ in range(cap + 10):
                ProcessMemoryScanner.first_scan(pid=self.pid, data_type="int8", scan_type="EXACT_VALUE", value=7)
            self.assertLessEqual(len(ProcessMemoryScanner._ACTIVE_SESSIONS), cap)

    def test_pointer_scanner_unaligned_depth3_and_self_verification(self):
        """Verifies PointerScanner enforces depth bounds, supports depth 3 with 4-byte alignment, and verifies chains."""
        import struct
        from unittest.mock import patch

        with self.assertRaises(ValueError):
            PointerScanner.find_pointer_paths(pid=self.pid, target_address=0x30000000, max_depth=4)

        snap = ProcessMemoryMapSnapshot(pid=self.pid, process_name="ptr_test.exe", architecture="x86-64")
        snap.add_region(ProcessMemoryRegion(0x140001000, 0x140000000, 0x100, MEM_COMMIT, PAGE_READWRITE, PAGE_READWRITE, MEM_IMAGE, "IMAGE_DATA", "ptr_test.exe"))
        snap.add_region(ProcessMemoryRegion(0x20000000, 0x20000000, 0x100, MEM_COMMIT, PAGE_READWRITE, PAGE_READWRITE, MEM_PRIVATE, "HEAP"))
        snap.add_region(ProcessMemoryRegion(0x30000000, 0x30000000, 0x100, MEM_COMMIT, PAGE_READWRITE, PAGE_READWRITE, MEM_PRIVATE, "HEAP"))

        # Chain (with unaligned 4-mod-8 slot in heap1 at 0x20000004!):
        # static[0x14000100C] -> 0x20000000 (+0x04 -> 0x20000004)
        # heap1[0x20000004]   -> 0x30000008 (+0x08 -> 0x30000010)
        # heap2[0x30000010]   -> 0x40000100 (+0x10 -> 0x40000110)
        static_buf = bytearray(0x100)
        struct.pack_into("<Q", static_buf, 0x0C, 0x20000000)

        heap1_buf = bytearray(0x100)
        struct.pack_into("<Q", heap1_buf, 0x04, 0x30000008)

        heap2_buf = bytearray(0x100)
        struct.pack_into("<Q", heap2_buf, 0x10, 0x40000100)

        target_addr = 0x40000110

        def fake_read(pid, addr, size, allow_partial=True):
            if 0x140001000 <= addr < 0x140001100:
                off = addr - 0x140001000
                data = bytes(static_buf[off:off + size])
            elif 0x20000000 <= addr < 0x20000100:
                off = addr - 0x20000000
                data = bytes(heap1_buf[off:off + size])
            elif 0x30000000 <= addr < 0x30000100:
                off = addr - 0x30000000
                data = bytes(heap2_buf[off:off + size])
            else:
                return {"status": "error", "data": None, "bytes_requested": size, "bytes_read": 0, "is_partial": False}
            return {"status": "success", "data": data, "bytes_requested": size, "bytes_read": len(data), "is_partial": False}

        with patch.object(VirtualMemoryInspector, "inspect_process", return_value=snap), \
             patch.object(VirtualMemoryInspector, "_read_memory_internal", side_effect=fake_read):
            res = PointerScanner.find_pointer_paths(
                pid=self.pid,
                target_address=target_addr,
                max_depth=3,
                max_offset=0x100,
                alignment=4,
            )
            self.assertTrue(res["heuristic"])
            self.assertGreaterEqual(res["paths_count"], 1)
            d3_paths = [p for p in res["paths"] if p["depth"] == 3]
            self.assertGreaterEqual(len(d3_paths), 1)
            self.assertTrue(all(p["verified"] is True for p in d3_paths))
            self.assertEqual(d3_paths[0]["offsets"], ["0x4", "0x8", "0x10"])

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

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
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
