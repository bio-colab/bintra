# -*- coding: utf-8 -*-
"""
Passive Virtual Memory & VAD Layout Inspector (Read-Only).
Provides high-fidelity, non-intrusive memory mapping and classification
(Executable Modules, Private Heaps, Thread Stacks, Mapped Files, and Null-Page Traps)
using standard Win32 VirtualQueryEx and Toolhelp32 module introspection.
Strictly read-only; governed by ExecutionGuard and Capability.PROCESS_QUERY.
"""

import os
import re
import sys
import time
import uuid
import struct
import ctypes
from ctypes import wintypes
from typing import Dict, Any, List, Optional, Tuple

from security.execution_guard import ExecutionGuard
from security.capability_registry import Capability


# Win32 Memory Allocation States
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_FREE = 0x00010000

# Win32 Memory Types
MEM_PRIVATE = 0x00020000
MEM_MAPPED = 0x00040000
MEM_IMAGE = 0x01000000

# Win32 Page Protection Flags
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400

# Process Access Flags (Read-Only)
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# Maximum user-mode virtual address on 64-bit Windows
X64_USER_MAX_ADDRESS = 0x00007FFFFFFFFFFF
X86_USER_MAX_ADDRESS = 0x7FFFFFFF
NULL_TRAP_UPPER_BOUND = 0x000000000000FFFF


class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64),
        ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wintypes.DWORD),
        ("Alignment1", wintypes.DWORD),
        ("RegionSize", ctypes.c_uint64),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("Alignment2", wintypes.DWORD),
    ]


class MEMORY_BASIC_INFORMATION32(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.DWORD),
        ("AllocationBase", wintypes.DWORD),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", wintypes.DWORD),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class ProcessMemoryRegion:
    """Represents a discrete contiguous page allocation block in a process's virtual memory."""

    def __init__(
        self,
        base_address: int,
        allocation_base: int,
        region_size: int,
        state: int,
        protect: int,
        alloc_protect: int,
        mem_type: int,
        category: str = "UNKNOWN",
        module_name: Optional[str] = None,
        module_path: Optional[str] = None,
        section_name: Optional[str] = None,
        rva: Optional[int] = None,
    ):
        self.base_address = base_address
        self.allocation_base = allocation_base
        self.region_size = region_size
        self.state = state
        self.protect = protect
        self.alloc_protect = alloc_protect
        self.mem_type = mem_type
        self.category = category
        self.module_name = module_name
        self.module_path = module_path
        self.section_name = section_name
        self.rva = rva

    @property
    def end_address(self) -> int:
        return self.base_address + self.region_size

    def contains(self, addr: int) -> bool:
        return self.base_address <= addr < self.end_address

    def is_executable(self) -> bool:
        return bool(self.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))

    def is_readable(self) -> bool:
        if self.protect & (PAGE_NOACCESS | PAGE_GUARD):
            return False
        return bool(self.protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))

    def is_writable(self) -> bool:
        return bool(self.protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))

    def is_wx(self) -> bool:
        """Returns True if the page violates W^X security (both writable and executable)."""
        return self.is_executable() and self.is_writable()

    def is_guard_page(self) -> bool:
        return bool(self.protect & PAGE_GUARD)

    def state_str(self) -> str:
        if self.state == MEM_COMMIT:
            return "MEM_COMMIT"
        if self.state == MEM_RESERVE:
            return "MEM_RESERVE"
        if self.state == MEM_FREE:
            return "MEM_FREE"
        return f"STATE_0x{self.state:X}"

    def type_str(self) -> str:
        if self.mem_type == MEM_IMAGE:
            return "MEM_IMAGE"
        if self.mem_type == MEM_PRIVATE:
            return "MEM_PRIVATE"
        if self.mem_type == MEM_MAPPED:
            return "MEM_MAPPED"
        return f"TYPE_0x{self.mem_type:X}"

    def protect_str(self) -> str:
        parts = []
        base = self.protect & 0xFF
        base_map = {
            PAGE_NOACCESS: "PAGE_NOACCESS",
            PAGE_READONLY: "PAGE_READONLY",
            PAGE_READWRITE: "PAGE_READWRITE",
            PAGE_WRITECOPY: "PAGE_WRITECOPY",
            PAGE_EXECUTE: "PAGE_EXECUTE",
            PAGE_EXECUTE_READ: "PAGE_EXECUTE_READ",
            PAGE_EXECUTE_READWRITE: "PAGE_EXECUTE_READWRITE",
            PAGE_EXECUTE_WRITECOPY: "PAGE_EXECUTE_WRITECOPY",
        }
        if base in base_map:
            parts.append(base_map[base])
        elif base != 0:
            parts.append(f"PROTECT_0x{base:X}")

        if self.protect & PAGE_GUARD:
            parts.append("PAGE_GUARD")
        if self.protect & PAGE_NOCACHE:
            parts.append("PAGE_NOCACHE")
        if self.protect & PAGE_WRITECOMBINE:
            parts.append("PAGE_WRITECOMBINE")

        return " | ".join(parts) if parts else "PAGE_NOACCESS"

    def to_dict(self) -> Dict[str, Any]:
        res = {
            "base_address": f"0x{self.base_address:016X}",
            "end_address": f"0x{self.end_address:016X}",
            "allocation_base": f"0x{self.allocation_base:016X}",
            "region_size_bytes": self.region_size,
            "state": self.state_str(),
            "protect": self.protect_str(),
            "type": self.type_str(),
            "category": self.category,
            "is_executable": self.is_executable(),
            "is_writable": self.is_writable(),
            "is_wx": self.is_wx(),
        }
        if self.module_name:
            res["module_name"] = self.module_name
            res["module_path"] = self.module_path
        if self.section_name:
            res["section_name"] = self.section_name
        if self.rva is not None:
            res["rva"] = f"0x{self.rva:X}"
        return res


class ProcessMemoryMapSnapshot:
    """Complete in-memory spatial representation of a process's virtual memory layout."""

    def __init__(self, pid: int, process_name: str, architecture: str = "x86-64"):
        self.pid = pid
        self.process_name = process_name
        self.architecture = architecture
        self.timestamp = time.time()
        self.regions: List[ProcessMemoryRegion] = []
        self.modules: List[Dict[str, Any]] = []

    def add_region(self, region: ProcessMemoryRegion) -> None:
        self.regions.append(region)

    def compute_summary(self) -> Dict[str, Any]:
        commit_bytes = 0
        reserve_bytes = 0
        free_bytes = 0
        image_bytes = 0
        heap_bytes = 0
        stack_bytes = 0
        mapped_bytes = 0
        exec_bytes = 0
        wx_count = 0
        guard_count = 0

        for r in self.regions:
            sz = r.region_size
            if r.state == MEM_COMMIT:
                commit_bytes += sz
                if r.is_executable():
                    exec_bytes += sz
                if r.is_wx():
                    wx_count += 1
                if r.is_guard_page():
                    guard_count += 1

                if r.mem_type == MEM_IMAGE:
                    image_bytes += sz
                elif r.mem_type == MEM_MAPPED:
                    mapped_bytes += sz
                elif r.mem_type == MEM_PRIVATE:
                    if r.category == "STACK":
                        stack_bytes += sz
                    else:
                        heap_bytes += sz
            elif r.state == MEM_RESERVE:
                reserve_bytes += sz
            elif r.state == MEM_FREE:
                free_bytes += sz

        return {
            "total_regions": len(self.regions),
            "commit_bytes": commit_bytes,
            "commit_mb": round(commit_bytes / (1024 * 1024), 2),
            "reserve_bytes": reserve_bytes,
            "reserve_mb": round(reserve_bytes / (1024 * 1024), 2),
            "free_bytes": free_bytes,
            "image_bytes": image_bytes,
            "image_mb": round(image_bytes / (1024 * 1024), 2),
            "heap_bytes": heap_bytes,
            "heap_mb": round(heap_bytes / (1024 * 1024), 2),
            "stack_bytes": stack_bytes,
            "stack_kb": round(stack_bytes / 1024, 2),
            "mapped_bytes": mapped_bytes,
            "executable_bytes": exec_bytes,
            "wx_regions_count": wx_count,
            "guard_pages_count": guard_count,
        }

    def classify_address(self, address: int) -> Dict[str, Any]:
        """
        Classifies an arbitrary 64-bit or 32-bit virtual address into its exact structural
        category, containing module, RVA, and permissions.
        """
        # 1. Null page trap detection
        if address <= NULL_TRAP_UPPER_BOUND:
            return {
                "address": f"0x{address:016X}",
                "status": "FAULT_NULL_DEREFERENCE",
                "category": "NULL_PAGE_TRAP",
                "offset_from_null": address,
                "is_accessible": False,
                "description": f"Address falls in zero-page trap buffer (0x0 - 0x10000); classic NULL pointer dereference or offset [0x{address:X}]."
            }

        # 2. Kernel space boundary check
        limit = X64_USER_MAX_ADDRESS if self.architecture == "x86-64" else X86_USER_MAX_ADDRESS
        if address > limit:
            return {
                "address": f"0x{address:016X}",
                "status": "FAULT_KERNEL_BOUNDARY",
                "category": "KERNEL_SPACE",
                "is_accessible": False,
                "description": "Address resides in Windows Kernel virtual memory space; user-mode access strictly prohibited by hardware ring protection."
            }

        # 3. Locate containing memory region
        for r in self.regions:
            if r.contains(address):
                rva_str = f"0x{address - r.allocation_base:X}" if r.allocation_base else "N/A"
                return {
                    "address": f"0x{address:016X}",
                    "status": "COMMITTED" if r.state == MEM_COMMIT else r.state_str(),
                    "category": r.category,
                    "region_base": f"0x{r.base_address:016X}",
                    "region_size_bytes": r.region_size,
                    "state": r.state_str(),
                    "protect": r.protect_str(),
                    "type": r.type_str(),
                    "module_name": r.module_name,
                    "module_path": r.module_path,
                    "section_name": r.section_name,
                    "rva": rva_str,
                    "is_executable": r.is_executable(),
                    "is_writable": r.is_writable(),
                    "is_wx": r.is_wx(),
                    "is_guard_page": r.is_guard_page(),
                }

        return {
            "address": f"0x{address:016X}",
            "status": "UNMAPPED_FREE",
            "category": "UNALLOCATED_SPACE",
            "is_accessible": False,
            "description": "Address does not belong to any committed or reserved virtual memory region (wild pointer or use-after-free access)."
        }

    def to_dict(self, include_regions: bool = False) -> Dict[str, Any]:
        res = {
            "pid": self.pid,
            "process_name": self.process_name,
            "architecture": self.architecture,
            "timestamp": self.timestamp,
            "summary": self.compute_summary(),
            "module_count": len(self.modules),
        }
        if include_regions:
            res["regions"] = [r.to_dict() for r in self.regions]
        return res


class VirtualMemoryInspector:
    """
    Authoritative, read-only Virtual Address Descriptor (VAD) inspector for Windows processes.
    Gathers memory layouts, classifies pointers, audits executable pages, and diffs state deltas.
    """

    @classmethod
    def _is_windows(cls) -> bool:
        return os.name == "nt"

    @classmethod
    def inspect_process(cls, pid: int, include_free: bool = False) -> ProcessMemoryMapSnapshot:
        """
        Safely enumerates the virtual address space of the target process using VirtualQueryEx.
        Mediated by ExecutionGuard with Capability.PROCESS_QUERY.
        """
        ExecutionGuard.request_access(
            component="virtual_memory_inspector",
            operation="inspect_process",
            target=f"PID:{pid}",
            capability=Capability.PROCESS_QUERY,
            access_mode="QUERY"
        )

        if not cls._is_windows():
            # Graceful cross-platform synthetic fallback for CI/Linux
            snapshot = ProcessMemoryMapSnapshot(pid=pid, process_name=f"simulated_{pid}.exe", architecture="x86-64")
            # Synthesize standard PE image + heap + stack regions for clean testing
            snapshot.add_region(ProcessMemoryRegion(0x140000000, 0x140000000, 0x1000, MEM_COMMIT, PAGE_READONLY, PAGE_READONLY, MEM_IMAGE, "IMAGE_HEADER", "target.exe"))
            snapshot.add_region(ProcessMemoryRegion(0x140001000, 0x140000000, 0x5000, MEM_COMMIT, PAGE_EXECUTE_READ, PAGE_EXECUTE_READ, MEM_IMAGE, "IMAGE_TEXT", "target.exe", section_name=".text"))
            snapshot.add_region(ProcessMemoryRegion(0x140006000, 0x140000000, 0x2000, MEM_COMMIT, PAGE_READWRITE, PAGE_READWRITE, MEM_IMAGE, "IMAGE_DATA", "target.exe", section_name=".data"))
            snapshot.add_region(ProcessMemoryRegion(0x0000020000000000, 0x0000020000000000, 0x100000, MEM_COMMIT, PAGE_READWRITE, PAGE_READWRITE, MEM_PRIVATE, "HEAP"))
            snapshot.add_region(ProcessMemoryRegion(0x0000005000000000, 0x0000005000000000, 0x40000, MEM_COMMIT, PAGE_READWRITE, PAGE_READWRITE, MEM_PRIVATE, "STACK"))
            return snapshot

        # Query process modules to map AllocationBase to DLL/EXE identities
        modules = cls._enumerate_modules(pid)
        proc_name = modules[0]["name"] if modules else f"pid_{pid}.exe"

        # Open process for query and read information (Read-Only)
        k32 = ctypes.windll.kernel32
        h_proc = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h_proc:
            h_proc = k32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
        if not h_proc:
            # Fall back to limited query rights (Windows 10/11)
            h_proc = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)

        if not h_proc:
            err = ctypes.GetLastError()
            raise PermissionError(f"Failed to open process PID {pid} for memory query (Win32 Error: {err})")

        detected_arch = "x86-64"
        max_addr = X64_USER_MAX_ADDRESS
        is_wow64 = wintypes.BOOL(False)
        if hasattr(k32, "IsWow64Process") and k32.IsWow64Process(h_proc, ctypes.byref(is_wow64)):
            if is_wow64.value:
                detected_arch = "x86-32"
                max_addr = X86_USER_MAX_ADDRESS

        snapshot = ProcessMemoryMapSnapshot(pid=pid, process_name=proc_name, architecture=detected_arch)
        snapshot.modules = modules

        try:
            mbi = MEMORY_BASIC_INFORMATION64()
            mbi_size = ctypes.sizeof(mbi)
            current_addr = 0

            while current_addr < max_addr:
                res = k32.VirtualQueryEx(h_proc, ctypes.c_void_p(current_addr), ctypes.byref(mbi), mbi_size)
                if res == 0:
                    break

                base_addr = mbi.BaseAddress
                region_sz = mbi.RegionSize
                state = mbi.State
                protect = mbi.Protect
                alloc_base = mbi.AllocationBase
                alloc_protect = mbi.AllocationProtect
                mem_type = mbi.Type

                # Skip MEM_FREE regions unless requested
                if state != MEM_FREE or include_free:
                    # Classify category
                    cat, mod_name, mod_path, sec_name = cls._classify_region_details(
                        base_addr, alloc_base, protect, mem_type, modules
                    )

                    rva = (base_addr - alloc_base) if (alloc_base and mod_name) else None

                    region = ProcessMemoryRegion(
                        base_address=base_addr,
                        allocation_base=alloc_base,
                        region_size=region_sz,
                        state=state,
                        protect=protect,
                        alloc_protect=alloc_protect,
                        mem_type=mem_type,
                        category=cat,
                        module_name=mod_name,
                        module_path=mod_path,
                        section_name=sec_name,
                        rva=rva
                    )
                    snapshot.add_region(region)

                next_addr = base_addr + region_sz
                if next_addr <= current_addr:
                    # Guard against 64-bit integer wraparound
                    break
                current_addr = next_addr

        finally:
            k32.CloseHandle(h_proc)

        return snapshot

    _MODULE_SECTIONS_CACHE: Dict[str, List[Dict[str, Any]]] = {}

    @classmethod
    def _get_module_sections(cls, mod_path: Optional[str]) -> List[Dict[str, Any]]:
        """Parses PE section table headers from disk or cache to obtain exact section boundaries."""
        if not mod_path or not os.path.isfile(mod_path):
            return []
        if mod_path in cls._MODULE_SECTIONS_CACHE:
            return cls._MODULE_SECTIONS_CACHE[mod_path]

        sections = []
        try:
            with open(mod_path, "rb") as f:
                dos = f.read(64)
                if len(dos) >= 64 and dos[:2] == b"MZ":
                    (e_lfanew,) = struct.unpack("<I", dos[60:64])
                    f.seek(e_lfanew)
                    pe_sig = f.read(4)
                    if pe_sig == b"PE\x00\x00":
                        file_hdr = f.read(20)
                        num_sections, opt_hdr_sz = struct.unpack("<HH", file_hdr[2:6])
                        f.seek(e_lfanew + 24 + opt_hdr_sz)
                        for _ in range(min(num_sections, 96)):
                            sec_hdr = f.read(40)
                            if len(sec_hdr) < 40:
                                break
                            name = sec_hdr[:8].rstrip(b"\x00").decode("latin1", errors="replace")
                            v_size, v_addr = struct.unpack("<II", sec_hdr[8:16])
                            sections.append({
                                "name": name,
                                "va": v_addr,
                                "size": v_size
                            })
        except Exception:
            pass

        cls._MODULE_SECTIONS_CACHE[mod_path] = sections
        return sections

    @classmethod
    def _classify_region_details(
        cls,
        base_addr: int,
        alloc_base: int,
        protect: int,
        mem_type: int,
        modules: List[Dict[str, Any]]
    ) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
        """Determines if a region belongs to a module (.text, .data), heap, stack, or mapped view."""
        if mem_type == MEM_IMAGE:
            for mod in modules:
                m_base = mod["base_address"]
                m_size = mod["size"]
                if m_base <= base_addr < m_base + m_size:
                    mod_name = mod["name"]
                    mod_path = mod["path"]
                    rva = base_addr - m_base

                    if base_addr == m_base:
                        return "IMAGE_HEADER", mod_name, mod_path, "HEADERS"

                    # 1. First priority: Exact PE section header matching
                    exact_sec = None
                    for sec in cls._get_module_sections(mod_path):
                        if sec["va"] <= rva < sec["va"] + max(sec["size"], 0x1000):
                            exact_sec = sec["name"]
                            break

                    if exact_sec:
                        sec_lower = exact_sec.lower()
                        if "text" in sec_lower:
                            return "IMAGE_TEXT", mod_name, mod_path, exact_sec
                        elif "rdata" in sec_lower:
                            return "IMAGE_RDATA", mod_name, mod_path, exact_sec
                        elif "data" in sec_lower:
                            return "IMAGE_DATA", mod_name, mod_path, exact_sec
                        elif "pdata" in sec_lower:
                            return "IMAGE_PDATA", mod_name, mod_path, exact_sec
                        elif "reloc" in sec_lower:
                            return "IMAGE_RELOC", mod_name, mod_path, exact_sec
                        elif "rsrc" in sec_lower:
                            return "IMAGE_RESOURCE", mod_name, mod_path, exact_sec
                        return f"IMAGE_{exact_sec.upper().lstrip('.')}", mod_name, mod_path, exact_sec

                    # 2. Fallback heuristic based on page protection
                    if protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE):
                        return "IMAGE_TEXT", mod_name, mod_path, ".text"
                    if protect & PAGE_READONLY:
                        return "IMAGE_RDATA", mod_name, mod_path, ".rdata"
                    if protect & PAGE_READWRITE:
                        return "IMAGE_DATA", mod_name, mod_path, ".data"
                    return "IMAGE_SECTION", mod_name, mod_path, None
            return "IMAGE_UNKNOWN", None, None, None

        if mem_type == MEM_MAPPED:
            return "MAPPED_FILE", None, None, None

        if mem_type == MEM_PRIVATE:
            if protect & PAGE_GUARD:
                return "STACK_GUARD", None, None, None
            if protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE):
                return "JIT_OR_DYNAMIC_CODE", None, None, None
            return "HEAP", None, None, None

        return "UNKNOWN", None, None, None

    @classmethod
    def _enumerate_modules(cls, pid: int) -> List[Dict[str, Any]]:
        """Collects loaded module address bounds via Toolhelp32 snapshot."""
        if not cls._is_windows():
            return []

        from windows_intelligence.process_intelligence.module_inventory import ModuleInventory, MODULEENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32
        k32 = ModuleInventory._get_kernel32()
        if not k32:
            return []

        h_snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        if h_snap == wintypes.HANDLE(-1).value:
            return []

        modules = []
        try:
            me = MODULEENTRY32W()
            me.dwSize = ctypes.sizeof(MODULEENTRY32W)
            if k32.Module32FirstW(h_snap, ctypes.byref(me)):
                while True:
                    m_base = ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value or 0
                    modules.append({
                        "name": str(me.szModule),
                        "path": str(me.szExePath),
                        "base_address": m_base,
                        "size": int(me.modBaseSize)
                    })
                    if not k32.Module32NextW(h_snap, ctypes.byref(me)):
                        break
        finally:
            k32.CloseHandle(h_snap)

        return modules

    @classmethod
    def diff_snapshots(
        cls,
        snap_a: ProcessMemoryMapSnapshot,
        snap_b: ProcessMemoryMapSnapshot
    ) -> Dict[str, Any]:
        """
        Computes spatial memory difference between two snapshots (allocations, deallocations,
        protection changes, region resizing, type mutations, and net commit growth).
        """
        regions_a = {r.base_address: r for r in snap_a.regions if r.state == MEM_COMMIT}
        regions_b = {r.base_address: r for r in snap_b.regions if r.state == MEM_COMMIT}

        new_allocations = []
        deallocated = []
        modified_protection = []
        mutated_regions = []

        # Find new allocations and mutations in B
        for base, r_b in regions_b.items():
            if base not in regions_a:
                new_allocations.append(r_b.to_dict())
            else:
                r_a = regions_a[base]
                changes = {}
                if r_a.protect != r_b.protect:
                    changes["old_protect"] = r_a.protect_str()
                    changes["new_protect"] = r_b.protect_str()
                    modified_protection.append({
                        "base_address": f"0x{base:016X}",
                        "old_protect": r_a.protect_str(),
                        "new_protect": r_b.protect_str(),
                        "region_size_bytes": r_b.region_size,
                        "category": r_b.category,
                    })
                if r_a.region_size != r_b.region_size:
                    changes["old_size"] = r_a.region_size
                    changes["new_size"] = r_b.region_size
                if r_a.mem_type != r_b.mem_type:
                    changes["old_type"] = r_a.type_str()
                    changes["new_type"] = r_b.type_str()

                if changes:
                    mutated_regions.append({
                        "base_address": f"0x{base:016X}",
                        "category": r_b.category,
                        "mutations": changes
                    })

        # Find deallocated regions
        for base, r_a in regions_a.items():
            if base not in regions_b:
                deallocated.append(r_a.to_dict())

        sum_a = snap_a.compute_summary()
        sum_b = snap_b.compute_summary()

        net_commit_delta = sum_b["commit_bytes"] - sum_a["commit_bytes"]

        return {
            "pid": snap_b.pid,
            "elapsed_seconds": round(snap_b.timestamp - snap_a.timestamp, 3),
            "net_commit_delta_bytes": net_commit_delta,
            "net_commit_delta_mb": round(net_commit_delta / (1024 * 1024), 2),
            "new_allocations_count": len(new_allocations),
            "deallocations_count": len(deallocated),
            "protection_modifications_count": len(modified_protection),
            "mutated_regions_count": len(mutated_regions),
            "new_allocations": new_allocations[:100],  # Bounded sample
            "deallocations": deallocated[:100],
            "modified_protection": modified_protection,
            "mutated_regions": mutated_regions[:100],
        }

    @classmethod
    def read_process_memory(
        cls,
        pid: int,
        address: int,
        size: int
    ) -> bytes:
        """
        Safely reads virtual memory bytes from a target process.
        Uses kernel32.ReadProcessMemory in bounded chunked blocks.
        Strictly read-only (PROCESS_VM_READ); governed by Capability.PROCESS_QUERY.
        """
        ExecutionGuard.request_access(
            component="virtual_memory_inspector",
            operation="read_process_memory",
            target=f"pid_{pid}_0x{address:X}",
            capability=Capability.PROCESS_QUERY,
            access_mode="READ"
        )
        if not cls._is_windows() or size <= 0:
            return b""

        k32 = ctypes.windll.kernel32
        h_proc = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h_proc:
            h_proc = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h_proc:
            return b""

        try:
            CHUNK_SIZE = 64 * 1024
            bytes_left = size
            cur_addr = address
            out_buf = bytearray()

            k32.ReadProcessMemory.argtypes = [
                wintypes.HANDLE,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_size_t)
            ]
            k32.ReadProcessMemory.restype = wintypes.BOOL

            while bytes_left > 0:
                to_read = min(bytes_left, CHUNK_SIZE)
                c_buf = ctypes.create_string_buffer(to_read)
                bytes_read = ctypes.c_size_t(0)
                ok = k32.ReadProcessMemory(
                    h_proc,
                    ctypes.c_void_p(cur_addr),
                    c_buf,
                    to_read,
                    ctypes.byref(bytes_read)
                )
                if not ok or bytes_read.value == 0:
                    out_buf.extend(b"\x00" * to_read)
                else:
                    out_buf.extend(c_buf.raw[:bytes_read.value])
                    if bytes_read.value < to_read:
                        out_buf.extend(b"\x00" * (to_read - bytes_read.value))
                cur_addr += to_read
                bytes_left -= to_read

            return bytes(out_buf)
        finally:
            k32.CloseHandle(h_proc)


class ProcessMemoryScanner:
    """
    Stateful read-only memory value search engine providing First Scan and Next Scan.
    Supports multiple data types (int32, int64, float, double, bytes, string).
    Supports exact value, value between, increased, decreased, changed, and unchanged scans.
    Strictly read-only (PROCESS_VM_READ); never modifies process memory.
    """
    _ACTIVE_SESSIONS: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def first_scan(
        cls,
        pid: int,
        data_type: str = "int32",
        scan_type: str = "EXACT_VALUE",
        value: Any = None,
        min_val: Any = None,
        max_val: Any = None,
        writable_only: bool = True,
        max_candidates: int = 50000
    ) -> Dict[str, Any]:
        """Initiates an initial memory scan across committed readable regions."""
        ExecutionGuard.request_access(
            component="virtual_memory_inspector",
            operation="first_scan",
            target=f"pid_{pid}_{data_type}_{scan_type}",
            capability=Capability.PROCESS_QUERY,
            access_mode="READ"
        )
        snap = VirtualMemoryInspector.inspect_process(pid)
        candidates: List[Dict[str, Any]] = []

        type_map = {
            "int32": ("<i", 4, 4),
            "uint32": ("<I", 4, 4),
            "int64": ("<q", 8, 8),
            "uint64": ("<Q", 8, 8),
            "float": ("<f", 4, 4),
            "double": ("<d", 8, 8),
            "bytes": (None, 1, 1),
            "string": (None, 1, 1),
        }
        type_info = type_map.get(data_type.lower())
        if not type_info:
            raise ValueError(f"Unsupported scan data type: {data_type}")
        fmt, step, align = type_info

        target_regions = [
            r for r in snap.regions
            if r.state == MEM_COMMIT and (not writable_only or r.is_writable()) and not r.is_guard_page()
        ]

        target_bytes = None
        if data_type.lower() == "bytes":
            target_bytes = bytes.fromhex(str(value).replace(" ", ""))
        elif data_type.lower() == "string":
            target_bytes = str(value).encode("utf-8")

        for reg in target_regions:
            if len(candidates) >= max_candidates:
                break
            raw = VirtualMemoryInspector.read_process_memory(pid, reg.base_address, reg.region_size)
            if not raw or len(raw) < step:
                continue

            if target_bytes is not None:
                idx = 0
                while idx != -1:
                    idx = raw.find(target_bytes, idx)
                    if idx != -1:
                        addr = reg.base_address + idx
                        candidates.append({
                            "address": f"0x{addr:016X}",
                            "address_int": addr,
                            "value": value,
                            "category": reg.category
                        })
                        if len(candidates) >= max_candidates:
                            break
                        idx += 1
            else:
                num_items = (len(raw) - step) // align + 1
                for i in range(num_items):
                    offset = i * align
                    (val,) = struct.unpack_from(fmt, raw, offset)
                    match = False
                    if scan_type == "EXACT_VALUE" and value is not None:
                        if data_type.lower() in ("float", "double"):
                            match = abs(val - float(value)) < 1e-4
                        else:
                            match = (val == int(value))
                    elif scan_type == "VALUE_BETWEEN" and min_val is not None and max_val is not None:
                        match = (float(min_val) <= val <= float(max_val))
                    elif scan_type == "UNKNOWN_INITIAL_VALUE":
                        match = True

                    if match:
                        addr = reg.base_address + offset
                        candidates.append({
                            "address": f"0x{addr:016X}",
                            "address_int": addr,
                            "value": round(val, 4) if isinstance(val, float) else val,
                            "category": reg.category
                        })
                        if len(candidates) >= max_candidates:
                            break

        session_id = str(uuid.uuid4())[:8]
        cls._ACTIVE_SESSIONS[session_id] = {
            "session_id": session_id,
            "pid": pid,
            "data_type": data_type,
            "candidates": candidates,
            "created_at": time.time()
        }

        return {
            "session_id": session_id,
            "pid": pid,
            "data_type": data_type,
            "scan_type": scan_type,
            "total_candidates": len(candidates),
            "candidates_sample": candidates[:50]
        }

    @classmethod
    def next_scan(
        cls,
        session_id: str,
        scan_type: str = "EXACT_VALUE",
        value: Any = None,
        min_val: Any = None,
        max_val: Any = None
    ) -> Dict[str, Any]:
        """Filters previous scan candidates by re-reading their current memory values."""
        sess = cls._ACTIVE_SESSIONS.get(session_id)
        if not sess:
            raise KeyError(f"Scan session '{session_id}' not found or expired.")

        pid = sess["pid"]
        data_type = sess["data_type"]
        prev_candidates = sess["candidates"]

        type_map = {
            "int32": ("<i", 4),
            "uint32": ("<I", 4),
            "int64": ("<q", 8),
            "uint64": ("<Q", 8),
            "float": ("<f", 4),
            "double": ("<d", 8),
        }
        fmt, step = type_map.get(data_type.lower(), ("<i", 4))

        surviving = []
        for cand in prev_candidates:
            addr = cand["address_int"]
            old_val = cand["value"]
            raw = VirtualMemoryInspector.read_process_memory(pid, addr, step)
            if len(raw) < step:
                continue
            (new_val,) = struct.unpack(fmt, raw)
            if isinstance(new_val, float):
                new_val = round(new_val, 4)

            match = False
            if scan_type == "EXACT_VALUE" and value is not None:
                match = (abs(new_val - float(value)) < 1e-4) if isinstance(new_val, float) else (new_val == int(value))
            elif scan_type == "INCREASED_VALUE":
                match = (new_val > old_val)
            elif scan_type == "DECREASED_VALUE":
                match = (new_val < old_val)
            elif scan_type == "CHANGED_VALUE":
                match = (new_val != old_val)
            elif scan_type == "UNCHANGED_VALUE":
                match = (new_val == old_val)
            elif scan_type == "VALUE_BETWEEN" and min_val is not None and max_val is not None:
                match = (float(min_val) <= new_val <= float(max_val))

            if match:
                cand_copy = dict(cand)
                cand_copy["previous_value"] = old_val
                cand_copy["value"] = new_val
                surviving.append(cand_copy)

        sess["candidates"] = surviving
        return {
            "session_id": session_id,
            "pid": pid,
            "scan_type": scan_type,
            "previous_count": len(prev_candidates),
            "surviving_count": len(surviving),
            "candidates_sample": surviving[:50]
        }


class PointerScanner:
    """
    Reverse-engineers pointer paths connecting static module roots to dynamic memory objects.
    Finds: [Module.dll + RVA] -> +Offset1 -> +Offset2 -> TargetAddress.
    Strictly read-only; uses chunked ReadProcessMemory.
    """
    @classmethod
    def find_pointer_paths(
        cls,
        pid: int,
        target_address: int,
        max_depth: int = 2,
        max_offset: int = 0x1000,
        max_results: int = 25
    ) -> Dict[str, Any]:
        """Discovers multi-level pointer paths reaching target_address."""
        ExecutionGuard.request_access(
            component="virtual_memory_inspector",
            operation="pointer_scan",
            target=f"pid_{pid}_0x{target_address:X}",
            capability=Capability.PROCESS_QUERY,
            access_mode="READ"
        )
        snap = VirtualMemoryInspector.inspect_process(pid)
        arch = snap.architecture
        ptr_size = 4 if arch == "x86-32" else 8
        fmt = "<I" if ptr_size == 4 else "<Q"

        static_regions = [r for r in snap.regions if r.mem_type == MEM_IMAGE and r.category in ("IMAGE_DATA", "IMAGE_RDATA", "IMAGE_SECTION")]
        heap_regions = [r for r in snap.regions if r.mem_type == MEM_PRIVATE and r.state == MEM_COMMIT and r.is_readable()]

        paths_found = []

        # Level 1 search: static module pointer -> target
        for reg in static_regions:
            if len(paths_found) >= max_results:
                break
            raw = VirtualMemoryInspector.read_process_memory(pid, reg.base_address, reg.region_size)
            if not raw or len(raw) < ptr_size:
                continue
            num_ptrs = (len(raw) - ptr_size) // ptr_size + 1
            for i in range(num_ptrs):
                off = i * ptr_size
                (ptr_val,) = struct.unpack_from(fmt, raw, off)
                if 0 <= (target_address - ptr_val) <= max_offset:
                    delta = target_address - ptr_val
                    mod_name = reg.module_name or "target.exe"
                    rva = (reg.base_address + off) - (reg.allocation_base or reg.base_address)
                    paths_found.append({
                        "depth": 1,
                        "base_module": mod_name,
                        "base_rva": f"0x{rva:X}",
                        "offsets": [f"0x{delta:X}"],
                        "expression": f"[{mod_name}+0x{rva:X}] + 0x{delta:X}",
                        "resolved_target": f"0x{target_address:X}"
                    })
                    if len(paths_found) >= max_results:
                        break

        # Level 2 search: static -> heap pointer -> target
        if max_depth >= 2 and len(paths_found) < max_results:
            candidate_heap_ptrs = []
            for reg in heap_regions[:20]:
                if len(candidate_heap_ptrs) >= 200:
                    break
                raw = VirtualMemoryInspector.read_process_memory(pid, reg.base_address, reg.region_size)
                if not raw or len(raw) < ptr_size:
                    continue
                num_ptrs = (len(raw) - ptr_size) // ptr_size + 1
                for i in range(num_ptrs):
                    off = i * ptr_size
                    (ptr_val,) = struct.unpack_from(fmt, raw, off)
                    if 0 <= (target_address - ptr_val) <= max_offset:
                        candidate_heap_ptrs.append((reg.base_address + off, target_address - ptr_val))

            for heap_addr, delta2 in candidate_heap_ptrs:
                if len(paths_found) >= max_results:
                    break
                for reg in static_regions:
                    if len(paths_found) >= max_results:
                        break
                    raw = VirtualMemoryInspector.read_process_memory(pid, reg.base_address, reg.region_size)
                    if not raw or len(raw) < ptr_size:
                        continue
                    num_ptrs = (len(raw) - ptr_size) // ptr_size + 1
                    for i in range(num_ptrs):
                        off = i * ptr_size
                        (ptr_val,) = struct.unpack_from(fmt, raw, off)
                        if 0 <= (heap_addr - ptr_val) <= max_offset:
                            delta1 = heap_addr - ptr_val
                            mod_name = reg.module_name or "target.exe"
                            rva = (reg.base_address + off) - (reg.allocation_base or reg.base_address)
                            paths_found.append({
                                "depth": 2,
                                "base_module": mod_name,
                                "base_rva": f"0x{rva:X}",
                                "offsets": [f"0x{delta1:X}", f"0x{delta2:X}"],
                                "expression": f"[[{mod_name}+0x{rva:X}] + 0x{delta1:X}] + 0x{delta2:X}",
                                "intermediate_heap_address": f"0x{heap_addr:X}",
                                "resolved_target": f"0x{target_address:X}"
                            })
                            if len(paths_found) >= max_results:
                                break

        return {
            "pid": pid,
            "target_address": f"0x{target_address:X}",
            "paths_count": len(paths_found),
            "paths": paths_found
        }


class StructureDissector:
    """
    Analyzes raw memory at a target address and classifies fields (pointers, vftables,
    floats, integers, strings) to reconstruct runtime data structures.
    Strictly read-only.
    """
    @classmethod
    def dissect(
        cls,
        pid: int,
        base_address: int,
        size: int = 128
    ) -> Dict[str, Any]:
        """Dissects consecutive memory slots and infers field data types."""
        ExecutionGuard.request_access(
            component="virtual_memory_inspector",
            operation="dissect_struct",
            target=f"pid_{pid}_0x{base_address:X}",
            capability=Capability.PROCESS_QUERY,
            access_mode="READ"
        )
        snap = VirtualMemoryInspector.inspect_process(pid)
        arch = snap.architecture
        ptr_size = 4 if arch == "x86-32" else 8
        fmt = "<I" if ptr_size == 4 else "<Q"

        raw = VirtualMemoryInspector.read_process_memory(pid, base_address, size)
        if not raw:
            return {
                "status": "error",
                "message": f"Could not read {size} bytes from address 0x{base_address:X}."
            }

        fields = []
        num_slots = min(len(raw) // ptr_size, size // ptr_size)
        c_lines = [f"struct Reconstructed_0x{base_address:X} {{"]

        for i in range(num_slots):
            offset = i * ptr_size
            (slot_val,) = struct.unpack_from(fmt, raw, offset)
            field_name = f"field_0x{offset:X}"

            cls_ptr = snap.classify_address(slot_val)
            f_type = "unknown"
            desc = ""

            if cls_ptr.get("status") == "COMMITTED":
                cat = cls_ptr.get("category", "")
                if cat == "IMAGE_TEXT":
                    f_type = "void**"
                    desc = f"vftable_or_code_ptr ({cls_ptr.get('module_name')}+{cls_ptr.get('rva')})"
                elif cat in ("IMAGE_DATA", "IMAGE_RDATA"):
                    f_type = "void*"
                    desc = f"static_data_ptr ({cls_ptr.get('module_name')}+{cls_ptr.get('rva')})"
                elif cat == "HEAP":
                    f_type = "void*"
                    desc = f"heap_ptr (0x{slot_val:X})"
                elif cat == "STACK":
                    f_type = "void*"
                    desc = f"stack_frame_ptr (0x{slot_val:X})"
                elif cat == "MAPPED_FILE":
                    f_type = "void*"
                    desc = f"mapped_memory_ptr (0x{slot_val:X})"
            else:
                if ptr_size == 8:
                    (i32_a, i32_b) = struct.unpack_from("<ii", raw, offset)
                    (f32_a, f32_b) = struct.unpack_from("<ff", raw, offset)
                    if 0.001 < abs(f32_a) < 100000.0 and abs(f32_a - round(f32_a, 2)) < 0.05:
                        f_type = "float"
                        desc = f"Float value: {round(f32_a, 4)}"
                    elif slot_val == 0:
                        f_type = "uint64_t"
                        desc = "Zero / NULL"
                    else:
                        f_type = "int64_t"
                        desc = f"Integer (int64: {slot_val}, int32: {i32_a})"
                else:
                    (f32,) = struct.unpack_from("<f", raw, offset)
                    if 0.001 < abs(f32) < 100000.0:
                        f_type = "float"
                        desc = f"Float value: {round(f32, 4)}"
                    else:
                        f_type = "int32_t"
                        desc = f"Integer value: {slot_val}"

            fields.append({
                "offset": f"0x{offset:X}",
                "offset_bytes": offset,
                "raw_hex": f"0x{slot_val:X}",
                "inferred_type": f_type,
                "description": desc
            })
            c_lines.append(f"    {f_type:<10} {field_name}; // {offset:02X}: {desc}")

        c_lines.append("};")

        return {
            "status": "success",
            "pid": pid,
            "base_address": f"0x{base_address:016X}",
            "architecture": arch,
            "size_analyzed": len(raw),
            "fields_count": len(fields),
            "fields": fields,
            "c_struct_definition": "\n".join(c_lines)
        }
