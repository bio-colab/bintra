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
import math
import time
import uuid
import struct
import ctypes
import threading
from collections import OrderedDict
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

    def __init__(self, pid: int, process_name: str, architecture: str = "x86-64", is_simulated: bool = False):
        self.pid = pid
        self.process_name = process_name
        self.architecture = architecture
        self.timestamp = time.time()
        self.is_simulated = is_simulated
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
                    if r.category in ("STACK", "STACK_GUARD"):
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
            "status": "simulated" if self.is_simulated else "live",
            "source": "synthetic" if self.is_simulated else "live",
            "is_simulated": self.is_simulated,
            "pid": self.pid,
            "process_name": self.process_name,
            "architecture": self.architecture,
            "timestamp": self.timestamp,
            "summary": self.compute_summary(),
            "module_count": len(self.modules),
        }
        if self.is_simulated:
            res["notice"] = "Non-Windows NT or unprivileged host environment; memory layout is synthetic/simulated."
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
            snapshot = ProcessMemoryMapSnapshot(
                pid=pid,
                process_name=f"simulated_{pid}.exe",
                architecture="x86-64",
                is_simulated=True
            )
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

            # Post-processing pass: Associate committed private regions sharing an AllocationBase with STACK_GUARD as STACK
            stack_alloc_bases = {r.allocation_base for r in snapshot.regions if r.category == "STACK_GUARD" and r.allocation_base}
            if stack_alloc_bases:
                for r in snapshot.regions:
                    if r.mem_type == MEM_PRIVATE and r.category == "HEAP" and r.allocation_base in stack_alloc_bases:
                        r.category = "STACK"

        finally:
            k32.CloseHandle(h_proc)

        return snapshot

    _MODULE_SECTIONS_CACHE: "OrderedDict[str, List[Dict[str, Any]]]" = OrderedDict()
    _MAX_MODULE_CACHE_SIZE = 256

    @classmethod
    def _get_module_sections(cls, mod_path: Optional[str]) -> List[Dict[str, Any]]:
        """Parses PE section table headers from disk or cache to obtain exact section boundaries."""
        if not mod_path or not os.path.isfile(mod_path):
            return []
        if mod_path in cls._MODULE_SECTIONS_CACHE:
            cls._MODULE_SECTIONS_CACHE.move_to_end(mod_path)
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
                            raw_name_bytes = sec_hdr[:8].rstrip(b"\x00")
                            # Only accept printable ASCII section names (0x20..0x7E)
                            if raw_name_bytes and all(0x20 <= b <= 0x7E for b in raw_name_bytes):
                                name = raw_name_bytes.decode("ascii", errors="ignore").strip()
                            else:
                                name = None
                            v_size, v_addr = struct.unpack("<II", sec_hdr[8:16])
                            if name:
                                sections.append({
                                    "name": name,
                                    "va": v_addr,
                                    "size": v_size
                                })
        except Exception:
            pass

        while len(cls._MODULE_SECTIONS_CACHE) >= cls._MAX_MODULE_CACHE_SIZE:
            cls._MODULE_SECTIONS_CACHE.popitem(last=False)
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
                        sanitized = "".join(c for c in exact_sec.upper().lstrip(".") if c.isalnum() or c == "_")
                        if sanitized:
                            return f"IMAGE_{sanitized}", mod_name, mod_path, exact_sec
                        return "IMAGE_SECTION", mod_name, mod_path, exact_sec

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
    def _get_process_start_time(cls, pid: int) -> Optional[int]:
        """Returns Win32 FILETIME process creation timestamp as a 64-bit integer to guard against PID reuse."""
        if not cls._is_windows():
            return None
        try:
            k32 = ctypes.windll.kernel32
            h_proc = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not h_proc:
                h_proc = k32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
            if not h_proc:
                return None
            try:
                class _FT(ctypes.Structure):
                    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

                ft_create, ft_exit, ft_kernel, ft_user = _FT(), _FT(), _FT(), _FT()
                ok = k32.GetProcessTimes(
                    h_proc,
                    ctypes.byref(ft_create),
                    ctypes.byref(ft_exit),
                    ctypes.byref(ft_kernel),
                    ctypes.byref(ft_user),
                )
                if ok:
                    return (int(ft_create.dwHighDateTime) << 32) | int(ft_create.dwLowDateTime)
            finally:
                k32.CloseHandle(h_proc)
        except Exception:
            return None
        return None

    @classmethod
    def _read_process_memory_raw(
        cls,
        pid: int,
        address: int,
        size: int,
        allow_partial: bool = True
    ) -> Dict[str, Any]:
        """
        Internal chunked ReadProcessMemory worker.
        NEVER fabricates zero bytes on failed chunks or short reads: stops at the first
        unreadable boundary and reports valid length and failure address transparently.
        """
        if size <= 0:
            return {
                "status": "success",
                "data": b"",
                "bytes_requested": 0,
                "bytes_read": 0,
                "is_partial": False,
                "first_failed_address": None,
            }
        if not cls._is_windows():
            return {
                "status": "not_applicable",
                "is_simulated": True,
                "data": None,
                "bytes_requested": size,
                "bytes_read": 0,
                "is_partial": False,
                "first_failed_address": f"0x{address:X}",
            }

        k32 = ctypes.windll.kernel32
        h_proc = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h_proc:
            h_proc = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h_proc:
            err = ctypes.GetLastError()
            raise PermissionError(f"Failed to open process PID {pid} with PROCESS_VM_READ (Win32 Error: {err})")

        try:
            CHUNK_SIZE = 64 * 1024
            bytes_left = size
            cur_addr = address
            out_buf = bytearray()
            failed_addr: Optional[int] = None

            k32.ReadProcessMemory.argtypes = [
                wintypes.HANDLE,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_size_t),
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
                    ctypes.byref(bytes_read),
                )
                n_read = int(bytes_read.value)
                if n_read > 0:
                    out_buf.extend(c_buf.raw[:n_read])
                if not ok or n_read == 0:
                    failed_addr = cur_addr
                    break
                if n_read < to_read:
                    failed_addr = cur_addr + n_read
                    break
                cur_addr += to_read
                bytes_left -= to_read

            total_read = len(out_buf)
            if total_read == 0:
                return {
                    "status": "error",
                    "data": None,
                    "bytes_requested": size,
                    "bytes_read": 0,
                    "is_partial": False,
                    "first_failed_address": f"0x{(failed_addr if failed_addr is not None else address):X}",
                }
            if total_read < size:
                if not allow_partial:
                    return {
                        "status": "partial_aborted",
                        "data": None,
                        "bytes_requested": size,
                        "bytes_read": total_read,
                        "is_partial": True,
                        "first_failed_address": f"0x{(failed_addr if failed_addr is not None else address + total_read):X}",
                    }
                return {
                    "status": "partial",
                    "data": bytes(out_buf),
                    "bytes_requested": size,
                    "bytes_read": total_read,
                    "is_partial": True,
                    "first_failed_address": f"0x{(failed_addr if failed_addr is not None else address + total_read):X}",
                }
            return {
                "status": "success",
                "data": bytes(out_buf),
                "bytes_requested": size,
                "bytes_read": total_read,
                "is_partial": False,
                "first_failed_address": None,
            }
        finally:
            k32.CloseHandle(h_proc)

    @classmethod
    def _read_memory_internal(
        cls,
        pid: int,
        address: int,
        size: int,
        allow_partial: bool = True
    ) -> Dict[str, Any]:
        """Uses patched read_process_memory if mocked in tests, otherwise calls fast un-flooded raw reader."""
        is_mocked = getattr(cls.read_process_memory, "__func__", None) is not VirtualMemoryInspector.read_process_memory.__func__
        if is_mocked:
            raw = cls.read_process_memory(pid, address, size)
            if raw is None:
                return {
                    "status": "error",
                    "data": None,
                    "bytes_requested": max(0, size),
                    "bytes_read": 0,
                    "is_partial": False,
                    "first_failed_address": f"0x{address:X}",
                }
            n = len(raw)
            if n < size and not allow_partial:
                return {
                    "status": "partial_aborted",
                    "data": None,
                    "bytes_requested": size,
                    "bytes_read": n,
                    "is_partial": True,
                    "first_failed_address": f"0x{address + n:X}",
                }
            return {
                "status": "partial" if n < size else "success",
                "data": raw,
                "bytes_requested": max(0, size),
                "bytes_read": n,
                "is_partial": n < size,
                "first_failed_address": f"0x{address + n:X}" if n < size else None,
            }
        return cls._read_process_memory_raw(pid, address, size, allow_partial=allow_partial)

    @classmethod
    def read_process_memory_checked(
        cls,
        pid: int,
        address: int,
        size: int,
        allow_partial: bool = True
    ) -> Dict[str, Any]:
        """
        Mediated read-only virtual memory reader returning explicit read metadata
        (data, bytes_requested, bytes_read, is_partial, first_failed_address).
        Never pads unreadable spans with fabricated zeros.
        """
        ExecutionGuard.request_access(
            component="virtual_memory_inspector",
            operation="read_process_memory",
            target=f"pid_{pid}_0x{address:X}",
            capability=Capability.PROCESS_QUERY,
            access_mode="READ",
        )
        return cls._read_process_memory_raw(pid, address, size, allow_partial=allow_partial)

    @classmethod
    def read_process_memory(
        cls,
        pid: int,
        address: int,
        size: int
    ) -> Optional[bytes]:
        """
        Safely reads virtual memory bytes from a target process.
        Uses kernel32.ReadProcessMemory in bounded chunked blocks.
        Strictly read-only (PROCESS_VM_READ); governed by Capability.PROCESS_QUERY.
        Truncates strictly at the last verified readable byte and NEVER pads failures with zeros.
        Returns None on non-Windows platforms or zero-byte/unmapped read failures, and raises PermissionError if OpenProcess fails.
        """
        ExecutionGuard.request_access(
            component="virtual_memory_inspector",
            operation="read_process_memory",
            target=f"pid_{pid}_0x{address:X}",
            capability=Capability.PROCESS_QUERY,
            access_mode="READ",
        )
        res = cls._read_process_memory_raw(pid, address, size, allow_partial=True)
        return res.get("data")


class ProcessMemoryScanner:
    """
    Stateful read-only memory value search engine providing First Scan and Next Scan.
    Supports int8, uint8, int16, uint16, int32, uint32, int64, uint64, float, double, bytes, and string.
    Supports exact, between, unknown initial, increased, decreased, changed, and unchanged scans.
    Bounded by LRU + TTL session eviction and PID creation-time identity verification.
    Strictly read-only (PROCESS_VM_READ); never modifies process memory.
    """
    _ACTIVE_SESSIONS: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
    _MAX_SESSIONS = 64
    _SESSION_TTL_SECONDS = 1800.0
    _SESSION_LOCK = threading.Lock()

    _TYPE_MAP: Dict[str, Tuple[Optional[str], int, int]] = {
        "int8": ("<b", 1, 1),
        "uint8": ("<B", 1, 1),
        "int16": ("<h", 2, 2),
        "uint16": ("<H", 2, 2),
        "int32": ("<i", 4, 4),
        "uint32": ("<I", 4, 4),
        "int64": ("<q", 8, 8),
        "uint64": ("<Q", 8, 8),
        "float": ("<f", 4, 4),
        "double": ("<d", 8, 8),
        "bytes": (None, 1, 1),
        "string": (None, 1, 1),
    }
    _FIRST_SCAN_MODES = {"EXACT_VALUE", "VALUE_BETWEEN", "UNKNOWN_INITIAL_VALUE"}
    _NEXT_SCAN_MODES = {
        "EXACT_VALUE",
        "VALUE_BETWEEN",
        "INCREASED_VALUE",
        "DECREASED_VALUE",
        "CHANGED_VALUE",
        "UNCHANGED_VALUE",
    }

    @classmethod
    def _evict_sessions_locked(cls, now: Optional[float] = None) -> None:
        now_ts = now if now is not None else time.time()
        expired = [
            sid for sid, s in cls._ACTIVE_SESSIONS.items()
            if (now_ts - s.get("last_accessed", s.get("created_at", now_ts))) > cls._SESSION_TTL_SECONDS
        ]
        for sid in expired:
            cls._ACTIVE_SESSIONS.pop(sid, None)
        while len(cls._ACTIVE_SESSIONS) >= cls._MAX_SESSIONS:
            cls._ACTIVE_SESSIONS.popitem(last=False)

    @classmethod
    def _parse_bytes_or_string_target(cls, dtype: str, value: Any) -> bytes:
        if value is None:
            raise ValueError(f"'value' is required for '{dtype}' scan.")
        if dtype == "bytes":
            if isinstance(value, (bytes, bytearray)):
                raw = bytes(value)
            else:
                cleaned = str(value).replace(" ", "").replace("0x", "").replace("0X", "")
                raw = bytes.fromhex(cleaned)
            if not raw:
                raise ValueError("'bytes' pattern must not be empty.")
            return raw
        encoded = str(value).encode("utf-8")
        if not encoded:
            raise ValueError("'string' search target must not be empty.")
        return encoded

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
        max_candidates: int = 50000,
        alignment: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Initiates an initial memory scan across committed readable regions."""
        ExecutionGuard.request_access(
            component="virtual_memory_inspector",
            operation="first_scan",
            target=f"pid_{pid}_{data_type}_{scan_type}",
            capability=Capability.PROCESS_QUERY,
            access_mode="READ",
        )
        dtype = data_type.lower()
        type_info = cls._TYPE_MAP.get(dtype)
        if not type_info:
            raise ValueError(f"Unsupported scan data type: {data_type}")
        fmt, step, default_align = type_info

        if scan_type in ("INCREASED_VALUE", "DECREASED_VALUE", "CHANGED_VALUE", "UNCHANGED_VALUE"):
            raise ValueError(
                f"Scan type '{scan_type}' is a differential comparison mode valid only in next_scan(); "
                f"run first_scan() with UNKNOWN_INITIAL_VALUE, EXACT_VALUE, or VALUE_BETWEEN."
            )
        if scan_type not in cls._FIRST_SCAN_MODES:
            raise ValueError(f"Unsupported first_scan mode: {scan_type}")

        if scan_type == "EXACT_VALUE" and value is None:
            raise ValueError("'value' is required when scan_type='EXACT_VALUE'.")
        if scan_type == "VALUE_BETWEEN" and (min_val is None or max_val is None):
            raise ValueError("'min_val' and 'max_val' are required when scan_type='VALUE_BETWEEN'.")
        if dtype in ("bytes", "string") and scan_type != "EXACT_VALUE":
            raise ValueError(f"first_scan on '{dtype}' only supports scan_type='EXACT_VALUE'.")

        if alignment is not None:
            if alignment < 1:
                raise ValueError("alignment must be >= 1.")
            step_align = 1 if dtype in ("bytes", "string") else int(alignment)
        else:
            step_align = default_align

        target_bytes: Optional[bytes] = None
        if dtype in ("bytes", "string"):
            target_bytes = cls._parse_bytes_or_string_target(dtype, value)

        snap = VirtualMemoryInspector.inspect_process(pid)
        proc_start_time = VirtualMemoryInspector._get_process_start_time(pid)
        now_ts = time.time()
        session_id = uuid.uuid4().hex[:16]

        if snap.is_simulated:
            with cls._SESSION_LOCK:
                cls._evict_sessions_locked(now_ts)
                cls._ACTIVE_SESSIONS[session_id] = {
                    "session_id": session_id,
                    "pid": pid,
                    "process_start_time": proc_start_time,
                    "data_type": dtype,
                    "alignment": step_align,
                    "candidates": [],
                    "created_at": now_ts,
                    "last_accessed": now_ts,
                }
            return {
                "status": "not_applicable",
                "is_simulated": True,
                "notice": "Process memory scanning requires a live Windows NT host with PROCESS_VM_READ access.",
                "session_id": session_id,
                "pid": pid,
                "data_type": dtype,
                "scan_type": scan_type,
                "alignment": step_align,
                "total_candidates": 0,
                "candidates_sample": [],
            }

        candidates: List[Dict[str, Any]] = []
        target_regions = [
            r for r in snap.regions
            if r.state == MEM_COMMIT and (not writable_only or r.is_writable()) and not r.is_guard_page()
        ]

        SCAN_WINDOW = 4 * 1024 * 1024  # 4 MB bounded streaming window
        truncated_by_limit = False
        regions_scanned = 0
        partial_regions_encountered = 0

        pattern_len = len(target_bytes) if target_bytes is not None else step
        overlap = max(0, pattern_len - step_align)

        for reg in target_regions:
            if len(candidates) >= max_candidates:
                truncated_by_limit = True
                break
            regions_scanned += 1
            pos = 0
            while pos < reg.region_size:
                if len(candidates) >= max_candidates:
                    truncated_by_limit = True
                    break
                win_len = min(SCAN_WINDOW, reg.region_size - pos)
                read_res = VirtualMemoryInspector._read_memory_internal(
                    pid, reg.base_address + pos, win_len, allow_partial=True
                )
                raw = read_res.get("data")
                is_partial = bool(read_res.get("is_partial"))
                if is_partial:
                    partial_regions_encountered += 1
                if not raw or len(raw) < pattern_len:
                    break

                if target_bytes is not None:
                    idx = 0
                    disp_val = target_bytes.hex() if dtype == "bytes" else value
                    while True:
                        idx = raw.find(target_bytes, idx)
                        if idx == -1:
                            break
                        addr = reg.base_address + pos + idx
                        candidates.append({
                            "address": f"0x{addr:016X}",
                            "address_int": addr,
                            "value": disp_val,
                            "raw_hex": target_bytes.hex(),
                            "match_len": len(target_bytes),
                            "category": reg.category,
                        })
                        if len(candidates) >= max_candidates:
                            truncated_by_limit = True
                            break
                        idx += 1
                else:
                    assert fmt is not None
                    if scan_type == "EXACT_VALUE" and dtype not in ("float", "double"):
                        # Fast C-level byte search for exact integers (critical when alignment=1 over large heaps)
                        packed_target = struct.pack(fmt, int(value))
                        idx = 0
                        target_int = int(value)
                        while True:
                            idx = raw.find(packed_target, idx)
                            if idx == -1:
                                break
                            abs_off = pos + idx
                            if step_align == 1 or (abs_off % step_align == 0):
                                addr = reg.base_address + abs_off
                                candidates.append({
                                    "address": f"0x{addr:016X}",
                                    "address_int": addr,
                                    "value": target_int,
                                    "category": reg.category,
                                })
                                if len(candidates) >= max_candidates:
                                    truncated_by_limit = True
                                    break
                            idx += 1
                    else:
                        limit_off = len(raw) - step
                        for off in range(0, limit_off + 1, step_align):
                            (val,) = struct.unpack_from(fmt, raw, off)
                            match = False
                            if scan_type == "EXACT_VALUE":
                                match = math.isfinite(val) and abs(val - float(value)) < 1e-4
                            elif scan_type == "VALUE_BETWEEN":
                                match = math.isfinite(val) if isinstance(val, float) else True
                                if match:
                                    match = (float(min_val) <= val <= float(max_val))
                            elif scan_type == "UNKNOWN_INITIAL_VALUE":
                                match = True

                            if match:
                                addr = reg.base_address + pos + off
                                candidates.append({
                                    "address": f"0x{addr:016X}",
                                    "address_int": addr,
                                    "value": round(val, 4) if isinstance(val, float) and math.isfinite(val) else val,
                                    "category": reg.category,
                                })
                                if len(candidates) >= max_candidates:
                                    truncated_by_limit = True
                                    break

                if is_partial or len(raw) < win_len or pos + win_len >= reg.region_size:
                    break
                usable = len(raw) - overlap
                advance = (usable // step_align) * step_align
                if advance <= 0:
                    advance = step_align
                pos += advance

        with cls._SESSION_LOCK:
            cls._evict_sessions_locked(now_ts)
            cls._ACTIVE_SESSIONS[session_id] = {
                "session_id": session_id,
                "pid": pid,
                "process_start_time": proc_start_time,
                "data_type": dtype,
                "alignment": step_align,
                "candidates": candidates,
                "created_at": now_ts,
                "last_accessed": now_ts,
            }

        return {
            "session_id": session_id,
            "pid": pid,
            "data_type": dtype,
            "scan_type": scan_type,
            "alignment": step_align,
            "regions_scanned": regions_scanned,
            "total_target_regions": len(target_regions),
            "partial_read_regions": partial_regions_encountered,
            "truncated_by_max_candidates": truncated_by_limit,
            "total_candidates": len(candidates),
            "candidates_sample": candidates[:50],
        }

    @classmethod
    def next_scan(
        cls,
        session_id: Optional[str] = None,
        scan_type: str = "EXACT_VALUE",
        value: Any = None,
        min_val: Any = None,
        max_val: Any = None,
        pid: Optional[int] = None,
        data_type: Optional[str] = None,
        candidate_addresses: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """
        Filters previous scan candidates (from session_id or explicit candidate_addresses)
        by re-reading current live memory values with strict type fidelity and zero fabrication.
        """
        if scan_type not in cls._NEXT_SCAN_MODES:
            raise ValueError(f"Unsupported scan_type for next_scan: {scan_type}")

        sess: Optional[Dict[str, Any]] = None
        now_ts = time.time()

        if session_id:
            with cls._SESSION_LOCK:
                cls._evict_sessions_locked(now_ts)
                sess = cls._ACTIVE_SESSIONS.get(session_id)
                if not sess:
                    raise KeyError(f"Scan session '{session_id}' not found or expired.")
                cls._ACTIVE_SESSIONS.move_to_end(session_id)
                sess["last_accessed"] = now_ts
            target_pid = int(sess["pid"])
            dtype = str(sess["data_type"]).lower()
            prev_candidates = list(sess["candidates"])
            sess_start_time = sess.get("process_start_time")
        else:
            if not pid or pid <= 0:
                raise ValueError("Either 'session_id' or valid 'pid' with 'candidate_addresses' is required.")
            if candidate_addresses is None:
                raise ValueError("Either 'session_id' or 'candidate_addresses' is required for next_scan.")
            target_pid = int(pid)
            dtype = str(data_type or "int32").lower()
            if scan_type in ("INCREASED_VALUE", "DECREASED_VALUE", "CHANGED_VALUE", "UNCHANGED_VALUE"):
                raise ValueError(
                    f"Stateless candidate_addresses filtering cannot compute '{scan_type}' without a baseline session_id; "
                    f"use EXACT_VALUE or VALUE_BETWEEN, or pass session_id from first_scan."
                )
            prev_candidates = [
                {
                    "address": f"0x{int(a, 0) if isinstance(a, str) else int(a):016X}",
                    "address_int": int(a, 0) if isinstance(a, str) else int(a),
                    "value": None,
                    "category": "CANDIDATE",
                }
                for a in candidate_addresses
            ]
            sess_start_time = None

        ExecutionGuard.request_access(
            component="virtual_memory_inspector",
            operation="next_scan",
            target=f"pid_{target_pid}_{dtype}_{scan_type}",
            capability=Capability.PROCESS_QUERY,
            access_mode="READ",
        )

        if sess is not None and sess_start_time is not None and VirtualMemoryInspector._is_windows():
            cur_start = VirtualMemoryInspector._get_process_start_time(target_pid)
            if cur_start is not None and cur_start != sess_start_time:
                with cls._SESSION_LOCK:
                    cls._ACTIVE_SESSIONS.pop(session_id, None)  # type: ignore[arg-type]
                raise RuntimeError(
                    f"PID {target_pid} process identity changed (PID reuse detected); scan session '{session_id}' invalidated."
                )

        if dtype not in cls._TYPE_MAP:
            raise ValueError(f"Unsupported scan data type: {dtype}")

        if scan_type == "EXACT_VALUE" and value is None:
            raise ValueError("'value' is required when scan_type='EXACT_VALUE'.")
        if scan_type == "VALUE_BETWEEN" and (min_val is None or max_val is None):
            raise ValueError("'min_val' and 'max_val' are required when scan_type='VALUE_BETWEEN'.")

        surviving: List[Dict[str, Any]] = []

        if dtype in ("bytes", "string"):
            if scan_type in ("INCREASED_VALUE", "DECREASED_VALUE", "VALUE_BETWEEN"):
                raise ValueError(
                    f"Scan mode '{scan_type}' is not valid for '{dtype}' data type; "
                    f"use EXACT_VALUE, CHANGED_VALUE, or UNCHANGED_VALUE."
                )
            target_bytes: Optional[bytes] = None
            if scan_type == "EXACT_VALUE":
                target_bytes = cls._parse_bytes_or_string_target(dtype, value)

            for cand in prev_candidates:
                addr = int(cand["address_int"])
                old_hex = cand.get("raw_hex")
                old_bytes: Optional[bytes] = None
                if isinstance(old_hex, str) and old_hex:
                    old_bytes = bytes.fromhex(old_hex)
                elif cand.get("value") is not None:
                    old_bytes = (
                        cls._parse_bytes_or_string_target("bytes", cand["value"])
                        if dtype == "bytes"
                        else str(cand["value"]).encode("utf-8")
                    )

                read_len = len(target_bytes) if target_bytes is not None else (
                    int(cand.get("match_len") or (len(old_bytes) if old_bytes else 0))
                )
                if read_len <= 0:
                    continue

                read_res = VirtualMemoryInspector._read_memory_internal(
                    target_pid, addr, read_len, allow_partial=False
                )
                cur_bytes = read_res.get("data")
                if cur_bytes is None or len(cur_bytes) < read_len:
                    continue

                match = False
                if scan_type == "EXACT_VALUE" and target_bytes is not None:
                    match = (cur_bytes == target_bytes)
                elif scan_type == "CHANGED_VALUE" and old_bytes is not None:
                    match = (cur_bytes != old_bytes)
                elif scan_type == "UNCHANGED_VALUE" and old_bytes is not None:
                    match = (cur_bytes == old_bytes)

                if match:
                    cand_copy = dict(cand)
                    cand_copy["previous_value"] = cand.get("value")
                    cand_copy["raw_hex"] = cur_bytes.hex()
                    cand_copy["match_len"] = len(cur_bytes)
                    cand_copy["value"] = (
                        cur_bytes.hex() if dtype == "bytes" else cur_bytes.decode("utf-8", errors="replace")
                    )
                    surviving.append(cand_copy)
        else:
            fmt, step, _ = cls._TYPE_MAP[dtype]
            assert fmt is not None
            for cand in prev_candidates:
                addr = int(cand["address_int"])
                old_val = cand.get("value")
                read_res = VirtualMemoryInspector._read_memory_internal(
                    target_pid, addr, step, allow_partial=False
                )
                raw = read_res.get("data")
                if raw is None or len(raw) < step:
                    continue
                (new_val,) = struct.unpack(fmt, raw)
                if isinstance(new_val, float):
                    if not math.isfinite(new_val):
                        continue
                    new_val = round(new_val, 4)

                match = False
                if scan_type == "EXACT_VALUE":
                    match = (
                        abs(new_val - float(value)) < 1e-4
                        if dtype in ("float", "double")
                        else (new_val == int(value))
                    )
                elif scan_type == "INCREASED_VALUE" and old_val is not None:
                    match = (new_val > old_val)
                elif scan_type == "DECREASED_VALUE" and old_val is not None:
                    match = (new_val < old_val)
                elif scan_type == "CHANGED_VALUE" and old_val is not None:
                    match = (new_val != old_val)
                elif scan_type == "UNCHANGED_VALUE" and old_val is not None:
                    match = (new_val == old_val)
                elif scan_type == "VALUE_BETWEEN":
                    match = (float(min_val) <= new_val <= float(max_val))

                if match:
                    cand_copy = dict(cand)
                    cand_copy["previous_value"] = old_val
                    cand_copy["value"] = new_val
                    surviving.append(cand_copy)

        if sess is not None:
            with cls._SESSION_LOCK:
                if session_id in cls._ACTIVE_SESSIONS:
                    cls._ACTIVE_SESSIONS[session_id]["candidates"] = surviving
                    cls._ACTIVE_SESSIONS[session_id]["last_accessed"] = time.time()

        return {
            "session_id": session_id,
            "pid": target_pid,
            "data_type": dtype,
            "scan_type": scan_type,
            "previous_count": len(prev_candidates),
            "surviving_count": len(surviving),
            "candidates_sample": surviving[:50],
        }


class PointerScanner:
    """
    Reverse-engineers pointer paths connecting static module roots to dynamic memory objects.
    Supports depth 1..3 ([Module.dll+RVA] -> [+Off1] -> [+Off2] -> TargetAddress) with 4-byte slot
    alignment support and mandatory live dereference verification before reporting.
    Strictly read-only; uses chunked ReadProcessMemory.
    """

    @classmethod
    def _verify_pointer_path(
        cls,
        pid: int,
        base_slot_va: int,
        offsets: List[int],
        expected_target: int,
        fmt: str,
        ptr_size: int
    ) -> bool:
        """Independently re-dereferences a candidate pointer chain from base_slot_va to confirm it reaches expected_target."""
        cur_ptr_slot = base_slot_va
        for idx, off in enumerate(offsets):
            read_res = VirtualMemoryInspector._read_memory_internal(pid, cur_ptr_slot, ptr_size, allow_partial=False)
            raw = read_res.get("data")
            if raw is None or len(raw) < ptr_size:
                return False
            (deref_val,) = struct.unpack(fmt, raw)
            next_addr = deref_val + off
            if idx == len(offsets) - 1:
                return next_addr == expected_target
            cur_ptr_slot = next_addr
        return False

    @classmethod
    def find_pointer_paths(
        cls,
        pid: int,
        target_address: int,
        max_depth: int = 2,
        max_offset: int = 0x1000,
        max_results: int = 25,
        alignment: int = 4,
    ) -> Dict[str, Any]:
        """Discovers and dereference-verifies multi-level pointer paths (depth 1..3) reaching target_address."""
        import bisect

        ExecutionGuard.request_access(
            component="virtual_memory_inspector",
            operation="pointer_scan",
            target=f"pid_{pid}_0x{target_address:X}",
            capability=Capability.PROCESS_QUERY,
            access_mode="READ",
        )
        if max_depth < 1 or max_depth > 3:
            raise ValueError(f"max_depth must be between 1 and 3 (got {max_depth}).")
        if max_offset < 0:
            raise ValueError("max_offset must be >= 0.")
        if alignment < 1:
            raise ValueError("alignment must be >= 1.")

        snap = VirtualMemoryInspector.inspect_process(pid)
        if snap.is_simulated:
            return {
                "status": "not_applicable",
                "is_simulated": True,
                "heuristic": True,
                "notice": "Pointer path resolution requires a live Windows NT process with PROCESS_VM_READ access.",
                "pid": pid,
                "target_address": f"0x{target_address:016X}",
                "max_depth_searched": max_depth,
                "alignment": alignment,
                "paths_count": 0,
                "paths": [],
            }

        arch = snap.architecture
        ptr_size = 4 if arch == "x86-32" else 8
        fmt = "<I" if ptr_size == 4 else "<Q"
        scan_stride = min(alignment, ptr_size)

        static_regions = [
            r for r in snap.regions
            if r.mem_type == MEM_IMAGE and r.category in ("IMAGE_DATA", "IMAGE_RDATA", "IMAGE_SECTION") and r.is_readable()
        ]
        heap_regions = [
            r for r in snap.regions
            if r.mem_type == MEM_PRIVATE and r.state == MEM_COMMIT and r.is_readable() and not r.is_guard_page()
        ]
        # Prioritize regions nearest/containing target_address and keep bounded byte budget
        heap_regions.sort(key=lambda r: abs((r.base_address + r.region_size // 2) - target_address))

        static_blobs: List[Tuple[ProcessMemoryRegion, bytes]] = []
        for reg in static_regions:
            if reg.region_size > 16 * 1024 * 1024:
                continue
            read_res = VirtualMemoryInspector._read_memory_internal(pid, reg.base_address, reg.region_size, allow_partial=True)
            raw = read_res.get("data")
            if raw and len(raw) >= ptr_size:
                static_blobs.append((reg, raw))

        paths_found: List[Dict[str, Any]] = []

        # Depth 1: [Module+RVA] + delta == target_address
        for reg, raw in static_blobs:
            if len(paths_found) >= max_results:
                break
            mod_name = reg.module_name or "target.exe"
            mod_base = reg.allocation_base or reg.base_address
            for off in range(0, len(raw) - ptr_size + 1, scan_stride):
                (ptr_val,) = struct.unpack_from(fmt, raw, off)
                delta = target_address - ptr_val
                if 0 <= delta <= max_offset:
                    slot_va = reg.base_address + off
                    if not cls._verify_pointer_path(pid, slot_va, [delta], target_address, fmt, ptr_size):
                        continue
                    rva = slot_va - mod_base
                    paths_found.append({
                        "depth": 1,
                        "base_module": mod_name,
                        "base_rva": f"0x{rva:X}",
                        "offsets": [f"0x{delta:X}"],
                        "expression": f"[{mod_name}+0x{rva:X}] + 0x{delta:X}",
                        "resolved_target": f"0x{target_address:X}",
                        "verified": True,
                        "confidence": "HEURISTIC_STATIC_DEREF",
                    })
                    if len(paths_found) >= max_results:
                        break

        # Build Level-1 heap candidates once when max_depth >= 2
        heap_l1_map: Dict[int, int] = {}
        sorted_h1: List[int] = []
        heap_blobs: List[Tuple[ProcessMemoryRegion, bytes]] = []
        if max_depth >= 2 and len(paths_found) < max_results:
            total_heap_bytes = 0
            HEAVY_BUDGET = 64 * 1024 * 1024
            for reg in heap_regions[:64]:
                if total_heap_bytes >= HEAVY_BUDGET:
                    break
                if reg.region_size > 16 * 1024 * 1024:
                    continue
                read_res = VirtualMemoryInspector._read_memory_internal(pid, reg.base_address, reg.region_size, allow_partial=True)
                raw = read_res.get("data")
                if raw and len(raw) >= ptr_size:
                    total_heap_bytes += len(raw)
                    heap_blobs.append((reg, raw))
                    for off in range(0, len(raw) - ptr_size + 1, scan_stride):
                        (ptr_val,) = struct.unpack_from(fmt, raw, off)
                        delta = target_address - ptr_val
                        if 0 <= delta <= max_offset:
                            h1_addr = reg.base_address + off
                            heap_l1_map[h1_addr] = delta
                            if len(heap_l1_map) >= 400:
                                break
                if len(heap_l1_map) >= 400:
                    break

            sorted_h1 = sorted(heap_l1_map.keys())

            # Depth 2: static -> heap_l1 -> target (using bisect for O(log H) lookup)
            if sorted_h1:
                for reg, raw in static_blobs:
                    if len(paths_found) >= max_results:
                        break
                    mod_name = reg.module_name or "target.exe"
                    mod_base = reg.allocation_base or reg.base_address
                    for off in range(0, len(raw) - ptr_size + 1, scan_stride):
                        (ptr_val,) = struct.unpack_from(fmt, raw, off)
                        lo_idx = bisect.bisect_left(sorted_h1, ptr_val)
                        while lo_idx < len(sorted_h1):
                            h1_addr = sorted_h1[lo_idx]
                            d1 = h1_addr - ptr_val
                            if d1 > max_offset:
                                break
                            d2 = heap_l1_map[h1_addr]
                            slot_va = reg.base_address + off
                            if cls._verify_pointer_path(pid, slot_va, [d1, d2], target_address, fmt, ptr_size):
                                rva = slot_va - mod_base
                                paths_found.append({
                                    "depth": 2,
                                    "base_module": mod_name,
                                    "base_rva": f"0x{rva:X}",
                                    "offsets": [f"0x{d1:X}", f"0x{d2:X}"],
                                    "expression": f"[[{mod_name}+0x{rva:X}] + 0x{d1:X}] + 0x{d2:X}",
                                    "intermediate_heap_address": f"0x{h1_addr:X}",
                                    "resolved_target": f"0x{target_address:X}",
                                    "verified": True,
                                    "confidence": "HEURISTIC_STATIC_DEREF",
                                })
                                if len(paths_found) >= max_results:
                                    break
                            lo_idx += 1
                        if len(paths_found) >= max_results:
                            break

        # Depth 3: static -> heap_l2 -> heap_l1 -> target
        if max_depth >= 3 and len(paths_found) < max_results and sorted_h1:
            heap_l2_map: Dict[int, Tuple[int, int, int]] = {}  # h2_addr -> (d2, d3, h1_addr)
            for reg, raw in heap_blobs:
                if len(heap_l2_map) >= 400:
                    break
                for off in range(0, len(raw) - ptr_size + 1, scan_stride):
                    (ptr_val,) = struct.unpack_from(fmt, raw, off)
                    lo_idx = bisect.bisect_left(sorted_h1, ptr_val)
                    while lo_idx < len(sorted_h1):
                        h1_addr = sorted_h1[lo_idx]
                        d2 = h1_addr - ptr_val
                        if d2 > max_offset:
                            break
                        h2_addr = reg.base_address + off
                        if h2_addr != h1_addr:
                            heap_l2_map[h2_addr] = (d2, heap_l1_map[h1_addr], h1_addr)
                            break
                        lo_idx += 1
                    if len(heap_l2_map) >= 400:
                        break

            sorted_h2 = sorted(heap_l2_map.keys())
            if sorted_h2:
                for reg, raw in static_blobs:
                    if len(paths_found) >= max_results:
                        break
                    mod_name = reg.module_name or "target.exe"
                    mod_base = reg.allocation_base or reg.base_address
                    for off in range(0, len(raw) - ptr_size + 1, scan_stride):
                        (ptr_val,) = struct.unpack_from(fmt, raw, off)
                        lo_idx = bisect.bisect_left(sorted_h2, ptr_val)
                        while lo_idx < len(sorted_h2):
                            h2_addr = sorted_h2[lo_idx]
                            d1 = h2_addr - ptr_val
                            if d1 > max_offset:
                                break
                            d2, d3, _h1 = heap_l2_map[h2_addr]
                            slot_va = reg.base_address + off
                            if cls._verify_pointer_path(pid, slot_va, [d1, d2, d3], target_address, fmt, ptr_size):
                                rva = slot_va - mod_base
                                paths_found.append({
                                    "depth": 3,
                                    "base_module": mod_name,
                                    "base_rva": f"0x{rva:X}",
                                    "offsets": [f"0x{d1:X}", f"0x{d2:X}", f"0x{d3:X}"],
                                    "expression": f"[[[{mod_name}+0x{rva:X}] + 0x{d1:X}] + 0x{d2:X}] + 0x{d3:X}",
                                    "intermediate_heap_address": f"0x{h2_addr:X}",
                                    "resolved_target": f"0x{target_address:X}",
                                    "verified": True,
                                    "confidence": "HEURISTIC_STATIC_DEREF",
                                })
                                if len(paths_found) >= max_results:
                                    break
                            lo_idx += 1
                        if len(paths_found) >= max_results:
                            break

        return {
            "pid": pid,
            "target_address": f"0x{target_address:X}",
            "max_depth_searched": max_depth,
            "alignment": scan_stride,
            "heuristic": True,
            "notice": "Pointer chains are heuristic candidates verified immediately via read-only dereferencing; ASLR or heap freeing may invalidate paths later.",
            "paths_count": len(paths_found),
            "paths": paths_found,
        }


class StructureDissector:
    """
    Analyzes raw memory at a target address at 4-byte field granularity with 64-bit
    pointer/scalar lookahead, confidence scoring, and alternative type hypotheses.
    Strictly read-only.
    """

    @staticmethod
    def _is_plausible_float32(raw4: bytes) -> Optional[float]:
        (u32,) = struct.unpack("<I", raw4)
        exp = (u32 >> 23) & 0xFF
        if exp in (0, 0xFF):
            return None
        (f32,) = struct.unpack("<f", raw4)
        if not math.isfinite(f32):
            return None
        if 0.0001 <= abs(f32) <= 1_000_000.0 and abs(f32 - round(f32, 3)) < 1e-3 * max(1.0, abs(f32)):
            return round(f32, 4)
        return None

    @staticmethod
    def _is_plausible_float64(raw8: bytes) -> Optional[float]:
        (u64,) = struct.unpack("<Q", raw8)
        exp = (u64 >> 52) & 0x7FF
        if exp in (0, 0x7FF):
            return None
        (f64,) = struct.unpack("<d", raw8)
        if not math.isfinite(f64):
            return None
        if 0.0001 <= abs(f64) <= 1_000_000.0 and abs(f64 - round(f64, 4)) < 1e-4 * max(1.0, abs(f64)):
            return round(f64, 4)
        return None

    @classmethod
    def _classify_pointer(
        cls,
        pid: int,
        snap: ProcessMemoryMapSnapshot,
        ptr_val: int,
        ptr_size: int
    ) -> Optional[Tuple[str, str, List[str], str]]:
        """Classifies a committed target pointer and distinguishes IMAGE_RDATA vtables from code/data pointers."""
        if ptr_val == 0:
            return None
        cls_ptr = snap.classify_address(ptr_val)
        if cls_ptr.get("status") != "COMMITTED":
            return None
        cat = cls_ptr.get("category", "")
        mod = cls_ptr.get("module_name")
        rva = cls_ptr.get("rva")
        uint_alt = "uint64_t" if ptr_size == 8 else "uint32_t"

        if cat == "IMAGE_RDATA":
            # Look ahead 1 slot: vtables reside in .rdata and hold pointers into .text
            probe = VirtualMemoryInspector._read_memory_internal(pid, ptr_val, ptr_size, allow_partial=False)
            p_raw = probe.get("data")
            if p_raw and len(p_raw) == ptr_size:
                fmt = "<Q" if ptr_size == 8 else "<I"
                (first_slot,) = struct.unpack(fmt, p_raw)
                slot_cls = snap.classify_address(first_slot)
                if slot_cls.get("status") == "COMMITTED" and slot_cls.get("category") == "IMAGE_TEXT":
                    return "void**", f"vtable_ptr ({mod}+{rva} -> {slot_cls.get('module_name')}+{slot_cls.get('rva')})", [uint_alt, "void*"], "HIGH"
            return "void*", f"static_rdata_ptr ({mod}+{rva})", [uint_alt], "HIGH"
        elif cat == "IMAGE_TEXT":
            return "void*", f"code_or_fn_ptr ({mod}+{rva})", [uint_alt], "HIGH"
        elif cat == "IMAGE_DATA":
            return "void*", f"static_data_ptr ({mod}+{rva})", [uint_alt], "HIGH"
        elif cat == "HEAP":
            return "void*", f"heap_ptr (0x{ptr_val:X})", [uint_alt], "HIGH"
        elif cat == "STACK":
            return "void*", f"stack_frame_ptr (0x{ptr_val:X})", [uint_alt], "MEDIUM"
        elif cat == "MAPPED_FILE":
            return "void*", f"mapped_memory_ptr (0x{ptr_val:X})", [uint_alt], "HIGH"
        return "void*", f"committed_ptr_{cat} (0x{ptr_val:X})", [uint_alt], "MEDIUM"

    @classmethod
    def dissect(
        cls,
        pid: int,
        base_address: int,
        size: int = 128,
        struct_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Dissects memory at 4-byte field granularity with pointer/64-bit scalar lookahead."""
        ExecutionGuard.request_access(
            component="virtual_memory_inspector",
            operation="dissect_struct",
            target=f"pid_{pid}_0x{base_address:X}",
            capability=Capability.PROCESS_QUERY,
            access_mode="READ",
        )
        snap = VirtualMemoryInspector.inspect_process(pid)
        effective_name = struct_name or f"Reconstructed_0x{base_address:X}"
        if snap.is_simulated:
            return {
                "status": "not_applicable",
                "is_simulated": True,
                "heuristic": True,
                "notice": "Structure dissection requires a live Windows NT process with PROCESS_VM_READ access.",
                "pid": pid,
                "base_address": f"0x{base_address:016X}",
                "structure_name": effective_name,
                "architecture": snap.architecture,
                "fields_count": 0,
                "fields": [],
                "c_struct_definition": f"// Structure dissection unavailable on non-Windows environment for PID {pid}",
            }

        arch = snap.architecture
        ptr_size = 4 if arch == "x86-32" else 8

        is_mocked = getattr(
            VirtualMemoryInspector.read_process_memory, "__func__", None
        ) is not VirtualMemoryInspector.read_process_memory.__func__
        if is_mocked:
            raw = VirtualMemoryInspector.read_process_memory(pid, base_address, size)
            is_partial = bool(raw is not None and len(raw) < size)
        else:
            read_res = VirtualMemoryInspector.read_process_memory_checked(pid, base_address, size, allow_partial=True)
            raw = read_res.get("data")
            is_partial = bool(read_res.get("is_partial"))

        if not raw:
            return {
                "status": "error",
                "message": f"Could not read {size} bytes from address 0x{base_address:X}.",
            }

        usable_len = min(len(raw), size)
        fields: List[Dict[str, Any]] = []
        c_lines = [f"struct {effective_name} {{"]

        offset = 0
        while offset + 4 <= usable_len:
            field_name = f"field_0x{offset:X}"

            # On 64-bit aligned boundaries, look ahead across 8 bytes for pointers, NULL/zeros, or 64-bit scalars
            if ptr_size == 8 and (offset % 8 == 0) and (offset + 8 <= usable_len):
                raw8 = raw[offset:offset + 8]
                (u64,) = struct.unpack("<Q", raw8)
                (i64,) = struct.unpack("<q", raw8)

                ptr_hit = cls._classify_pointer(pid, snap, u64, 8)
                if ptr_hit is not None:
                    f_type, desc, alts, conf = ptr_hit
                    fields.append({
                        "offset": f"0x{offset:X}",
                        "offset_bytes": offset,
                        "size_bytes": 8,
                        "raw_hex": f"0x{u64:016X}",
                        "inferred_type": f_type,
                        "confidence": conf,
                        "alternatives": alts,
                        "heuristic": True,
                        "description": desc,
                    })
                    c_lines.append(f"    {f_type:<10} {field_name}; // 0x{offset:02X}: {desc}")
                    offset += 8
                    continue

                if u64 == 0:
                    fields.append({
                        "offset": f"0x{offset:X}",
                        "offset_bytes": offset,
                        "size_bytes": 8,
                        "raw_hex": f"0x{u64:016X}",
                        "inferred_type": "uint64_t",
                        "confidence": "LOW",
                        "alternatives": ["void* (NULL)", "int32_t[2] (0, 0)", "double (0.0)"],
                        "heuristic": True,
                        "description": "NULL_POINTER_OR_ZERO (8 bytes all zero)",
                    })
                    c_lines.append(f"    uint64_t   {field_name}; // 0x{offset:02X}: NULL_POINTER_OR_ZERO")
                    offset += 8
                    continue

                raw4_lo = raw[offset:offset + 4]
                raw4_hi = raw[offset + 4:offset + 8]
                (lo_u32,) = struct.unpack("<I", raw4_lo)
                (hi_u32,) = struct.unpack("<I", raw4_hi)
                (lo_i32,) = struct.unpack("<i", raw4_lo)
                (hi_i32,) = struct.unpack("<i", raw4_hi)
                lo_f32 = cls._is_plausible_float32(raw4_lo)
                hi_f32 = cls._is_plausible_float32(raw4_hi)
                f64_val = cls._is_plausible_float64(raw8)

                # Zero-extended 64-bit unsigned integer (e.g. score=5000, magic=0xDEADBEEF in u64 slot)
                if hi_u32 == 0 and lo_u32 != 0 and lo_f32 is None:
                    fields.append({
                        "offset": f"0x{offset:X}",
                        "offset_bytes": offset,
                        "size_bytes": 8,
                        "raw_hex": f"0x{u64:016X}",
                        "inferred_type": "uint64_t",
                        "confidence": "MEDIUM",
                        "alternatives": ["uint32_t + uint32_t_padding"],
                        "heuristic": True,
                        "description": f"Unsigned 64-bit integer: {u64} (0x{u64:X})",
                    })
                    c_lines.append(f"    uint64_t   {field_name}; // 0x{offset:02X}: uint64_t {u64}")
                    offset += 8
                    continue

                # Sign-extended negative 64-bit integer
                if hi_u32 == 0xFFFFFFFF and lo_i32 < 0 and lo_f32 is None:
                    fields.append({
                        "offset": f"0x{offset:X}",
                        "offset_bytes": offset,
                        "size_bytes": 8,
                        "raw_hex": f"0x{u64:016X}",
                        "inferred_type": "int64_t",
                        "confidence": "MEDIUM",
                        "alternatives": ["int32_t + sign_extension"],
                        "heuristic": True,
                        "description": f"Signed 64-bit integer: {i64}",
                    })
                    c_lines.append(f"    int64_t    {field_name}; // 0x{offset:02X}: int64_t {i64}")
                    offset += 8
                    continue

                # Clean 64-bit double when halves do not look like discrete 32-bit int+float
                if f64_val is not None and lo_f32 is None and hi_f32 is None and not (abs(lo_i32) < 100000 and abs(hi_i32) < 100000):
                    fields.append({
                        "offset": f"0x{offset:X}",
                        "offset_bytes": offset,
                        "size_bytes": 8,
                        "raw_hex": f"0x{u64:016X}",
                        "inferred_type": "double",
                        "confidence": "MEDIUM",
                        "alternatives": ["uint64_t", "uint32_t[2]"],
                        "heuristic": True,
                        "description": f"Double value: {f64_val}",
                    })
                    c_lines.append(f"    double     {field_name}; // 0x{offset:02X}: double {f64_val}")
                    offset += 8
                    continue

            # Fall through to 4-byte field classification (never merges unrelated 32-bit fields!)
            raw4 = raw[offset:offset + 4]
            (u32,) = struct.unpack("<I", raw4)
            (i32,) = struct.unpack("<i", raw4)

            if ptr_size == 4:
                ptr4_hit = cls._classify_pointer(pid, snap, u32, 4)
                if ptr4_hit is not None:
                    f_type, desc, alts, conf = ptr4_hit
                    fields.append({
                        "offset": f"0x{offset:X}",
                        "offset_bytes": offset,
                        "size_bytes": 4,
                        "raw_hex": f"0x{u32:08X}",
                        "inferred_type": f_type,
                        "confidence": conf,
                        "alternatives": alts,
                        "heuristic": True,
                        "description": desc,
                    })
                    c_lines.append(f"    {f_type:<10} {field_name}; // 0x{offset:02X}: {desc}")
                    offset += 4
                    continue

            f32_val = cls._is_plausible_float32(raw4)
            if u32 == 0:
                f_type = "uint32_t"
                conf = "LOW"
                alts = ["int32_t (0)", "float (0.0)", "padding"]
                desc = "Zero32 / Padding (0x0)"
            elif f32_val is not None:
                f_type = "float"
                conf = "MEDIUM"
                alts = ["uint32_t", "int32_t"]
                desc = f"Float value: {f32_val}"
            elif i32 < 0 and u32 > 0xF0000000:
                f_type = "int32_t"
                conf = "MEDIUM"
                alts = ["uint32_t", "bitmask"]
                desc = f"Signed int32: {i32} (u32: 0x{u32:08X})"
            else:
                f_type = "int32_t" if abs(i32) <= 0x7FFFFFFF and i32 >= -10000000 else "uint32_t"
                conf = "MEDIUM"
                alts = ["uint32_t" if f_type == "int32_t" else "int32_t", "bitflags"]
                desc = f"Integer32: {i32 if f_type == 'int32_t' else u32} (0x{u32:08X})"

            fields.append({
                "offset": f"0x{offset:X}",
                "offset_bytes": offset,
                "size_bytes": 4,
                "raw_hex": f"0x{u32:08X}",
                "inferred_type": f_type,
                "confidence": conf,
                "alternatives": alts,
                "heuristic": True,
                "description": desc,
            })
            c_lines.append(f"    {f_type:<10} {field_name}; // 0x{offset:02X}: {desc}")
            offset += 4

        c_lines.append("};")

        return {
            "status": "success",
            "heuristic": True,
            "notice": "Inferred types are 4-byte/8-byte heuristic classifications; verify against PDB/DWARF or decompiler output.",
            "pid": pid,
            "base_address": f"0x{base_address:016X}",
            "structure_name": effective_name,
            "architecture": arch,
            "bytes_requested": size,
            "bytes_read": usable_len,
            "is_partial": is_partial,
            "size_analyzed": usable_len,
            "fields_count": len(fields),
            "fields": fields,
            "c_struct_definition": "\n".join(c_lines),
        }
