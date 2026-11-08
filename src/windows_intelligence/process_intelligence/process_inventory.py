# -*- coding: utf-8 -*-
"""
Process Inventory and Hierarchy Analysis Engine.
Enumerates active Windows processes, resolves authoritative image paths via QueryFullProcessImageNameW,
constructs parent-child process execution trees, and identifies running instances of target executables.
"""

import os
import ctypes
from ctypes import wintypes
from typing import Dict, Any, List, Optional


TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260)
    ]


class ProcessInventory:
    """
    Interrogates the Windows kernel process table via Toolhelp32 and Process APIs.
    Discovers running process instances, resolves image paths, and models parent-child topologies.
    """

    @classmethod
    def _get_kernel32(cls):
        if os.name != "nt":
            return None
        k32 = ctypes.windll.kernel32
        k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]

        k32.Process32FirstW.restype = wintypes.BOOL
        k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]

        k32.Process32NextW.restype = wintypes.BOOL
        k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]

        k32.OpenProcess.restype = wintypes.HANDLE
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

        if hasattr(k32, "QueryFullProcessImageNameW"):
            k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
            k32.QueryFullProcessImageNameW.argtypes = [
                wintypes.HANDLE, wintypes.DWORD, ctypes.c_wchar_p, ctypes.POINTER(wintypes.DWORD)
            ]

        k32.CloseHandle.restype = wintypes.BOOL
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        return k32

    @classmethod
    def get_process_image_path(cls, pid: int) -> Optional[str]:
        """Resolves the authoritative full image path on disk for a given PID."""
        k32 = cls._get_kernel32()
        if not k32 or not hasattr(k32, "QueryFullProcessImageNameW"):
            return None

        h_proc = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h_proc:
            return None

        try:
            buf = (ctypes.c_wchar * 1024)()
            size = wintypes.DWORD(len(buf))
            if k32.QueryFullProcessImageNameW(h_proc, 0, buf, ctypes.byref(size)):
                return buf.value
            return None
        finally:
            k32.CloseHandle(h_proc)

    @classmethod
    def enumerate_processes(cls, resolve_paths: bool = True, max_processes: int = 512) -> List[Dict[str, Any]]:
        """Enumerates active processes with PIDs, Parent PIDs, thread counts, and image paths."""
        k32 = cls._get_kernel32()
        if not k32:
            return []

        h_snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not h_snap or h_snap == wintypes.HANDLE(-1).value:
            return []

        processes = []
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

        try:
            if k32.Process32FirstW(h_snap, ctypes.byref(entry)):
                while len(processes) < max_processes:
                    pid = entry.th32ProcessID
                    ppid = entry.th32ParentProcessID
                    exe_name = entry.szExeFile
                    threads = entry.cntThreads

                    image_path = cls.get_process_image_path(pid) if resolve_paths and pid > 4 else None

                    processes.append({
                        "process_id": pid,
                        "parent_process_id": ppid,
                        "executable_name": exe_name,
                        "image_path": image_path,
                        "thread_count": threads
                    })

                    if not k32.Process32NextW(h_snap, ctypes.byref(entry)):
                        break
        finally:
            k32.CloseHandle(h_snap)

        return processes

    @classmethod
    def get_process_tree(cls) -> Dict[str, Any]:
        """Builds a hierarchical parent-child process tree."""
        procs = cls.enumerate_processes(resolve_paths=False)
        proc_map = {p["process_id"]: p for p in procs}
        children_map: Dict[int, List[Dict[str, Any]]] = {}

        for p in procs:
            ppid = p["parent_process_id"]
            pid = p["process_id"]
            if ppid == pid:
                continue
            if ppid not in children_map:
                children_map[ppid] = []
            children_map[ppid].append(p)

        # Roots are processes whose parent is not in proc_map or is PID 0 (excluding PID 0 itself as child)
        roots = [p for p in procs if p["parent_process_id"] == 0 or p["parent_process_id"] not in proc_map]

        def _build_subtree(proc, visited=None):
            if visited is None:
                visited = set()
            pid = proc["process_id"]
            node = dict(proc)
            if pid in visited:
                return node
            visited.add(pid)
            childs = [c for c in children_map.get(pid, []) if c["process_id"] != pid and c["process_id"] not in visited]
            if childs:
                node["children"] = [_build_subtree(c, visited.copy()) for c in childs]
            return node

        tree = [_build_subtree(r) for r in roots]
        return {
            "total_processes": len(procs),
            "root_processes_count": len(roots),
            "process_tree": tree
        }

    @classmethod
    def find_processes_by_file(cls, file_path_or_name: str) -> List[Dict[str, Any]]:
        """
        Determines if a target executable is currently running as an active process.
        Matches against both full image path and executable name.
        """
        norm_target = os.path.normpath(file_path_or_name).lower()
        target_basename = os.path.basename(norm_target)

        matches = []
        for p in cls.enumerate_processes(resolve_paths=True):
            img_p = p.get("image_path")
            exe_n = p.get("executable_name", "").lower()

            matched = False
            confidence = "UNVERIFIED"
            if img_p and os.path.normpath(img_p).lower() == norm_target:
                matched = True
                confidence = "EXACT_PATH_MATCH"
            elif exe_n == target_basename:
                matched = True
                confidence = "BASENAME_FALLBACK_UNVERIFIED_PATH"

            if matched:
                item = dict(p)
                item["match_confidence"] = confidence
                matches.append(item)

        return matches
