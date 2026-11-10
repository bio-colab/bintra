# -*- coding: utf-8 -*-
"""
Process Module and In-Memory DLL Introspection Engine.
Enumerates loaded DLL modules within processes via Toolhelp32 module snapshots,
and identifies all running processes that have loaded a specific DLL into memory.
"""

import os
import ctypes
from ctypes import wintypes
from typing import Dict, Any, List, Optional
from .process_inventory import ProcessInventory


TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * 260)
    ]


class ModuleInventory:
    """
    Interrogates in-memory process modules to discover loaded dynamic libraries.
    Determines if a target DLL is actively hosted inside another program's address space.
    """

    @classmethod
    def _get_kernel32(cls):
        if os.name != "nt":
            return None
        k32 = ctypes.windll.kernel32
        k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]

        k32.Module32FirstW.restype = wintypes.BOOL
        k32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]

        k32.Module32NextW.restype = wintypes.BOOL
        k32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]

        k32.CloseHandle.restype = wintypes.BOOL
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        return k32

    @classmethod
    def get_modules_for_process(cls, pid: int, max_modules: int = 256) -> Dict[str, Any]:
        """
        Enumerates all modules (DLLs and main executable) loaded into the address space of a specific PID.
        Returns ACCESS_DENIED or PARTIAL_DATA cleanly if security protections prevent inspection.
        """
        k32 = cls._get_kernel32()
        if not k32:
            return {"status": "error", "pid": pid, "error": "Toolhelp32 unavailable on this platform."}

        flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
        h_snap = k32.CreateToolhelp32Snapshot(flags, pid)
        if not h_snap or h_snap == wintypes.HANDLE(-1).value:
            return {
                "status": "error",
                "pid": pid,
                "error": "ACCESS_DENIED (Unable to create module snapshot for process; insufficient privileges or PPL protection)."
            }

        modules = []
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32W)

        try:
            if k32.Module32FirstW(h_snap, ctypes.byref(entry)):
                while len(modules) < max_modules:
                    base_addr = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0
                    modules.append({
                        "module_name": entry.szModule,
                        "module_path": entry.szExePath,
                        "base_address": hex(base_addr),
                        "module_size": entry.modBaseSize,
                        "handle": hex(entry.hModule or 0)
                    })
                    if not k32.Module32NextW(h_snap, ctypes.byref(entry)):
                        break
        finally:
            k32.CloseHandle(h_snap)

        return {
            "status": "success",
            "pid": pid,
            "modules_count": len(modules),
            "modules": modules
        }

    @classmethod
    def find_processes_hosting_module(cls, module_name_or_path: str, max_processes_scanned: int = 128) -> Dict[str, Any]:
        """
        Scans running processes to identify which ones have loaded a specific DLL into memory.
        Solves the question: 'Is this DLL loaded inside another program?'
        """
        if os.name != "nt":
            return {
                "status": "not_applicable",
                "notice": "Windows Toolhelp32 process enumeration is unavailable on non-Windows NT platforms.",
                "query": module_name_or_path,
                "processes_scanned": 0,
                "access_denied_processes": 0,
                "hosting_processes_count": 0,
                "hosting_processes": []
            }

        norm_query = os.path.normpath(module_name_or_path).lower()
        query_basename = os.path.basename(norm_query)

        procs = ProcessInventory.enumerate_processes(resolve_paths=False, max_processes=max_processes_scanned)
        hosting_processes = []
        access_denied_count = 0

        for p in procs:
            pid = p["process_id"]
            if pid <= 4:
                continue

            res = cls.get_modules_for_process(pid, max_modules=128)
            if res.get("status") == "error":
                access_denied_count += 1
                continue

            for m in res.get("modules", []):
                m_path = m.get("module_path", "").lower()
                m_name = m.get("module_name", "").lower()

                matched = False
                if norm_query in m_path:
                    matched = True
                elif m_name == query_basename:
                    matched = True

                if matched:
                    hosting_processes.append({
                        "process_id": pid,
                        "executable_name": p.get("executable_name"),
                        "matched_module": m
                    })
                    break

        status = "access_denied" if (len(procs) > 0 and access_denied_count == len(procs)) else (
            "partial_success" if access_denied_count > 0 else "success"
        )
        return {
            "status": status,
            "query": module_name_or_path,
            "processes_scanned": len(procs),
            "access_denied_processes": access_denied_count,
            "hosting_processes_count": len(hosting_processes),
            "hosting_processes": hosting_processes
        }
