# -*- coding: utf-8 -*-
"""
Process Mitigation, Token, and Memory Introspection Engine.
Interrogates Windows process mitigation policies (DEP, ASLR, CFG), security token
integrity levels, and virtual memory counters using kernel32 and advapi32 APIs.
"""

import os
import ctypes
from ctypes import wintypes
from typing import Dict, Any, List, Optional


class PROCESS_MITIGATION_DEP_POLICY(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Permanent", wintypes.BOOLEAN)
    ]


class PROCESS_MITIGATION_ASLR_POLICY(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD)
    ]


class PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD)
    ]


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [
        ("Label_Sid", ctypes.c_void_p),
        ("Label_Attributes", wintypes.DWORD),
    ]


class ProcessMitigationInspector:
    """
    Directly evaluates active Windows exploit mitigations (DEP, ASLR, CFG),
    token integrity levels, and memory quotas on running processes.
    """

    INTEGRITY_LEVEL_MAP = {
        0x0000: "Untrusted",
        0x1000: "Low (Sandbox / AppContainer)",
        0x2000: "Medium (Standard User)",
        0x3000: "High (Elevated Administrator)",
        0x4000: "System (SYSTEM / Kernel Host)",
        0x5000: "Protected Process (PPL)"
    }

    @classmethod
    def inspect_process(cls, process_handle: Optional[int] = None, pid: Optional[int] = None) -> Dict[str, Any]:
        """
        Inspects process security mitigations (DEP, ASLR, CFG),
        token integrity level, and memory usage.
        Defaults to inspecting the current process if both process_handle and pid are omitted.
        """
        if os.name != "nt":
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "Process mitigation inspection requires Windows NT."
            }

        kernel32 = ctypes.windll.kernel32
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p

        opened_handle = False
        target_pid = pid or os.getpid()

        if process_handle is not None:
            handle = process_handle
            is_current = False
        elif pid is not None and pid != os.getpid():
            PROCESS_QUERY_INFORMATION = 0x0400
            PROCESS_VM_READ = 0x0010
            kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel32.OpenProcess.restype = ctypes.c_void_p
            handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if not handle:
                return {
                    "status": "error",
                    "error": f"Failed to open process PID {pid} (Access Denied or Invalid PID)",
                    "pid": pid,
                    "is_current_process": False
                }
            opened_handle = True
            is_current = False
        else:
            handle = kernel32.GetCurrentProcess()
            target_pid = os.getpid()
            is_current = True

        try:
            # 1. Mitigation Policies
            mitigations = {}
            if hasattr(kernel32, "GetProcessMitigationPolicy"):
                kernel32.GetProcessMitigationPolicy.restype = wintypes.BOOL
                kernel32.GetProcessMitigationPolicy.argtypes = [
                    ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t
                ]

                # Policy 0: ProcessDEPPolicy
                dep_pol = PROCESS_MITIGATION_DEP_POLICY()
                if kernel32.GetProcessMitigationPolicy(handle, 0, ctypes.byref(dep_pol), ctypes.sizeof(dep_pol)):
                    mitigations["dep"] = {
                        "enabled": bool(dep_pol.Flags & 0x1),
                        "disable_atl_thunk_emulation": bool(dep_pol.Flags & 0x2),
                        "permanent": bool(dep_pol.Permanent),
                        "raw_flags": hex(dep_pol.Flags)
                    }

                # Policy 1: ProcessASLRPolicy
                aslr_pol = PROCESS_MITIGATION_ASLR_POLICY()
                if kernel32.GetProcessMitigationPolicy(handle, 1, ctypes.byref(aslr_pol), ctypes.sizeof(aslr_pol)):
                    mitigations["aslr"] = {
                        "bottom_up_randomization": bool(aslr_pol.Flags & 0x1),
                        "force_relocate_images": bool(aslr_pol.Flags & 0x2),
                        "high_entropy": bool(aslr_pol.Flags & 0x4),
                        "raw_flags": hex(aslr_pol.Flags)
                    }

                # Policy 4: ProcessControlFlowGuardPolicy
                cfg_pol = PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY()
                if kernel32.GetProcessMitigationPolicy(handle, 4, ctypes.byref(cfg_pol), ctypes.sizeof(cfg_pol)):
                    mitigations["cfg"] = {
                        "enabled": bool(cfg_pol.Flags & 0x1),
                        "export_suppression": bool(cfg_pol.Flags & 0x2),
                        "strict_mode": bool(cfg_pol.Flags & 0x4),
                        "raw_flags": hex(cfg_pol.Flags)
                    }

            # 2. Token Integrity Level
            integrity_info = cls._get_token_integrity(handle)

            # 3. Process Memory Counters
            memory_info = cls._get_process_memory(handle)

            return {
                "status": "success",
                "pid": target_pid,
                "is_current_process": is_current,
                "mitigations": mitigations,
                "security_token": integrity_info,
                "memory": memory_info
            }
        finally:
            if opened_handle and handle:
                kernel32.CloseHandle(handle)

    @classmethod
    def _get_token_integrity(cls, process_handle: int) -> Dict[str, Any]:
        """Queries process security token integrity level."""
        try:
            advapi32 = ctypes.windll.advapi32
            kernel32 = ctypes.windll.kernel32

            advapi32.OpenProcessToken.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
            advapi32.OpenProcessToken.restype = wintypes.BOOL

            token_handle = wintypes.HANDLE()
            TOKEN_QUERY = 0x0008
            if not advapi32.OpenProcessToken(process_handle, TOKEN_QUERY, ctypes.byref(token_handle)):
                return {"integrity_level": "Unknown", "error": "OpenProcessToken failed"}

            TokenIntegrityLevel = 25
            req_len = wintypes.DWORD()
            advapi32.GetTokenInformation(token_handle, TokenIntegrityLevel, None, 0, ctypes.byref(req_len))

            if req_len.value <= 0:
                kernel32.CloseHandle(token_handle)
                return {"integrity_level": "Unknown"}

            buf = ctypes.create_string_buffer(req_len.value)
            if not advapi32.GetTokenInformation(token_handle, TokenIntegrityLevel, buf, req_len.value, ctypes.byref(req_len)):
                kernel32.CloseHandle(token_handle)
                return {"integrity_level": "Unknown"}

            tml = TOKEN_MANDATORY_LABEL.from_buffer_copy(buf)
            sid_ptr = tml.Label_Sid

            advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
            advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
            advapi32.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
            advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)

            count_ptr = advapi32.GetSidSubAuthorityCount(sid_ptr)
            if not count_ptr or count_ptr.contents.value <= 0:
                kernel32.CloseHandle(token_handle)
                return {"integrity_level": "Unknown"}

            sub_auth_idx = count_ptr.contents.value - 1
            rid_ptr = advapi32.GetSidSubAuthority(sid_ptr, sub_auth_idx)
            rid = rid_ptr.contents.value if rid_ptr else 0

            kernel32.CloseHandle(token_handle)
            name = cls.INTEGRITY_LEVEL_MAP.get(rid, f"Custom_RID_{hex(rid)}")
            return {
                "integrity_level": name,
                "integrity_rid": hex(rid),
                "is_elevated_admin": (rid >= 0x3000)
            }
        except Exception as e:
            return {"integrity_level": "Unknown", "error": str(e)}

    @classmethod
    def _get_process_memory(cls, process_handle: int) -> Dict[str, Any]:
        """Queries process working set and memory counters via PSAPI."""
        try:
            psapi = getattr(ctypes.windll, "psapi", ctypes.windll.kernel32)
            psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
            psapi.GetProcessMemoryInfo.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), wintypes.DWORD
            ]

            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            if psapi.GetProcessMemoryInfo(process_handle, ctypes.byref(counters), counters.cb):
                return {
                    "working_set_bytes": counters.WorkingSetSize,
                    "working_set_mb": round(counters.WorkingSetSize / (1024 * 1024), 2),
                    "peak_working_set_mb": round(counters.PeakWorkingSetSize / (1024 * 1024), 2),
                    "pagefile_usage_mb": round(counters.PagefileUsage / (1024 * 1024), 2)
                }
        except Exception:
            pass
        return {}
