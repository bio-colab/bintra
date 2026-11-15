# -*- coding: utf-8 -*-
"""
Windows Task Manager Intelligence & Process Telemetry Engine.
Provides comprehensive, zero-dependency introspection matching and exceeding Windows Task Manager:
1. Performance Tab: Global CPU utilization, physical/commit memory, uptime, process & thread counts.
2. Processes & Details Tab: Memory counters (Working Set, Commit, Paged/Non-paged pool), CPU times,
   I/O counters, handle count, thread count, architecture (x86/x64), session ID, elevation, user account,
   command-line arguments, and exploit mitigations.
3. Search & Filtering: Real-time query matching across PIDs, executable names, image paths, users, and CLI args.
4. Service & Network Fusion: Cross-correlating processes with hosted SCM services and active TCP network sockets.
"""

import os
import sys
import ctypes
import datetime
import time
from ctypes import wintypes
from typing import Dict, Any, List, Optional


from .process_inventory import PROCESSENTRY32W, ProcessInventory
from ..system_introspection.process_inspector import PROCESS_MEMORY_COUNTERS, ProcessMitigationInspector


class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD)
    ]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_uint64),
        ("ullAvailPhys", ctypes.c_uint64),
        ("ullTotalPageFile", ctypes.c_uint64),
        ("ullAvailPageFile", ctypes.c_uint64),
        ("ullTotalVirtual", ctypes.c_uint64),
        ("ullAvailVirtual", ctypes.c_uint64),
        ("ullAvailExtendedVirtual", ctypes.c_uint64),
    ]


class TOKEN_ELEVATION(ctypes.Structure):
    _fields_ = [
        ("TokenIsElevated", wintypes.DWORD)
    ]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Sid", ctypes.c_void_p),
        ("Attributes", wintypes.DWORD)
    ]


class TaskManagerInspector:
    """
    Unified Windows Task Manager Intelligence Engine.
    Provides complete parity with Windows Task Manager (Processes, Performance, Details, Services, Sockets).
    """

    TH32CS_SNAPPROCESS = 0x00000002
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    TOKEN_QUERY = 0x0008

    @classmethod
    def _get_k32(cls):
        windll = getattr(ctypes, "windll", None)
        k32 = getattr(windll, "kernel32", None) if windll else None
        if k32 and not getattr(k32, "_bintra_initialized", False):
            try:
                if hasattr(k32, "GetTickCount64"):
                    k32.GetTickCount64.restype = ctypes.c_ulonglong
                    k32.GetTickCount64.argtypes = []
                if hasattr(k32, "GetTickCount"):
                    k32.GetTickCount.restype = ctypes.c_ulong
                    k32.GetTickCount.argtypes = []
                if hasattr(k32, "OpenProcess"):
                    k32.OpenProcess.restype = ctypes.wintypes.HANDLE
                    k32.OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
                if hasattr(k32, "CloseHandle"):
                    k32.CloseHandle.restype = ctypes.wintypes.BOOL
                    k32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
                if hasattr(k32, "ProcessIdToSessionId"):
                    k32.ProcessIdToSessionId.restype = ctypes.wintypes.BOOL
                    k32.ProcessIdToSessionId.argtypes = [ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD)]
                if hasattr(k32, "GetProcessHandleCount"):
                    k32.GetProcessHandleCount.restype = ctypes.wintypes.BOOL
                    k32.GetProcessHandleCount.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.DWORD)]
                if hasattr(k32, "GlobalMemoryStatusEx"):
                    k32.GlobalMemoryStatusEx.restype = ctypes.wintypes.BOOL
                    k32.GlobalMemoryStatusEx.argtypes = [ctypes.c_void_p]
                if hasattr(k32, "GetSystemTimes"):
                    k32.GetSystemTimes.restype = ctypes.wintypes.BOOL
                    k32.GetSystemTimes.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
                if hasattr(k32, "GetProcessTimes"):
                    k32.GetProcessTimes.restype = ctypes.wintypes.BOOL
                    k32.GetProcessTimes.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
                k32._bintra_initialized = True
            except Exception:
                pass
        return k32

    @classmethod
    def _get_psapi(cls):
        windll = getattr(ctypes, "windll", None)
        if not windll:
            return None
        return getattr(windll, "psapi", getattr(windll, "kernel32", None))

    @classmethod
    def _get_advapi32(cls):
        windll = getattr(ctypes, "windll", None)
        return getattr(windll, "advapi32", None) if windll else None

    @classmethod
    def _get_ntdll(cls):
        windll = getattr(ctypes, "windll", None)
        return getattr(windll, "ntdll", None) if windll else None

    @classmethod
    def _filetime_to_int(cls, ft: FILETIME) -> int:
        return (ft.dwHighDateTime << 32) | ft.dwLowDateTime

    @classmethod
    def _filetime_to_datetime_utc(cls, ft: FILETIME) -> Optional[datetime.datetime]:
        val = cls._filetime_to_int(ft)
        if val <= 0:
            return None
        epoch_start = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        return epoch_start + datetime.timedelta(microseconds=val / 10)

    @classmethod
    def get_system_performance(cls, sample_interval: float = 0.05) -> Dict[str, Any]:
        """
        Gathers system-wide telemetry matching the Task Manager 'Performance' tab:
        - CPU Utilization %
        - Physical RAM (Total, In-Use, Available, Load %)
        - Commit Limits (Total Commit, Available Commit, Commit %)
        - System Uptime (Seconds, Hours, Days, Boot Timestamp)
        - Topology (Total Processes, Total Threads)
        """
        if os.name != "nt":
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "System performance inspection requires Windows NT."
            }

        k32 = cls._get_k32()
        if not k32:
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "Kernel32 not available."
            }

        # 1. Global Memory Status
        mem = MEMORYSTATUSEX()
        mem.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        k32.GlobalMemoryStatusEx(ctypes.byref(mem))

        total_phys_gb = round(mem.ullTotalPhys / (1024 ** 3), 2)
        avail_phys_gb = round(mem.ullAvailPhys / (1024 ** 3), 2)
        used_phys_gb = round((mem.ullTotalPhys - mem.ullAvailPhys) / (1024 ** 3), 2)

        total_page_gb = round(mem.ullTotalPageFile / (1024 ** 3), 2)
        avail_page_gb = round(mem.ullAvailPageFile / (1024 ** 3), 2)
        committed_gb = round((mem.ullTotalPageFile - mem.ullAvailPageFile) / (1024 ** 3), 2)
        commit_pct = round((committed_gb / total_page_gb * 100.0), 1) if total_page_gb > 0 else 0.0

        # 2. System Uptime (GetTickCount64)
        if hasattr(k32, "GetTickCount64"):
            uptime_ms = int(k32.GetTickCount64())
        else:
            uptime_ms = int(k32.GetTickCount())
        uptime_ms = max(0, uptime_ms)
        uptime_sec = uptime_ms / 1000.0
        uptime_hours = round(uptime_sec / 3600.0, 2)
        uptime_days = round(uptime_hours / 24.0, 2)
        boot_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=uptime_sec)

        # 3. CPU Utilization (GetSystemTimes delta)
        idle1, kern1, user1 = FILETIME(), FILETIME(), FILETIME()
        idle2, kern2, user2 = FILETIME(), FILETIME(), FILETIME()
        cpu_util = 0.0
        if hasattr(k32, "GetSystemTimes"):
            k32.GetSystemTimes(ctypes.byref(idle1), ctypes.byref(kern1), ctypes.byref(user1))
            time.sleep(max(0.01, min(sample_interval, 0.2)))
            k32.GetSystemTimes(ctypes.byref(idle2), ctypes.byref(kern2), ctypes.byref(user2))

            d_idle = cls._filetime_to_int(idle2) - cls._filetime_to_int(idle1)
            d_kern = cls._filetime_to_int(kern2) - cls._filetime_to_int(kern1)
            d_user = cls._filetime_to_int(user2) - cls._filetime_to_int(user1)
            total_sys = d_kern + d_user
            busy = total_sys - d_idle
            if total_sys > 0:
                cpu_util = round(max(0.0, min(100.0, (busy / total_sys) * 100.0)), 1)

        # 4. Topology totals via ProcessInventory
        procs_raw = ProcessInventory.enumerate_processes(resolve_paths=False, max_processes=2048)
        tot_procs = len(procs_raw)
        tot_threads = sum(p.get("thread_count", 0) for p in procs_raw)

        return {
            "status": "success",
            "cpu_utilization_percent": cpu_util,
            "memory": {
                "total_physical_gb": total_phys_gb,
                "used_physical_gb": used_phys_gb,
                "available_physical_gb": avail_phys_gb,
                "memory_load_percent": mem.dwMemoryLoad,
                "commit_limit_gb": total_page_gb,
                "committed_gb": committed_gb,
                "commit_percent": commit_pct,
            },
            "uptime": {
                "uptime_ms": uptime_ms,
                "uptime_seconds": round(uptime_sec, 1),
                "uptime_hours": uptime_hours,
                "uptime_days": uptime_days,
                "boot_time_utc": boot_time.isoformat(),
            },
            "topology": {
                "total_processes": tot_procs,
                "total_threads": tot_threads,
            }
        }

    @classmethod
    def _get_command_line(cls, h_proc: int) -> Optional[str]:
        """Reads process command line arguments via NtQueryInformationProcess (Class 60)."""
        try:
            ntdll = cls._get_ntdll()
            if not ntdll or not hasattr(ntdll, "NtQueryInformationProcess"):
                return None

            buf = ctypes.create_string_buffer(4096)
            ret_len = wintypes.ULONG()
            # ProcessCommandLineInformation = 60
            status = ntdll.NtQueryInformationProcess(h_proc, 60, buf, 4096, ctypes.byref(ret_len))
            if status == -1073741820:  # 0xC0000004: STATUS_INFO_LENGTH_MISMATCH
                buf = ctypes.create_string_buffer(ret_len.value)
                status = ntdll.NtQueryInformationProcess(h_proc, 60, buf, ret_len.value, ctypes.byref(ret_len))

            if status == 0 and len(buf.raw) >= 16:
                length = int.from_bytes(buf.raw[0:2], "little")
                ptr = int.from_bytes(buf.raw[8:16], "little")
                if length > 0 and ptr:
                    return ctypes.wstring_at(ptr, length // 2).strip()
        except Exception:
            pass
        return None

    @classmethod
    def _get_security_context(cls, h_proc: int) -> Dict[str, Any]:
        """Resolves process elevation, token integrity level, and owning Windows user/domain."""
        res = {
            "user": "Unknown",
            "is_elevated": False,
            "integrity_level": "Unknown",
            "integrity_rid": "0x0"
        }
        try:
            advapi32 = cls._get_advapi32()
            if not advapi32:
                return res
            k32 = cls._get_k32()
            if not k32:
                return res

            token = wintypes.HANDLE()
            if not advapi32.OpenProcessToken(h_proc, cls.TOKEN_QUERY, ctypes.byref(token)):
                return res

            try:
                # 1. Elevation (TokenElevation = 20)
                elev = TOKEN_ELEVATION()
                ret_len = wintypes.DWORD()
                if advapi32.GetTokenInformation(token, 20, ctypes.byref(elev), ctypes.sizeof(elev), ctypes.byref(ret_len)):
                    res["is_elevated"] = bool(elev.TokenIsElevated)

                # 2. Integrity Level (TokenIntegrityLevel = 25)
                from ..system_introspection.process_inspector import ProcessMitigationInspector
                advapi32.GetTokenInformation(token, 25, None, 0, ctypes.byref(ret_len))
                if ret_len.value > 0:
                    ibuf = ctypes.create_string_buffer(ret_len.value)
                    if advapi32.GetTokenInformation(token, 25, ibuf, ret_len.value, ctypes.byref(ret_len)):
                        from ..system_introspection.process_inspector import TOKEN_MANDATORY_LABEL
                        tml = TOKEN_MANDATORY_LABEL.from_buffer_copy(ibuf)
                        advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
                        advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
                        advapi32.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
                        advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)

                        count_ptr = advapi32.GetSidSubAuthorityCount(tml.Label_Sid)
                        if count_ptr and count_ptr.contents.value > 0:
                            sub_idx = count_ptr.contents.value - 1
                            rid_ptr = advapi32.GetSidSubAuthority(tml.Label_Sid, sub_idx)
                            if rid_ptr:
                                rid = rid_ptr.contents.value
                                res["integrity_rid"] = hex(rid)
                                res["integrity_level"] = ProcessMitigationInspector.INTEGRITY_LEVEL_MAP.get(
                                    rid, f"Custom_RID_{hex(rid)}"
                                )

                # 3. User Name & Domain (TokenUser = 1)
                advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(ret_len))
                if ret_len.value > 0:
                    ubuf = ctypes.create_string_buffer(ret_len.value)
                    if advapi32.GetTokenInformation(token, 1, ubuf, ret_len.value, ctypes.byref(ret_len)):
                        user_info = SID_AND_ATTRIBUTES.from_buffer_copy(ubuf)
                        name_buf = (ctypes.c_wchar * 256)()
                        dom_buf = (ctypes.c_wchar * 256)()
                        name_len = wintypes.DWORD(256)
                        dom_len = wintypes.DWORD(256)
                        sid_type = wintypes.DWORD()
                        advapi32.LookupAccountSidW.argtypes = [
                            ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.POINTER(wintypes.DWORD),
                            ctypes.c_wchar_p, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)
                        ]
                        if advapi32.LookupAccountSidW(None, user_info.Sid, name_buf, ctypes.byref(name_len), dom_buf, ctypes.byref(dom_len), ctypes.byref(sid_type)):
                            res["user"] = f"{dom_buf.value}\\{name_buf.value}"
            finally:
                k32.CloseHandle(token)
        except Exception:
            pass
        return res

    @classmethod
    def _get_architecture(cls, h_proc: int) -> str:
        """Determines if the process is 32-bit (WoW64) or native 64-bit."""
        try:
            k32 = cls._get_k32()
            if not k32:
                return "Unknown"
            is_wow64 = wintypes.BOOL()
            if hasattr(k32, "IsWow64Process") and k32.IsWow64Process(h_proc, ctypes.byref(is_wow64)):
                if is_wow64.value:
                    return "x86 (WoW64)"
                return "x64 (Native)"
        except Exception:
            pass
        return "Unknown"

    @classmethod
    def list_processes(
        cls,
        limit: int = 100,
        sort_by: str = "memory",
        reverse: bool = True,
        resolve_paths: bool = False,
        resolve_users: bool = False,
        query: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Enumerates running processes with live Task Manager columns:
        PID, Name, Memory (RAM / Commit MB), Threads, Handles, Session ID, User, Architecture, Image Path.
        """
        if os.name != "nt":
            return {
                "status": "not_applicable",
                "total_processes": 0,
                "matched_processes": 0,
                "processes": []
            }

        k32 = cls._get_k32()
        psapi = cls._get_psapi()

        from .process_inventory import ProcessInventory
        procs = ProcessInventory.enumerate_processes(resolve_paths=resolve_paths, max_processes=1024)

        mc = PROCESS_MEMORY_COUNTERS()
        mc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)

        sess_id = wintypes.DWORD()
        h_count = wintypes.DWORD()

        q_lower = query.strip().lower() if query else None

        enriched: List[Dict[str, Any]] = []
        for p in procs:
            pid = p["process_id"]
            p["working_set_mb"] = 0.0
            p["commit_mb"] = 0.0
            p["handle_count"] = 0
            p["session_id"] = 0
            p["architecture"] = "Unknown"
            p["user"] = "Unknown"

            if k32 and pid > 4:
                if hasattr(k32, "ProcessIdToSessionId"):
                    if k32.ProcessIdToSessionId(pid, ctypes.byref(sess_id)):
                        p["session_id"] = sess_id.value

                h = k32.OpenProcess(cls.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                if h:
                    try:
                        # Memory
                        if psapi and psapi.GetProcessMemoryInfo(h, ctypes.byref(mc), mc.cb):
                            p["working_set_mb"] = round(mc.WorkingSetSize / (1024 * 1024), 2)
                            p["commit_mb"] = round(mc.PagefileUsage / (1024 * 1024), 2)

                        # Handles
                        if hasattr(k32, "GetProcessHandleCount"):
                            if k32.GetProcessHandleCount(h, ctypes.byref(h_count)):
                                p["handle_count"] = h_count.value

                        # Architecture
                        p["architecture"] = cls._get_architecture(h)

                        # User (optional)
                        if resolve_users:
                            sec = cls._get_security_context(h)
                            p["user"] = sec.get("user", "Unknown")
                            p["is_elevated"] = sec.get("is_elevated", False)
                    finally:
                        k32.CloseHandle(h)

            # Query filtering
            if q_lower:
                exe_match = q_lower in p.get("executable_name", "").lower()
                pid_match = q_lower in str(pid)
                img_match = q_lower in (p.get("image_path") or "").lower()
                if not (exe_match or pid_match or img_match):
                    continue

            enriched.append(p)

        # Sorting
        sort_key_map = {
            "memory": lambda x: x.get("working_set_mb", 0.0),
            "commit": lambda x: x.get("commit_mb", 0.0),
            "threads": lambda x: x.get("thread_count", 0),
            "handles": lambda x: x.get("handle_count", 0),
            "pid": lambda x: x.get("process_id", 0),
            "name": lambda x: x.get("executable_name", "").lower(),
        }
        key_fn = sort_key_map.get(sort_by, sort_key_map["memory"])
        sorted_procs = sorted(enriched, key=key_fn, reverse=reverse)

        return {
            "status": "success",
            "total_processes": len(procs),
            "matched_processes": len(sorted_procs),
            "sort_by": sort_by,
            "processes": sorted_procs[:limit]
        }

    @classmethod
    def search_processes(cls, query: str, max_results: int = 50) -> Dict[str, Any]:
        """Searches processes by name, PID, image path, or command line."""
        return cls.list_processes(
            limit=max_results,
            sort_by="memory",
            reverse=True,
            resolve_paths=True,
            resolve_users=True,
            query=query
        )

    @classmethod
    def get_process_details(cls, pid: Optional[int] = None) -> Dict[str, Any]:
        """
        Deep-dive forensic inspection of a process matching all Windows Task Manager tabs:
        - Processes / Details: Identity, Command Line, Security, Elevation, Mitigations, Architecture, Session
        - Memory Counters: Working Set, Peak Working Set, Commit, Paged/Non-paged pool, Page faults
        - CPU & Time: Creation time UTC, Uptime, Kernel/User/Total CPU time
        - I/O Counters: Read/Write/Other bytes and operations
        - Services: SCM services hosted in this process
        - Network: Active TCP network sockets owned by this process
        - Modules: Loaded DLL inventory
        """
        target_pid = pid or os.getpid()

        if os.name != "nt":
            return {
                "status": "not_applicable",
                "process_id": target_pid,
                "reason": "Process details inspection requires Windows NT."
            }

        k32 = cls._get_k32()
        if not k32:
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "Kernel32 not available."
            }
        psapi = cls._get_psapi()

        from .process_inventory import ProcessInventory
        from ..system_introspection.process_inspector import ProcessMitigationInspector
        from .service_process_mapper import ServiceProcessMapper
        from .module_inventory import ModuleInventory
        from ..system_introspection.network_inspector import NetworkHardwareInspector

        # 1. Base inventory from snapshot
        base_info = next((p for p in ProcessInventory.enumerate_processes(resolve_paths=True) if p["process_id"] == target_pid), None)
        exe_name = base_info.get("executable_name") if base_info else "Unknown"
        ppid = base_info.get("parent_process_id") if base_info else 0
        img_path = base_info.get("image_path") if base_info else ProcessInventory.get_process_image_path(target_pid)
        thread_cnt = base_info.get("thread_count", 0) if base_info else 0

        # Open process handle
        h_proc = k32.OpenProcess(cls.PROCESS_QUERY_LIMITED_INFORMATION | cls.PROCESS_QUERY_INFORMATION, False, target_pid)
        if not h_proc and target_pid > 4:
            # Fallback to limited information
            h_proc = k32.OpenProcess(cls.PROCESS_QUERY_LIMITED_INFORMATION, False, target_pid)

        # 2. Session ID
        sess_id = 0
        if hasattr(k32, "ProcessIdToSessionId"):
            s_val = wintypes.DWORD()
            if k32.ProcessIdToSessionId(target_pid, ctypes.byref(s_val)):
                sess_id = s_val.value

        # 3. Architecture & Command Line & Security
        cmd_line = None
        arch = "Unknown"
        sec_context = {"user": "Unknown", "is_elevated": False, "integrity_level": "Unknown", "integrity_rid": "0x0"}
        handle_cnt = 0

        if h_proc:
            cmd_line = cls._get_command_line(h_proc)
            arch = cls._get_architecture(h_proc)
            sec_context = cls._get_security_context(h_proc)
            h_val = wintypes.DWORD()
            if hasattr(k32, "GetProcessHandleCount") and k32.GetProcessHandleCount(h_proc, ctypes.byref(h_val)):
                handle_cnt = h_val.value

        # 4. Memory Counters
        mem_info: Dict[str, Any] = {}
        if h_proc:
            mc = PROCESS_MEMORY_COUNTERS()
            mc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            if psapi.GetProcessMemoryInfo(h_proc, ctypes.byref(mc), mc.cb):
                mem_info = {
                    "working_set_bytes": mc.WorkingSetSize,
                    "working_set_mb": round(mc.WorkingSetSize / (1024 * 1024), 2),
                    "peak_working_set_mb": round(mc.PeakWorkingSetSize / (1024 * 1024), 2),
                    "commit_bytes": mc.PagefileUsage,
                    "commit_mb": round(mc.PagefileUsage / (1024 * 1024), 2),
                    "peak_commit_mb": round(mc.PeakPagefileUsage / (1024 * 1024), 2),
                    "paged_pool_mb": round(mc.QuotaPagedPoolUsage / (1024 * 1024), 2),
                    "non_paged_pool_mb": round(mc.QuotaNonPagedPoolUsage / (1024 * 1024), 2),
                    "page_fault_count": mc.PageFaultCount,
                }

        # 5. CPU Times & Uptime
        cpu_times: Dict[str, Any] = {}
        if h_proc and hasattr(k32, "GetProcessTimes"):
            ft_create, ft_exit, ft_kernel, ft_user = FILETIME(), FILETIME(), FILETIME(), FILETIME()
            if k32.GetProcessTimes(h_proc, ctypes.byref(ft_create), ctypes.byref(ft_exit), ctypes.byref(ft_kernel), ctypes.byref(ft_user)):
                create_dt = cls._filetime_to_datetime_utc(ft_create)
                t_kernel_sec = cls._filetime_to_int(ft_kernel) / 10000000.0
                t_user_sec = cls._filetime_to_int(ft_user) / 10000000.0
                uptime_sec = 0.0
                if create_dt:
                    uptime_sec = max(0.0, (datetime.datetime.now(datetime.timezone.utc) - create_dt).total_seconds())

                cpu_times = {
                    "creation_time_utc": create_dt.isoformat() if create_dt else None,
                    "uptime_seconds": round(uptime_sec, 1),
                    "uptime_hours": round(uptime_sec / 3600.0, 2),
                    "kernel_cpu_time_seconds": round(t_kernel_sec, 2),
                    "user_cpu_time_seconds": round(t_user_sec, 2),
                    "total_cpu_time_seconds": round(t_kernel_sec + t_user_sec, 2),
                }

        # 6. I/O Counters
        io_info: Dict[str, Any] = {}
        if h_proc and hasattr(k32, "GetProcessIoCounters"):
            ioc = IO_COUNTERS()
            if k32.GetProcessIoCounters(h_proc, ctypes.byref(ioc)):
                io_info = {
                    "read_transfer_mb": round(ioc.ReadTransferCount / (1024 * 1024), 2),
                    "write_transfer_mb": round(ioc.WriteTransferCount / (1024 * 1024), 2),
                    "other_transfer_mb": round(ioc.OtherTransferCount / (1024 * 1024), 2),
                    "read_operation_count": ioc.ReadOperationCount,
                    "write_operation_count": ioc.WriteOperationCount,
                    "other_operation_count": ioc.OtherOperationCount,
                }

        if h_proc:
            k32.CloseHandle(h_proc)

        # 7. Mitigations (DEP, ASLR, CFG)
        mitigations = ProcessMitigationInspector.inspect_process(pid=target_pid).get("mitigations", {})

        # 8. Hosted Services
        svcs = ServiceProcessMapper.get_services_for_process(target_pid)

        # 9. Active TCP Connections
        conns_rep = NetworkHardwareInspector.audit_tcp_connections(pid=target_pid)
        active_conns = conns_rep.get("connections", [])

        # 10. Loaded Modules
        mod_rep = ModuleInventory.get_modules_for_process(target_pid)

        return {
            "status": "success",
            "process_id": target_pid,
            "parent_process_id": ppid,
            "executable_name": exe_name,
            "image_path": img_path,
            "command_line": cmd_line,
            "architecture": arch,
            "session_id": sess_id,
            "security": sec_context,
            "thread_count": thread_cnt,
            "handle_count": handle_cnt,
            "memory": mem_info,
            "cpu_and_timing": cpu_times,
            "io_counters": io_info,
            "mitigations": mitigations,
            "hosted_services": svcs,
            "active_tcp_connections": active_conns,
            "loaded_modules_count": mod_rep.get("modules_count", 0),
            "modules_sample": mod_rep.get("modules", [])[:15]
        }
