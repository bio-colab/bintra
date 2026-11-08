# -*- coding: utf-8 -*-
"""
File Usage and Lock Inspector via Windows Restart Manager API.
Directly interrogates the Windows Restart Manager (Rstrtmgr.dll) to determine which
processes or services are holding open file handles or locking a resource.
Implements 100% read-only inspection: strictly executes RmStartSession, RmRegisterResources,
and RmGetList, and immediately closes with RmEndSession. NEVER invokes RmShutdown or RmRestart.
"""

import os
import ctypes
from ctypes import wintypes
from typing import Dict, Any, List, Optional


CCH_RM_SESSION_KEY = 32
CCH_RM_MAX_APP_NAME = 255
CCH_RM_MAX_SVC_NAME = 63


class RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = [
        ("dwProcessId", wintypes.DWORD),
        ("ProcessStartTime", wintypes.FILETIME)
    ]


class RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [
        ("Process", RM_UNIQUE_PROCESS),
        ("strAppName", ctypes.c_wchar * (CCH_RM_MAX_APP_NAME + 1)),
        ("strServiceShortName", ctypes.c_wchar * (CCH_RM_MAX_SVC_NAME + 1)),
        ("ApplicationType", wintypes.DWORD),
        ("AppStatus", wintypes.DWORD),
        ("TSSessionId", wintypes.DWORD),
        ("bRestartable", wintypes.BOOL)
    ]


class FileUsageInspector:
    """
    Authoritative read-only file lock detector using the native Windows Restart Manager API.
    Identifies the exact processes (PIDs, application names, services) preventing file deletion,
    modification, or binary swapping without terminating processes or modifying handles.
    """

    APP_TYPE_MAP = {
        0: "RmUnknownApp",
        1: "RmMainWindow",
        2: "RmOtherWindow",
        3: "RmService",
        4: "RmExplorer",
        5: "RmConsole",
        1000: "RmCritical"
    }

    APP_STATUS_MAP = {
        0x0: "RmStatusRunning",
        0x1: "RmStatusStopped",
        0x2: "RmStatusStoppedOther",
        0x4: "RmStatusRestarted",
        0x8: "RmStatusErrorOnStop",
        0x10: "RmStatusErrorOnRestart",
        0x20: "RmStatusShutdownMasked"
    }

    @classmethod
    def _get_restart_manager(cls):
        """Loads and returns typed rstrtmgr.dll functions."""
        if os.name != "nt":
            return None
        try:
            rm = ctypes.windll.rstrtmgr
            rm.RmStartSession.restype = wintypes.DWORD
            rm.RmStartSession.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, ctypes.c_wchar_p]

            rm.RmRegisterResources.restype = wintypes.DWORD
            rm.RmRegisterResources.argtypes = [
                wintypes.DWORD, wintypes.UINT, ctypes.POINTER(ctypes.c_wchar_p),
                wintypes.UINT, ctypes.c_void_p, wintypes.UINT, ctypes.c_void_p
            ]

            rm.RmGetList.restype = wintypes.DWORD
            rm.RmGetList.argtypes = [
                wintypes.DWORD, ctypes.POINTER(wintypes.UINT), ctypes.POINTER(wintypes.UINT),
                ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)
            ]

            rm.RmEndSession.restype = wintypes.DWORD
            rm.RmEndSession.argtypes = [wintypes.DWORD]
            return rm
        except Exception:
            return None

    @classmethod
    def inspect_file_locks(cls, file_path: str) -> Dict[str, Any]:
        """
        Interrogates the Windows Restart Manager to discover all processes and services
        locking or actively accessing the specified file.
        Pure read-only: does NOT shut down or restart processes.
        """
        norm_path = os.path.abspath(file_path)
        if not os.path.exists(norm_path):
            return {
                "status": "error",
                "file_path": norm_path,
                "error": f"Target file does not exist on disk: {norm_path}"
            }

        rm = cls._get_restart_manager()
        if not rm:
            return {
                "status": "error",
                "file_path": norm_path,
                "error": "Windows Restart Manager API is not available on this platform."
            }

        session_handle = wintypes.DWORD(0)
        session_key = (ctypes.c_wchar * (CCH_RM_SESSION_KEY + 1))()

        res_start = rm.RmStartSession(ctypes.byref(session_handle), 0, session_key)
        if res_start != 0:
            return {
                "status": "error",
                "file_path": norm_path,
                "error": f"RmStartSession failed with Win32 error code {res_start}."
            }

        locking_processes = []
        try:
            file_array = (ctypes.c_wchar_p * 1)(norm_path)
            res_reg = rm.RmRegisterResources(session_handle, 1, file_array, 0, None, 0, None)
            if res_reg != 0:
                return {
                    "status": "error",
                    "file_path": norm_path,
                    "error": f"RmRegisterResources failed with Win32 error code {res_reg}."
                }

            n_needed = wintypes.UINT(0)
            n_proc = wintypes.UINT(0)
            reboot_reasons = wintypes.DWORD(0)

            # Initial query to determine buffer size
            rm.RmGetList(session_handle, ctypes.byref(n_needed), ctypes.byref(n_proc), None, ctypes.byref(reboot_reasons))

            if n_needed.value > 0:
                proc_info_array = (RM_PROCESS_INFO * n_needed.value)()
                n_proc.value = n_needed.value
                res_list = rm.RmGetList(
                    session_handle,
                    ctypes.byref(n_needed),
                    ctypes.byref(n_proc),
                    ctypes.byref(proc_info_array),
                    ctypes.byref(reboot_reasons)
                )

                if res_list == 0:
                    for i in range(n_proc.value):
                        item = proc_info_array[i]
                        pid = item.Process.dwProcessId
                        app_name = item.strAppName.strip()
                        svc_name = item.strServiceShortName.strip() or None
                        app_type_code = item.ApplicationType
                        app_status_code = item.AppStatus

                        locking_processes.append({
                            "process_id": pid,
                            "application_name": app_name,
                            "service_name": svc_name,
                            "application_type": cls.APP_TYPE_MAP.get(app_type_code, f"Type_{app_type_code}"),
                            "application_status": cls.APP_STATUS_MAP.get(app_status_code, f"Status_{app_status_code}"),
                            "terminal_session_id": item.TSSessionId,
                            "is_restartable": bool(item.bRestartable)
                        })

        finally:
            rm.RmEndSession(session_handle)

        is_in_use = len(locking_processes) > 0
        return {
            "status": "success",
            "file_path": norm_path,
            "resource_state": "RESOURCE_IN_USE" if is_in_use else "RESOURCE_AVAILABLE",
            "is_locked": is_in_use,
            "handle_exclusivity": "POTENTIALLY_SHARED_OR_LOCKED",
            "locking_processes_count": len(locking_processes),
            "locking_processes": locking_processes,
            "audit_method": "WINDOWS_RESTART_MANAGER_RM_GET_LIST",
            "read_only_guarantee": True
        }
