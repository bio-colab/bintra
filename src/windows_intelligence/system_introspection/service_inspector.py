# -*- coding: utf-8 -*-
"""
Windows Service Control Manager (SCM) Introspection Engine.
Connects directly to the SCM database via advapi32.dll to inspect service states,
startup types, binary paths, account privileges, and dependency linkages.
"""

import os
import ctypes
from ctypes import wintypes
from typing import Dict, Any, List, Optional


class SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwServiceFlags", wintypes.DWORD),
    ]


class ENUM_SERVICE_STATUS_PROCESSW(ctypes.Structure):
    _fields_ = [
        ("lpServiceName", ctypes.c_wchar_p),
        ("lpDisplayName", ctypes.c_wchar_p),
        ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
    ]


class QUERY_SERVICE_CONFIGW(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwStartType", wintypes.DWORD),
        ("dwErrorControl", wintypes.DWORD),
        ("lpBinaryPathName", ctypes.c_wchar_p),
        ("lpLoadOrderGroup", ctypes.c_wchar_p),
        ("dwTagId", wintypes.DWORD),
        ("lpDependencies", ctypes.c_wchar_p),
        ("lpServiceStartName", ctypes.c_wchar_p),
        ("lpDisplayName", ctypes.c_wchar_p),
    ]


class ServiceManagerInspector:
    """
    Introspects the live Windows Service database via SCM APIs (advapi32.dll).
    Identifies service states, binary paths, and failed startup dependencies.
    """

    SC_MANAGER_CONNECT = 0x0001
    SC_MANAGER_ENUMERATE_SERVICE = 0x0004

    SERVICE_WIN32 = 0x00000030
    SERVICE_DRIVER = 0x0000000B
    SERVICE_STATE_ALL = 0x00000003

    STATE_NAMES = {
        1: "STOPPED",
        2: "START_PENDING",
        3: "STOP_PENDING",
        4: "RUNNING",
        5: "CONTINUE_PENDING",
        6: "PAUSE_PENDING",
        7: "PAUSED"
    }

    START_TYPE_NAMES = {
        0: "BOOT_START",
        1: "SYSTEM_START",
        2: "AUTO_START",
        3: "DEMAND_START (Manual)",
        4: "DISABLED"
    }

    @classmethod
    def _get_advapi_library(cls):
        """Initializes and returns typed advapi32 library functions."""
        if os.name != "nt":
            return None
        try:
            advapi32 = ctypes.windll.advapi32

            advapi32.OpenSCManagerW.restype = ctypes.c_void_p
            advapi32.OpenSCManagerW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, wintypes.DWORD]

            advapi32.CloseServiceHandle.restype = wintypes.BOOL
            advapi32.CloseServiceHandle.argtypes = [ctypes.c_void_p]

            advapi32.EnumServicesStatusExW.restype = wintypes.BOOL
            advapi32.EnumServicesStatusExW.argtypes = [
                ctypes.c_void_p, ctypes.c_int, wintypes.DWORD, wintypes.DWORD,
                ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD), ctypes.c_wchar_p
            ]

            advapi32.OpenServiceW.restype = ctypes.c_void_p
            advapi32.OpenServiceW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, wintypes.DWORD]

            advapi32.QueryServiceConfigW.restype = wintypes.BOOL
            advapi32.QueryServiceConfigW.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
            ]

            return advapi32
        except Exception:
            return None

    @classmethod
    def enumerate_services(
        cls,
        include_drivers: bool = False,
        max_services: int = 512
    ) -> List[Dict[str, Any]]:
        """
        Enumerates services directly from the Windows Service Control Manager.
        Returns service names, display names, process IDs, and current states.
        """
        advapi32 = cls._get_advapi_library()
        if not advapi32:
            return []

        access = cls.SC_MANAGER_CONNECT | cls.SC_MANAGER_ENUMERATE_SERVICE
        scm = advapi32.OpenSCManagerW(None, None, access)
        if not scm:
            return []

        svc_type = cls.SERVICE_WIN32 | (cls.SERVICE_DRIVER if include_drivers else 0)
        bytes_needed = wintypes.DWORD()
        services_returned = wintypes.DWORD()
        resume_handle = wintypes.DWORD(0)

        # First probe for buffer size
        advapi32.EnumServicesStatusExW(
            scm, 0, svc_type, cls.SERVICE_STATE_ALL,
            None, 0, ctypes.byref(bytes_needed),
            ctypes.byref(services_returned), ctypes.byref(resume_handle), None
        )

        size = bytes_needed.value
        if size <= 0:
            advapi32.CloseServiceHandle(scm)
            return []

        buf = ctypes.create_string_buffer(size)
        success = advapi32.EnumServicesStatusExW(
            scm, 0, svc_type, cls.SERVICE_STATE_ALL,
            buf, size, ctypes.byref(bytes_needed),
            ctypes.byref(services_returned), ctypes.byref(resume_handle), None
        )

        services = []
        if success:
            entry_ptr = ctypes.cast(buf, ctypes.POINTER(ENUM_SERVICE_STATUS_PROCESSW))
            total = min(services_returned.value, max_services)
            for i in range(total):
                item = entry_ptr[i]
                state_code = item.ServiceStatusProcess.dwCurrentState
                services.append({
                    "service_name": item.lpServiceName or "",
                    "display_name": item.lpDisplayName or "",
                    "state": cls.STATE_NAMES.get(state_code, f"STATE_{state_code}"),
                    "state_code": state_code,
                    "process_id": item.ServiceStatusProcess.dwProcessId,
                    "win32_exit_code": item.ServiceStatusProcess.dwWin32ExitCode
                })

        advapi32.CloseServiceHandle(scm)
        return services

    @classmethod
    def get_service_config(cls, service_name: str) -> Optional[Dict[str, Any]]:
        """Queries detailed configuration for a specific service (binary path, start type, account)."""
        advapi32 = cls._get_advapi_library()
        if not advapi32:
            return None

        scm = advapi32.OpenSCManagerW(None, None, cls.SC_MANAGER_CONNECT)
        if not scm:
            return None

        svc = advapi32.OpenServiceW(scm, service_name, 0x0001)  # SERVICE_QUERY_CONFIG
        if not svc:
            advapi32.CloseServiceHandle(scm)
            return None

        bytes_needed = wintypes.DWORD()
        advapi32.QueryServiceConfigW(svc, None, 0, ctypes.byref(bytes_needed))

        size = bytes_needed.value
        config_data = None
        if size > 0:
            buf = ctypes.create_string_buffer(size)
            if advapi32.QueryServiceConfigW(svc, buf, size, ctypes.byref(bytes_needed)):
                cfg = ctypes.cast(buf, ctypes.POINTER(QUERY_SERVICE_CONFIGW)).contents
                start_code = cfg.dwStartType
                config_data = {
                    "service_name": service_name,
                    "display_name": cfg.lpDisplayName or "",
                    "binary_path": cfg.lpBinaryPathName or "",
                    "start_type": cls.START_TYPE_NAMES.get(start_code, f"START_{start_code}"),
                    "start_type_code": start_code,
                    "service_account": cfg.lpServiceStartName or "",
                    "dependencies": cfg.lpDependencies or ""
                }

        advapi32.CloseServiceHandle(svc)
        advapi32.CloseServiceHandle(scm)
        return config_data

    @classmethod
    def audit_services(cls) -> Dict[str, Any]:
        """Runs complete Windows service health audit."""
        if os.name != "nt":
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "ServiceManagerInspector requires a Windows NT host system."
            }
        all_services = cls.enumerate_services(include_drivers=False, max_services=512)
        running = [s for s in all_services if s.get("state") == "RUNNING"]
        stopped = [s for s in all_services if s.get("state") == "STOPPED"]

        return {
            "status": "success",
            "total_services_enumerated": len(all_services),
            "running_services_count": len(running),
            "stopped_services_count": len(stopped),
            "services_sample": all_services[:15]
        }
