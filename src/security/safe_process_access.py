# -*- coding: utf-8 -*-
"""
REA-Neural Safe Process Access Gateway.
Guarantees strictly read-only process inspection (PROCESS_QUERY_LIMITED_INFORMATION).
Forbids PROCESS_TERMINATE, PROCESS_VM_WRITE, memory injection, and thread hijacking.
"""

import sys
import ctypes
from typing import Dict, Any, Optional

from .execution_guard import ExecutionGuard
from .capability_registry import Capability


class SafeProcessAccess:
    """
    Authorized read-only Process inspection gateway mediated by ExecutionGuard.
    """

    # Win32 Constants
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_QUERY_INFORMATION = 0x0400

    # Strictly Prohibited Hazardous Access Masks
    FORBIDDEN_PROCESS_RIGHTS = (
        0x0001 |  # PROCESS_TERMINATE
        0x0002 |  # PROCESS_CREATE_THREAD
        0x0008 |  # PROCESS_VM_OPERATION
        0x0010 |  # PROCESS_VM_READ
        0x0020 |  # PROCESS_VM_WRITE
        0x0040 |  # PROCESS_DUP_HANDLE
        0x0080 |  # PROCESS_CREATE_PROCESS
        0x0100 |  # PROCESS_SET_QUOTA
        0x0200 |  # PROCESS_SET_INFORMATION
        0x001F0FFF  # PROCESS_ALL_ACCESS
    )

    @classmethod
    def open_process_for_query(cls, pid: int) -> Dict[str, Any]:
        """
        Safely acquires a process handle with PROCESS_QUERY_LIMITED_INFORMATION rights only.
        Returns graceful ACCESS_DENIED on protected or PPL processes without elevation.
        """
        ExecutionGuard.request_access(
            component="safe_process_access",
            operation="open_process_for_query",
            target=f"PID:{pid}",
            capability=Capability.PROCESS_QUERY,
            access_mode="QUERY"
        )

        if sys.platform != "win32":
            return {"status": "unsupported", "error": "Process handle inspection requires Windows"}

        try:
            h_proc = ctypes.windll.kernel32.OpenProcess(
                cls.PROCESS_QUERY_LIMITED_INFORMATION,
                False,
                pid
            )
            if not h_proc:
                err = ctypes.GetLastError()
                return {
                    "status": "access_denied" if err == 5 else "error",
                    "error_code": err,
                    "handle": None,
                    "reason": "ACCESS_DENIED (Protected / System Process)" if err == 5 else "Process not found"
                }

            return {
                "status": "success",
                "handle": h_proc,
                "process_id": pid,
                "access_mask": hex(cls.PROCESS_QUERY_LIMITED_INFORMATION)
            }
        except Exception as exc:
            return {"status": "error", "error": str(exc), "handle": None}

    @classmethod
    def query_process_image_path(cls, pid: int) -> Optional[str]:
        """Queries the full executable image path using limited query rights."""
        res = cls.open_process_for_query(pid)
        if res.get("status") != "success" or not res.get("handle"):
            return None

        h_proc = res["handle"]
        try:
            buf = ctypes.create_unicode_buffer(1024)
            size = ctypes.c_ulong(1024)
            # QueryFullProcessImageNameW (flag 0 = Win32 path format)
            success = ctypes.windll.kernel32.QueryFullProcessImageNameW(h_proc, 0, buf, ctypes.byref(size))
            if success:
                return buf.value
        finally:
            ctypes.windll.kernel32.CloseHandle(h_proc)

        return None
