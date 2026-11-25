# -*- coding: utf-8 -*-
"""
Bintra Safe Process Access Gateway.
Guarantees strictly read-only process inspection (PROCESS_QUERY_LIMITED_INFORMATION).
Forbids PROCESS_TERMINATE, PROCESS_VM_WRITE, memory injection, and thread hijacking.
"""

import sys
from typing import Any, Dict, Optional

from ._win32 import (
    PROCESS_QUERY_LIMITED_INFORMATION,
    close_handle_quiet,
    open_process_limited,
    query_process_image_path_from_handle,
)
from .capability_registry import Capability
from .execution_guard import ExecutionGuard


class SafeProcessAccess:
    """
    Authorized read-only Process inspection gateway mediated by ExecutionGuard.
    """

    PROCESS_QUERY_LIMITED_INFORMATION = PROCESS_QUERY_LIMITED_INFORMATION
    PROCESS_QUERY_INFORMATION = 0x0400

    # Strictly Prohibited Hazardous Access Masks
    FORBIDDEN_PROCESS_RIGHTS = (
        0x0001  # PROCESS_TERMINATE
        | 0x0002  # PROCESS_CREATE_THREAD
        | 0x0008  # PROCESS_VM_OPERATION
        | 0x0010  # PROCESS_VM_READ
        | 0x0020  # PROCESS_VM_WRITE
        | 0x0040  # PROCESS_DUP_HANDLE
        | 0x0080  # PROCESS_CREATE_PROCESS
        | 0x0100  # PROCESS_SET_QUOTA
        | 0x0200  # PROCESS_SET_INFORMATION
        | 0x001F0FFF  # PROCESS_ALL_ACCESS
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
            access_mode="QUERY",
        )

        if sys.platform != "win32":
            return {"status": "unsupported", "error": "Process handle inspection requires Windows"}

        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            return {"status": "error", "error": f"Invalid process ID: {pid!r}", "handle": None}

        try:
            h_proc, err = open_process_limited(pid)
            if not h_proc:
                return {
                    "status": "access_denied" if err == 5 else "error",
                    "error_code": err,
                    "handle": None,
                    "reason": "ACCESS_DENIED (Protected / System Process)" if err == 5 else "Process not found",
                }

            return {
                "status": "success",
                "handle": h_proc,
                "process_id": pid,
                "access_mask": hex(cls.PROCESS_QUERY_LIMITED_INFORMATION),
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
            return query_process_image_path_from_handle(h_proc)
        except Exception:
            return None
        finally:
            close_handle_quiet(h_proc)
