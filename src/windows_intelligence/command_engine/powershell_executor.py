# -*- coding: utf-8 -*-
"""
Constrained Read-Only PowerShell Cmdlet Harness.
Executes pre-approved CIM and WMI queries via PowerShell without loading user profiles
or executing unverified script blocks.
"""

import os
import json
import subprocess
from security import ExecutionGuard, Capability
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class PowerShellExecutor:
    """
    Safely executes whitelisted PowerShell CIM/WMI cmdlets to retrieve
    hardware, audio, and device telemetry not accessible via simple CMD tools.
    """

    APPROVED_CMDLETS = {
        "cim_os": "Get-CimInstance Win32_OperatingSystem",
        "cim_video": "Get-CimInstance Win32_VideoController",
        "cim_sound": "Get-CimInstance Win32_SoundDevice",
        "cim_cpu": "Get-CimInstance Win32_Processor",
        "cim_disk": "Get-CimInstance Win32_LogicalDisk",
        "cim_network": "Get-CimInstance Win32_NetworkAdapter"
    }

    @classmethod
    def build_command(cls, cmdlet: str) -> str:
        """Constructs safe PowerShell command string formatting with depth guard."""
        return f"{cmdlet} | ConvertTo-Json -Depth 4 -Compress"

    @classmethod
    def query(cls, query_id: str, timeout_seconds: int = 15) -> Dict[str, Any]:
        """
        Executes an approved CIM cmdlet, capturing compressed JSON output.
        """
        if os.name != "nt":
            return {"status": "error", "error": "PowerShell CIM execution requires Windows NT."}

        cmdlet = cls.APPROVED_CMDLETS.get(query_id)
        if not cmdlet:
            return {
                "status": "error",
                "query_id": query_id,
                "error": f"Query '{query_id}' is not in the approved PowerShell cmdlet whitelist."
            }

        # Mediate through ExecutionGuard Reference Monitor (Fail-Closed)
        try:
            ExecutionGuard.request_access(
                component="powershell_executor",
                operation="query_cim",
                target=f"cim:{query_id}",
                capability=Capability.SUBPROCESS_CATALOG_EXEC,
                access_mode="EXECUTE",
                metadata={
                    "query_id": query_id,
                    "cmdlet": cmdlet,
                    "timeout": timeout_seconds,
                    "shell": False,
                    "is_catalog_command": True,
                }
            )
        except Exception as guard_err:
            return {
                "status": "error",
                "query_id": query_id,
                "error": f"ExecutionGuard rejected PowerShell execution: {guard_err}"
            }

        # Strictly verify powershell.exe inside System32 directory (Never fallback to unverified PATH)
        sys_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR", r"C:\Windows")
        candidates = [
            os.path.join(sys_root, r"System32\WindowsPowerShell\v1.0\powershell.exe"),
            os.path.join(sys_root, r"System32\powershell.exe"),
        ]
        ps_exe = None
        for cand in candidates:
            if os.path.isfile(cand):
                ps_exe = cand
                break

        if not ps_exe:
            return {
                "status": "error",
                "query_id": query_id,
                "error": "Verified system powershell.exe not found in Windows System32 directory (fail-closed)."
            }

        command_str = cls.build_command(cmdlet)
        cmd_vector = [
            ps_exe,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command", command_str
        ]

        from security.safe_subprocess import SafeSubprocessBroker

        MAX_PS_STDOUT_BYTES = 5 * 1024 * 1024  # 5 MB streaming ceiling
        MAX_PS_STDERR_BYTES = 1 * 1024 * 1024  # 1 MB streaming ceiling
        try:
            run_res = SafeSubprocessBroker.run_bounded_process(
                argv=cmd_vector,
                timeout=timeout_seconds,
                max_stdout_bytes=MAX_PS_STDOUT_BYTES,
                max_stderr_bytes=MAX_PS_STDERR_BYTES,
                terminate_on_limit=True,
            )
            sub_status = run_res.get("status", "error")

            if sub_status == "timeout":
                return {
                    "status": "error",
                    "subprocess_status": "timeout",
                    "query_id": query_id,
                    "error": f"PowerShell execution timed out after {timeout_seconds} seconds.",
                }
            if sub_status == "output_limit_exceeded":
                return {
                    "status": "error",
                    "subprocess_status": "output_limit_exceeded",
                    "query_id": query_id,
                    "is_truncated": True,
                    "error": run_res.get("error", "PowerShell output exceeded streaming safety limit."),
                }
            if sub_status != "success":
                return {
                    "status": "error",
                    "subprocess_status": sub_status,
                    "query_id": query_id,
                    "exit_code": run_res.get("exit_code"),
                    "stderr": run_res.get("stderr", ""),
                    "error": run_res.get("error") or "PowerShell returned non-zero exit code.",
                }

            raw_json = run_res.get("stdout", "").strip()
            if not raw_json:
                return {
                    "status": "success",
                    "query_id": query_id,
                    "data": None,
                }

            parsed_data = json.loads(raw_json)
            return {
                "status": "success",
                "query_id": query_id,
                "cmdlet": cmdlet,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": parsed_data,
            }
        except Exception as e:
            return {
                "status": "error",
                "query_id": query_id,
                "error": f"Failed to execute PowerShell query: {str(e)}",
            }
