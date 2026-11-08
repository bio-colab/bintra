# -*- coding: utf-8 -*-
"""
Constrained Read-Only PowerShell Cmdlet Harness.
Executes pre-approved CIM and WMI queries via PowerShell without loading user profiles
or executing unverified script blocks.
"""

import os
import json
import subprocess
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

        ps_exe = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), r"System32\WindowsPowerShell\v1.0\powershell.exe")
        if not os.path.isfile(ps_exe):
            ps_exe = "powershell.exe"

        command_str = f"{cmdlet} | ConvertTo-Json -Compress"
        cmd_vector = [
            ps_exe,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command", command_str
        ]

        try:
            res = subprocess.run(
                cmd_vector,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                shell=False
            )

            if res.returncode != 0:
                return {
                    "status": "error",
                    "query_id": query_id,
                    "exit_code": res.returncode,
                    "error": res.stderr.strip() or "PowerShell returned non-zero exit code."
                }

            raw_json = res.stdout.strip()
            if not raw_json:
                return {
                    "status": "success",
                    "query_id": query_id,
                    "data": None
                }

            parsed_data = json.loads(raw_json)
            return {
                "status": "success",
                "query_id": query_id,
                "cmdlet": cmdlet,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": parsed_data
            }

        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "query_id": query_id,
                "error": f"PowerShell execution timed out after {timeout_seconds} seconds."
            }
        except Exception as e:
            return {
                "status": "error",
                "query_id": query_id,
                "error": f"Failed to execute PowerShell query: {str(e)}"
            }
