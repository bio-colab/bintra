# -*- coding: utf-8 -*-
"""
Bintra Safe Subprocess Broker.
Mediates external process execution through the ExecutionGuard.
Enforces shell=False, closed catalog of allowed binaries, argument whitelisting,
timeout enforcement, and output byte limits to prevent DoS.
"""

import os
import sys
import subprocess
from typing import Dict, Any, List, Optional, Tuple

from .execution_guard import ExecutionGuard, SecurityViolationError
from .capability_registry import Capability
from .path_identity import PathIdentity


class SafeSubprocessBroker:
    """
    Subprocess Command Broker.
    Prevents arbitrary shell execution and argument injection.
    """

    # Maximum permitted output size to prevent memory exhaustion (10 MB)
    MAX_OUTPUT_BYTES = 10 * 1024 * 1024

    # Default timeout in seconds
    DEFAULT_TIMEOUT_SEC = 15

    # Immutable specification of permitted binaries and their allowed flags
    CATALOG = {
        "os_ver": {
            "exe": "cmd.exe",
            "base_args": ["/c", "ver"],
            "allowed_flags": [],
            "risk": "read_only"
        },
        "system_info": {
            "exe": "systeminfo.exe",
            "base_args": ["/fo", "csv"],
            "allowed_flags": [],
            "risk": "read_only"
        },
        "task_list": {
            "exe": "tasklist.exe",
            "base_args": ["/v", "/fo", "csv"],
            "allowed_flags": ["/fi", "/m"],
            "risk": "read_only"
        },
        "driver_list": {
            "exe": "driverquery.exe",
            "base_args": ["/v", "/fo", "csv"],
            "allowed_flags": ["/si"],
            "risk": "read_only"
        },
        "pnp_drivers": {
            "exe": "pnputil.exe",
            "base_args": ["/enum-drivers"],
            "allowed_flags": [],
            "risk": "read_only"
        },
        "pnp_devices": {
            "exe": "pnputil.exe",
            "base_args": ["/enum-devices", "/problem"],
            "allowed_flags": ["/connected", "/disconnected"],
            "risk": "read_only"
        },
        "service_query": {
            "exe": "sc.exe",
            "base_args": ["query", "type=", "service", "state=", "all"],
            "allowed_flags": ["bufsize="],
            "risk": "read_only"
        },
        "driver_service_query": {
            "exe": "sc.exe",
            "base_args": ["query", "type=", "driver", "state=", "all"],
            "allowed_flags": ["bufsize="],
            "risk": "read_only"
        },
        "whoami": {
            "exe": "whoami.exe",
            "base_args": ["/all", "/fo", "csv"],
            "allowed_flags": ["/priv", "/groups", "/user"],
            "risk": "read_only"
        },
        "fltmc_filters": {
            "exe": "fltmc.exe",
            "base_args": ["filters"],
            "allowed_flags": ["instances"],
            "risk": "read_only"
        },
        "event_query": {
            "exe": "wevtutil.exe",
            "base_args": ["qe"],
            "allowed_flags": ["Application", "System", "Security", "/q:", "/c:", "/rd:", "/f:"],
            "risk": "read_only"
        }
    }

    @classmethod
    def _resolve_system_exe(cls, exe_name: str) -> str:
        """Resolves executable to verified System32 directory."""
        sys32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
        target = os.path.join(sys32, exe_name)
        if os.path.exists(target):
            return target
        return exe_name

    @classmethod
    def execute_catalog_command(
        cls,
        command_id: str,
        extra_flags: Optional[List[str]] = None,
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Executes a pre-approved catalog command under strict Reference Monitor mediation.
        Rejects arbitrary shell strings and unapproved arguments.
        """
        if command_id not in cls.CATALOG:
            raise SecurityViolationError(f"Command '{command_id}' is not in the approved safety catalog.")

        spec = cls.CATALOG[command_id]
        flags = extra_flags or []

        # Validate that extra flags are explicitly whitelisted
        allowed = spec.get("allowed_flags", [])
        for f in flags:
            f_clean = f.split("=")[0].strip()
            if not any(f.startswith(a) or f_clean == a for a in allowed):
                raise SecurityViolationError(
                    f"Flag '{f}' is not permitted for command '{command_id}'. Allowed: {allowed}"
                )

        exe_path = cls._resolve_system_exe(spec["exe"])
        argv = [exe_path] + spec.get("base_args", []) + flags

        # Mediate through ExecutionGuard
        ExecutionGuard.request_access(
            component="safe_subprocess",
            operation="execute_catalog_command",
            target=f"{command_id} ({spec['exe']})",
            capability=Capability.SUBPROCESS_CATALOG_EXEC,
            access_mode="EXECUTE",
            metadata={
                "command_id": command_id,
                "argv": argv,
                "shell": False,
                "is_catalog_command": True
            }
        )

        effective_timeout = timeout or cls.DEFAULT_TIMEOUT_SEC

        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                shell=False,  # Enforced invariant
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=effective_timeout
            )

            stdout = proc.stdout
            if len(stdout) > cls.MAX_OUTPUT_BYTES:
                stdout = stdout[:cls.MAX_OUTPUT_BYTES] + "\n[BINTRA-SAFETY: Output truncated at 10MB limit]"

            return {
                "status": "success",
                "command_id": command_id,
                "exit_code": proc.returncode,
                "stdout": stdout,
                "stderr": proc.stderr
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "command_id": command_id,
                "error": f"Command timed out after {effective_timeout}s."
            }
        except Exception as exc:
            return {
                "status": "error",
                "command_id": command_id,
                "error": str(exc)
            }
