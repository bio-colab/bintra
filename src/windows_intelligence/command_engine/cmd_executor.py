# -*- coding: utf-8 -*-
"""
Safe Command Execution Harness.
Executes pre-registered, read-only Windows commands strictly without shell=True,
enforcing timeouts, build compatibility gates, and typed schema validation.
"""

import sys
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

from .command_catalog import CommandCatalog
from .output_parsers import OutputParsers


class CommandExecutor:
    """
    Executes diagnostic commands defined in the CommandCatalog with strict
    safety invariants: no arbitrary shell invocations, mandatory timeouts,
    argument whitelisting, and structured output parsing.
    """

    @classmethod
    def execute(
        cls,
        command_id: str,
        extra_flags: Optional[Tuple[str, ...]] = None,
        current_build: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Executes a registered command safely and returns parsed JSON.
        """
        if sys.platform != "win32":
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "command_id": command_id,
                "error": "Windows Command Execution harness requires a Windows host system."
            }

        spec = CommandCatalog.get_spec(command_id)
        if not spec:
            return {
                "status": "error",
                "command_id": command_id,
                "error": f"Command '{command_id}' is not registered in the immutable CommandCatalog."
            }

        # 1. Build Compatibility Check
        actual_build = current_build
        if actual_build is None and sys.platform == "win32":
            try:
                actual_build = sys.getwindowsversion().build
            except Exception:
                actual_build = None

        if actual_build is not None and actual_build < spec.min_windows_build:
            return {
                "status": "error",
                "command_id": command_id,
                "error": f"Command requires Windows Build >= {spec.min_windows_build} (Current: {actual_build})."
            }

        # 2. Administrative Privilege Gate
        if spec.requires_admin:
            from ..security_inspector import WindowsSecurityInspector
            if not WindowsSecurityInspector.is_elevated():
                return {
                    "status": "error",
                    "command_id": command_id,
                    "error": f"Command '{command_id}' requires elevated administrative privileges (spec.requires_admin=True)."
                }

        # 3. Strict Argument Whitelisting Check
        validated_extra = []
        if extra_flags:
            # Flatten any space-separated flag arguments (e.g. "state= all" -> ["state=", "all"])
            flat_flags = []
            for flag in extra_flags:
                if " " in flag:
                    flat_flags.extend(flag.split())
                else:
                    flat_flags.append(flag)

            for flag in flat_flags:
                if flag not in spec.allowed_flags:
                    return {
                        "status": "error",
                        "command_id": command_id,
                        "error": f"Argument '{flag}' is not permitted for command '{command_id}' (Allowed: {spec.allowed_flags})."
                    }
                validated_extra.append(flag)

        # 3. Resolve System Binary Path
        binary_path = CommandCatalog.resolve_executable_path(spec.binary_name)
        if not binary_path:
            return {
                "status": "error",
                "command_id": command_id,
                "error": f"System executable '{spec.binary_name}' could not be located in System32 or PATH."
            }

        # 4. Construct Command Vector (No shell=True)
        cmd_vector = [binary_path, *spec.fixed_arguments, *validated_extra]

        # 5. Mandatory Mediation via Safety Kernel (Fail-Closed)
        from security import ExecutionGuard, Capability, SecurityViolationError
        try:
            ExecutionGuard.request_access(
                component="cmd_executor",
                operation="execute_command",
                target=f"{command_id} ({spec.binary_name})",
                capability=Capability.SUBPROCESS_CATALOG_EXEC,
                access_mode="EXECUTE",
                metadata={"command_id": command_id, "shell": False, "is_catalog_command": True}
            )
        except SecurityViolationError as sec_exc:
            return {
                "status": "error",
                "command_id": command_id,
                "error": f"Execution blocked by Safety Kernel: {str(sec_exc)}",
                "decision": "DENY"
            }

        from security.safe_subprocess import SafeSubprocessBroker

        MAX_OUTPUT_BYTES = 5 * 1024 * 1024  # 5 MB streaming ceiling
        MAX_STDERR_BYTES = 1 * 1024 * 1024  # 1 MB streaming ceiling
        start_time = time.time()
        try:
            run_res = SafeSubprocessBroker.run_bounded_process(
                argv=cmd_vector,
                timeout=spec.timeout_seconds,
                max_stdout_bytes=MAX_OUTPUT_BYTES,
                max_stderr_bytes=MAX_STDERR_BYTES,
                terminate_on_limit=True,
            )
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            sub_status = run_res.get("status", "error")

            if sub_status == "timeout":
                return {
                    "status": "error",
                    "subprocess_status": "timeout",
                    "command_id": command_id,
                    "exit_code": run_res.get("exit_code"),
                    "stderr": run_res.get("stderr", ""),
                    "error": f"Execution timed out after {spec.timeout_seconds} seconds.",
                }
            if sub_status == "output_limit_exceeded":
                return {
                    "status": "error",
                    "subprocess_status": "output_limit_exceeded",
                    "command_id": command_id,
                    "exit_code": run_res.get("exit_code"),
                    "is_truncated": True,
                    "stderr": run_res.get("stderr", ""),
                    "error": run_res.get("error", "Command output exceeded streaming safety limit."),
                }
            if sub_status != "success":
                return {
                    "status": "error",
                    "subprocess_status": sub_status,
                    "command_id": command_id,
                    "exit_code": run_res.get("exit_code"),
                    "stderr": run_res.get("stderr", ""),
                    "error": run_res.get("error") or f"Command exited with status {run_res.get('exit_code')}.",
                }

            stdout_text = run_res.get("stdout", "")
            parsed_data = OutputParsers.dispatch_parser(spec.parser_name, stdout_text)

            return {
                "status": "success",
                "subprocess_status": "success",
                "command_id": command_id,
                "schema": spec.output_schema,
                "executable": binary_path,
                "arguments": list(spec.fixed_arguments) + validated_extra,
                "exit_code": run_res.get("exit_code", 0),
                "duration_ms": elapsed_ms,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "is_truncated": False,
                "data": parsed_data,
            }
        except Exception as e:
            return {
                "status": "error",
                "command_id": command_id,
                "error": f"Execution failed with unexpected exception: {str(e)}",
            }
