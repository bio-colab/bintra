# -*- coding: utf-8 -*-
"""
Safe Command Execution Harness.
Executes pre-registered, read-only Windows commands strictly without shell=True,
enforcing timeouts, build compatibility gates, and typed schema validation.
"""

import os
import sys
import time
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from .command_catalog import CommandCatalog, CommandSpec
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

        # 5. Execute with Defensive Timeout & Error Isolation
        start_time = time.time()
        try:
            res = subprocess.run(
                cmd_vector,
                capture_output=True,
                text=True,
                timeout=spec.timeout_seconds,
                shell=False
            )
            elapsed_ms = round((time.time() - start_time) * 1000, 2)

            if res.returncode != 0 and not res.stdout:
                return {
                    "status": "error",
                    "command_id": command_id,
                    "exit_code": res.returncode,
                    "error": res.stderr.strip() or "Command execution returned non-zero exit code without stdout."
                }

            # 6. Parse Output into Typed Schema (with 5MB output guard)
            stdout_text = res.stdout
            MAX_OUTPUT_BYTES = 5 * 1024 * 1024  # 5 MB
            is_truncated = False
            if len(stdout_text.encode('utf-8', errors='ignore')) > MAX_OUTPUT_BYTES:
                stdout_text = stdout_text[:MAX_OUTPUT_BYTES] + "\n... [OUTPUT TRUNCATED AT 5MB SAFETY LIMIT]"
                is_truncated = True

            parsed_data = OutputParsers.dispatch_parser(spec.parser_name, stdout_text)

            return {
                "status": "success",
                "command_id": command_id,
                "schema": spec.output_schema,
                "executable": binary_path,
                "arguments": list(spec.fixed_arguments) + validated_extra,
                "exit_code": res.returncode,
                "duration_ms": elapsed_ms,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "is_truncated": is_truncated,
                "data": parsed_data
            }

        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "command_id": command_id,
                "error": f"Execution timed out after {spec.timeout_seconds} seconds."
            }
        except Exception as e:
            return {
                "status": "error",
                "command_id": command_id,
                "error": f"Execution failed with unexpected exception: {str(e)}"
            }
