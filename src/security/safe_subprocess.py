# -*- coding: utf-8 -*-
"""
Bintra Safe Subprocess Broker.
Mediates external process execution through the ExecutionGuard.
Enforces shell=False, closed catalog of allowed binaries, argument whitelisting,
timeout enforcement, and output byte limits to prevent DoS.
"""

import math
import os
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

from .audit_logger import AuditLogger
from .capability_registry import Capability
from .config import (
    SUBPROCESS_CATALOG,
    SUBPROCESS_DEFAULT_TIMEOUT_SEC,
    SUBPROCESS_MAX_OUTPUT_BYTES,
    SUBPROCESS_MAX_STDERR_BYTES,
    SUBPROCESS_STREAM_CHUNK_BYTES,
)
from .execution_guard import ExecutionGuard, SecurityViolationError
from .path_identity import PathIdentity


class SafeSubprocessBroker:
    """
    Subprocess Command Broker.
    Prevents arbitrary shell execution and argument injection.
    """

    MAX_OUTPUT_BYTES = SUBPROCESS_MAX_OUTPUT_BYTES
    MAX_STDERR_BYTES = SUBPROCESS_MAX_STDERR_BYTES
    STREAM_CHUNK_BYTES = SUBPROCESS_STREAM_CHUNK_BYTES
    DEFAULT_TIMEOUT_SEC = SUBPROCESS_DEFAULT_TIMEOUT_SEC
    CATALOG = SUBPROCESS_CATALOG

    @classmethod
    def _audit_and_reject(cls, target: str, reason: str) -> None:
        AuditLogger.log_decision(
            component="safe_subprocess",
            operation="execute_catalog_command",
            target=target,
            decision="DENY",
            reason=reason,
            requested_capability=Capability.SUBPROCESS_CATALOG_EXEC.value,
            result="DENIED",
        )
        raise SecurityViolationError(reason)

    @classmethod
    def _resolve_system_exe(cls, exe_name: str) -> str:
        """Resolves executable to verified canonical System32 directory."""
        sys_root = os.environ.get("SystemRoot", r"C:\Windows")
        sys32 = os.path.join(sys_root, "System32")
        try:
            can_sys32 = PathIdentity.canonicalize(sys32)
            can_target = PathIdentity.canonicalize(os.path.join(can_sys32, exe_name))
        except Exception as exc:
            cls._audit_and_reject(exe_name, f"Fail-closed: Invalid System32 executable path '{exe_name}': {exc}")

        if os.path.isfile(can_target) and PathIdentity.is_within_directory(can_target, can_sys32):
            return can_target
        cls._audit_and_reject(
            exe_name,
            f"Fail-closed: Catalog executable '{exe_name}' not found in System32 ({sys32}).",
        )

    @classmethod
    def _validate_extra_flags(cls, command_id: str, flags: List[str], allowed: List[str]) -> None:
        for flag in flags:
            if not isinstance(flag, str) or not flag or any(ch in flag for ch in ("\x00", "\r", "\n")):
                cls._audit_and_reject(
                    command_id,
                    f"Flag '{flag}' is not permitted for command '{command_id}'. Allowed: {allowed}",
                )

            permitted = False
            for rule in allowed:
                if rule.endswith(("=", ":")):
                    if flag.startswith(rule) and len(flag) > len(rule):
                        permitted = True
                        break
                elif flag == rule:
                    permitted = True
                    break

            if not permitted:
                cls._audit_and_reject(
                    command_id,
                    f"Flag '{flag}' is not permitted for command '{command_id}'. Allowed: {allowed}",
                )

    @classmethod
    def execute_catalog_command(
        cls,
        command_id: str,
        extra_flags: Optional[List[str]] = None,
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Executes a pre-approved catalog command under strict Reference Monitor mediation.
        Rejects arbitrary shell strings and unapproved arguments.
        """
        if command_id not in cls.CATALOG:
            cls._audit_and_reject(
                str(command_id),
                f"Command '{command_id}' is not in the approved safety catalog.",
            )

        spec = cls.CATALOG[command_id]
        flags = list(extra_flags or [])
        cls._validate_extra_flags(command_id, flags, list(spec.get("allowed_flags", [])))

        exe_path = cls._resolve_system_exe(str(spec["exe"]))
        argv = [exe_path] + list(spec.get("base_args", [])) + flags

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
                "is_catalog_command": True,
            },
        )

        effective_timeout = cls.DEFAULT_TIMEOUT_SEC if timeout is None else timeout
        if isinstance(effective_timeout, bool) or not isinstance(effective_timeout, (int, float)) or not math.isfinite(effective_timeout) or effective_timeout <= 0:
            raise ValueError(f"Timeout must be a positive number of seconds, got {effective_timeout!r}")

        run_res = cls.run_bounded_process(
            argv=argv,
            timeout=effective_timeout,
            max_stdout_bytes=cls.MAX_OUTPUT_BYTES,
            max_stderr_bytes=cls.MAX_STDERR_BYTES,
            terminate_on_limit=True,
        )
        run_res["command_id"] = command_id
        return run_res

    @classmethod
    def _terminate_process_safely(cls, proc: subprocess.Popen) -> None:
        """Deterministically terminates and reaps a child process to prevent orphans/zombies."""
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
        except OSError:
            pass
        try:
            proc.wait(timeout=1.0)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            pass

    @classmethod
    def _drain_pipe(
        cls,
        pipe: Any,
        limit: int,
        state: Dict[str, Any],
        limit_exceeded_event: threading.Event,
        terminate_on_limit: bool,
    ) -> None:
        try:
            while True:
                chunk = pipe.read(cls.STREAM_CHUNK_BYTES)
                if not chunk:
                    break
                state["bytes_seen"] += len(chunk)
                if not state["truncated"]:
                    remaining = limit - len(state["buf"])
                    if remaining > 0:
                        state["buf"].extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        state["truncated"] = True
                        limit_exceeded_event.set()
                        if terminate_on_limit:
                            break
        except Exception as exc:
            state["read_error"] = str(exc)
        finally:
            try:
                pipe.close()
            except Exception:
                pass

    @classmethod
    def _build_process_result(
        cls,
        exit_code: Optional[int],
        stdout_state: Dict[str, Any],
        stderr_state: Dict[str, Any],
        stdout_cap: int,
        stderr_cap: int,
        effective_timeout: float,
        timed_out: bool,
        output_limit_exceeded: bool,
    ) -> Dict[str, Any]:
        stdout_text = bytes(stdout_state["buf"]).decode("utf-8", errors="replace")
        stderr_text = bytes(stderr_state["buf"]).decode("utf-8", errors="replace")
        stdout_truncated = bool(stdout_state["truncated"])
        stderr_truncated = bool(stderr_state["truncated"])

        if stdout_truncated:
            stdout_text += f"\n[BINTRA-SAFETY: stdout truncated at {stdout_cap} byte limit]"
        if stderr_truncated:
            stderr_text += f"\n[BINTRA-SAFETY: stderr truncated at {stderr_cap} byte limit]"

        if timed_out:
            return {
                "status": "timeout",
                "exit_code": exit_code,
                "stdout": stdout_text,
                "stderr": stderr_text,
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
                "timed_out": True,
                "output_limit_exceeded": output_limit_exceeded,
                "error": f"Command timed out after {effective_timeout}s.",
            }
        if output_limit_exceeded or stdout_truncated or stderr_truncated:
            return {
                "status": "output_limit_exceeded",
                "exit_code": exit_code,
                "stdout": stdout_text,
                "stderr": stderr_text,
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
                "timed_out": False,
                "output_limit_exceeded": True,
                "error": f"Command output exceeded safety limit (stdout_cap={stdout_cap}, stderr_cap={stderr_cap}).",
            }

        pipe_err = stdout_state.get("read_error") or stderr_state.get("read_error")
        if exit_code != 0:
            return {
                "status": "nonzero_exit",
                "exit_code": exit_code,
                "stdout": stdout_text,
                "stderr": stderr_text,
                "stdout_truncated": False,
                "stderr_truncated": False,
                "timed_out": False,
                "output_limit_exceeded": False,
                "pipe_read_error": pipe_err,
                "error": stderr_text.strip() or f"Command exited with nonzero status {exit_code}.",
            }

        return {
            "status": "success" if not pipe_err else "pipe_error",
            "exit_code": exit_code,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "stdout_truncated": False,
            "stderr_truncated": False,
            "timed_out": False,
            "output_limit_exceeded": False,
            "pipe_read_error": pipe_err,
        }

    @classmethod
    def run_bounded_process(
        cls,
        argv: List[str],
        timeout: Optional[float] = None,
        max_stdout_bytes: Optional[int] = None,
        max_stderr_bytes: Optional[int] = None,
        terminate_on_limit: bool = True,
    ) -> Dict[str, Any]:
        """
        Executes a command vector with shell=False using streaming dual-pipe collection.
        Enforces hard in-flight byte caps on both stdout and stderr, deterministic timeout
        cleanup, and accurate exit-status classification.
        """
        effective_timeout = float(timeout if timeout is not None else cls.DEFAULT_TIMEOUT_SEC)
        if not math.isfinite(effective_timeout) or effective_timeout <= 0:
            raise ValueError(f"timeout must be positive and finite, got {timeout!r}")

        stdout_cap = int(max_stdout_bytes if max_stdout_bytes is not None else cls.MAX_OUTPUT_BYTES)
        stderr_cap = int(max_stderr_bytes if max_stderr_bytes is not None else cls.MAX_STDERR_BYTES)
        if stdout_cap < 0 or stderr_cap < 0:
            raise ValueError("max_stdout_bytes and max_stderr_bytes must be non-negative")

        limit_exceeded_event = threading.Event()
        stdout_state: Dict[str, Any] = {"buf": bytearray(), "truncated": False, "bytes_seen": 0}
        stderr_state: Dict[str, Any] = {"buf": bytearray(), "truncated": False, "bytes_seen": 0}

        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )
        except Exception as exc:
            return {
                "status": "error",
                "exit_code": None,
                "stdout": "",
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "error": str(exc),
            }

        t_out = threading.Thread(
            target=cls._drain_pipe,
            args=(proc.stdout, stdout_cap, stdout_state, limit_exceeded_event, terminate_on_limit),
            daemon=True,
        )
        t_err = threading.Thread(
            target=cls._drain_pipe,
            args=(proc.stderr, stderr_cap, stderr_state, limit_exceeded_event, terminate_on_limit),
            daemon=True,
        )
        t_out.start()
        t_err.start()

        timed_out = False
        output_limit_exceeded = False
        deadline = time.monotonic() + effective_timeout

        try:
            while True:
                if terminate_on_limit and limit_exceeded_event.is_set():
                    output_limit_exceeded = True
                    cls._terminate_process_safely(proc)
                    break

                if proc.poll() is not None:
                    break

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    cls._terminate_process_safely(proc)
                    break

                time.sleep(min(0.02, remaining))
        finally:
            if proc.poll() is None:
                cls._terminate_process_safely(proc)
            t_out.join(timeout=2.0)
            t_err.join(timeout=2.0)

        return cls._build_process_result(
            exit_code=proc.returncode,
            stdout_state=stdout_state,
            stderr_state=stderr_state,
            stdout_cap=stdout_cap,
            stderr_cap=stderr_cap,
            effective_timeout=effective_timeout,
            timed_out=timed_out,
            output_limit_exceeded=output_limit_exceeded,
        )
