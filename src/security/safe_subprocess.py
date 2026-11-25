# -*- coding: utf-8 -*-
"""
Bintra Safe Subprocess Broker.
Mediates external process execution through the ExecutionGuard.
Enforces shell=False, closed catalog of allowed binaries, argument whitelisting,
timeout enforcement, and output byte limits to prevent DoS.
"""

import os
import time
import threading
import subprocess
from typing import Dict, Any, List, Optional

from .execution_guard import ExecutionGuard, SecurityViolationError
from .capability_registry import Capability


class SafeSubprocessBroker:
    """
    Subprocess Command Broker.
    Prevents arbitrary shell execution and argument injection.
    """

    # Maximum permitted output sizes to prevent memory exhaustion during streaming collection
    MAX_OUTPUT_BYTES = 10 * 1024 * 1024
    MAX_STDERR_BYTES = 2 * 1024 * 1024
    STREAM_CHUNK_BYTES = 8192

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
        raise SecurityViolationError(f"Fail-closed: Catalog executable '{exe_name}' not found in System32 ({sys32}).")

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

        # Validate that extra flags are explicitly whitelisted (prefix match only for value-taking flags ending with '=' or ':')
        allowed = spec.get("allowed_flags", [])
        for f in flags:
            if not isinstance(f, str) or not f:
                raise SecurityViolationError(
                    f"Flag '{f}' is not permitted for command '{command_id}'. Allowed: {allowed}"
                )
            permitted = False
            for a in allowed:
                if a.endswith(("=", ":")):
                    if f.startswith(a) and len(f) > len(a):
                        permitted = True
                        break
                elif f == a:
                    permitted = True
                    break
            if not permitted:
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
        Enforces hard in-flight byte caps on both stdout and stderr (preventing pipe
        deadlocks and unbounded RAM allocation), deterministic timeout cleanup, and
        accurate exit-status classification (never reporting success on nonzero exit).
        """
        effective_timeout = float(timeout if timeout is not None else cls.DEFAULT_TIMEOUT_SEC)
        stdout_cap = int(max_stdout_bytes if max_stdout_bytes is not None else cls.MAX_OUTPUT_BYTES)
        stderr_cap = int(max_stderr_bytes if max_stderr_bytes is not None else cls.MAX_STDERR_BYTES)

        limit_exceeded_event = threading.Event()
        stdout_state: Dict[str, Any] = {"buf": bytearray(), "truncated": False, "bytes_seen": 0}
        stderr_state: Dict[str, Any] = {"buf": bytearray(), "truncated": False, "bytes_seen": 0}

        def _drain(pipe, limit: int, state: Dict[str, Any]) -> None:
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

        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,  # Enforced invariant
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

        t_out = threading.Thread(target=_drain, args=(proc.stdout, stdout_cap, stdout_state), daemon=True)
        t_err = threading.Thread(target=_drain, args=(proc.stderr, stderr_cap, stderr_state), daemon=True)
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

                rc = proc.poll()
                if rc is not None:
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

        stdout_text = bytes(stdout_state["buf"]).decode("utf-8", errors="replace")
        stderr_text = bytes(stderr_state["buf"]).decode("utf-8", errors="replace")
        stdout_truncated = bool(stdout_state["truncated"])
        stderr_truncated = bool(stderr_state["truncated"])

        if stdout_truncated:
            stdout_text += f"\n[BINTRA-SAFETY: stdout truncated at {stdout_cap} byte limit]"
        if stderr_truncated:
            stderr_text += f"\n[BINTRA-SAFETY: stderr truncated at {stderr_cap} byte limit]"

        exit_code = proc.returncode
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
