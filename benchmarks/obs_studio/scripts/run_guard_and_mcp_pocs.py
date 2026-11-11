"""Bintra vs OBS Studio — Axes A5 & A6 Security Guard & MCP Protocol Runner.

Executes BINTRA-OBS-010 (Safety Kernel Mediation & Audit Chain) and
BINTRA-OBS-012 (Real stdio MCP Server Protocol & Live OBS Tool Calls)
strictly without mutating installed OBS binaries.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC_DIR = REPO_ROOT / "src"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from binary_neural_engine import SurgicalBinaryPatcher  # noqa: E402
from security.audit_logger import AuditLogger  # noqa: E402
from security.capability_registry import Capability  # noqa: E402
from security.execution_guard import (  # noqa: E402
    ExecutionGuard,
    OutOfScopeError,
    SecurityViolationError,
    TargetMutationError,
)
from security.safe_subprocess import SafeSubprocessBroker  # noqa: E402

EVIDENCE_DIR = Path(__file__).resolve().parents[1] / "evidence"
PROGRAM_FILES = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
OBS_ROOT = PROGRAM_FILES / "obs-studio"
OBS_BIN_DIR = OBS_ROOT / "bin" / "64bit"
OBS_PLUGINS_DIR = OBS_ROOT / "obs-plugins" / "64bit"
HOME_DIR = Path.home()


def sanitize_text(value: str) -> str:
    if not value:
        return value
    out = value
    for src, dst in [
        (str(REPO_ROOT), "<REPO_ROOT>"),
        (str(REPO_ROOT).lower(), "<REPO_ROOT>"),
        (str(OBS_ROOT), "%ProgramFiles%\\obs-studio"),
        (str(OBS_ROOT).lower(), "%ProgramFiles%\\obs-studio"),
        (str(HOME_DIR), "%USERPROFILE%"),
        (str(HOME_DIR).lower(), "%USERPROFILE%"),
    ]:
        out = out.replace(src, dst)
        out = out.replace(src.replace("\\", "/"), dst.replace("\\", "/"))
        out = out.replace(src.replace("\\", "\\\\"), dst.replace("\\", "\\\\"))
    return out


def sanitize_obj(obj: Any) -> Any:
    if isinstance(obj, str):
        return sanitize_text(obj)
    if isinstance(obj, list):
        return [sanitize_obj(v) for v in obj]
    if isinstance(obj, dict):
        return {sanitize_text(str(k)): sanitize_obj(v) for k, v in obj.items()}
    return obj


def write_evidence(filename: str, payload: Dict[str, Any]) -> Path:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    out_path = EVIDENCE_DIR / filename
    out_path.write_text(
        json.dumps(sanitize_obj(payload), indent=2, default=str),
        encoding="utf-8",
    )
    return out_path


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def run_poc_010() -> Dict[str, Any]:
    obs_dll = OBS_BIN_DIR / "obs.dll"
    droidcam_dll = OBS_PLUGINS_DIR / "droidcam-obs.dll"
    frontend_dll = OBS_BIN_DIR / "obs-frontend-api.dll"

    pre_hashes = {
        "obs.dll": _sha256(obs_dll) if obs_dll.exists() else None,
        "droidcam-obs.dll": _sha256(droidcam_dll) if droidcam_dll.exists() else None,
        "obs-frontend-api.dll": _sha256(frontend_dll) if frontend_dll.exists() else None,
    }

    checks: Dict[str, Any] = {}
    disposable_proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(15)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        with tempfile.TemporaryDirectory(prefix="bintra_obs_guard_") as tmp_str:
            tmp_root = Path(tmp_str)
            target_dir = tmp_root / "target_dir"
            ws_dir = tmp_root / "authorized_ws"
            target_dir.mkdir(parents=True, exist_ok=True)
            ws_dir.mkdir(parents=True, exist_ok=True)

            target_copy = target_dir / "obs-frontend-api.dll"
            shutil.copy2(frontend_dll, target_copy)
            copy_hash_before = _sha256(target_copy)

            with ExecutionGuard.scoped_session(
                target_binary_path=str(target_copy),
                workspace_dir=str(ws_dir),
            ):
                # 1. In-place overwrite block
                try:
                    SurgicalBinaryPatcher.patch_file(
                        str(target_copy), str(target_copy), 0x400, "90", enforce_nociception=False
                    )
                    checks["inplace_overwrite_blocked"] = {"blocked": False}
                except SecurityViolationError as ex:
                    checks["inplace_overwrite_blocked"] = {
                        "blocked": True,
                        "exception": type(ex).__name__,
                        "detail": str(ex),
                    }

                # 2. Target-directory sibling write block
                try:
                    SurgicalBinaryPatcher.patch_file(
                        str(target_copy),
                        str(target_dir / "sibling_out.dll"),
                        0x400,
                        "90",
                        enforce_nociception=False,
                    )
                    checks["target_dir_sibling_write_blocked"] = {"blocked": False}
                except SecurityViolationError as ex:
                    checks["target_dir_sibling_write_blocked"] = {
                        "blocked": True,
                        "exception": type(ex).__name__,
                        "detail": str(ex),
                    }

                # 3. Path traversal / workspace escape block
                try:
                    ExecutionGuard.request_access(
                        "guard_bench",
                        "write_test",
                        str(ws_dir / ".." / "escaped.dll"),
                        Capability.WORKSPACE_WRITE,
                        access_mode="WRITE",
                    )
                    checks["workspace_traversal_blocked"] = {"blocked": False}
                except SecurityViolationError as ex:
                    checks["workspace_traversal_blocked"] = {
                        "blocked": True,
                        "exception": type(ex).__name__,
                        "detail": str(ex),
                    }

                # 4. Windows NTFS ADS stream block
                try:
                    ExecutionGuard.request_access(
                        "guard_bench",
                        "ads_test",
                        str(ws_dir / "clean.dll:hidden_stream"),
                        Capability.WORKSPACE_WRITE,
                        access_mode="WRITE",
                    )
                    checks["ads_injection_blocked"] = {"blocked": False}
                except SecurityViolationError as ex:
                    checks["ads_injection_blocked"] = {
                        "blocked": True,
                        "exception": type(ex).__name__,
                        "detail": str(ex),
                    }

                # 5. Live process write hazard block on disposable child PID
                try:
                    ExecutionGuard.request_access(
                        "guard_bench",
                        "vm_write_test",
                        f"pid_{disposable_proc.pid}",
                        Capability.PROCESS_MUTATE,
                        access_mode="WRITE",
                    )
                    checks["process_mutate_blocked"] = {"blocked": False}
                except SecurityViolationError as ex:
                    checks["process_mutate_blocked"] = {
                        "blocked": True,
                        "exception": type(ex).__name__,
                        "detail": str(ex),
                    }

                # 6. Prohibited shell execution hazard block
                try:
                    ExecutionGuard.request_access(
                        "guard_bench",
                        "shell_exec_test",
                        "cmd.exe /c whoami",
                        Capability.SHELL_FREE_EXEC,
                        access_mode="EXECUTE",
                    )
                    checks["shell_free_exec_blocked"] = {"blocked": False}
                except SecurityViolationError as ex:
                    checks["shell_free_exec_blocked"] = {
                        "blocked": True,
                        "exception": type(ex).__name__,
                        "detail": str(ex),
                    }

                # 7. Subprocess Broker: allowed catalog vs unapproved command & flag
                ok_cmd = SafeSubprocessBroker.execute_catalog_command("os_ver")
                unapproved_cmd_blocked = False
                try:
                    SafeSubprocessBroker.execute_catalog_command("arbitrary_shell_cmd")
                except SecurityViolationError:
                    unapproved_cmd_blocked = True

                bad_flag_blocked = False
                try:
                    SafeSubprocessBroker.execute_catalog_command("task_list", extra_flags=["/badflag"])
                except SecurityViolationError:
                    bad_flag_blocked = True

                checks["subprocess_broker"] = {
                    "catalog_os_ver_status": ok_cmd.get("status"),
                    "catalog_os_ver_exit": ok_cmd.get("exit_code"),
                    "unapproved_command_blocked": unapproved_cmd_blocked,
                    "disallowed_flag_blocked": bad_flag_blocked,
                }

                # 8. Positive Copy-on-Write inside authorized workspace only
                ws_out = ws_dir / "obs_frontend_cow.dll"
                patch_res = SurgicalBinaryPatcher.patch_file(
                    str(target_copy),
                    str(ws_out),
                    0x200,
                    "90",
                    enforce_nociception=False,
                )
                checks["authorized_cow_in_workspace"] = {
                    "output_exists": ws_out.exists(),
                    "patch_result_keys": list(patch_res.keys()),
                    "original_copy_sha256_unchanged": (_sha256(target_copy) == copy_hash_before),
                }

        # 9. Audit logger chain continuity + legacy rotation history check
        chain_res = AuditLogger.verify_audit_chain()
        bintra_logs_dir = HOME_DIR / ".bintra" / "logs"
        legacy_rotations = sorted(p.name for p in bintra_logs_dir.glob("audit.jsonl.legacy.*")) if bintra_logs_dir.exists() else []
        denials = AuditLogger.get_denials() if hasattr(AuditLogger, "get_denials") else []

        checks["audit_logger"] = {
            "verify_audit_chain": chain_res,
            "legacy_broken_chain_rotations_count": len(legacy_rotations),
            "legacy_rotation_filenames_sample": legacy_rotations[-5:],
            "recent_denials_count": len(denials) if isinstance(denials, list) else None,
        }
    finally:
        if disposable_proc.poll() is None:
            disposable_proc.terminate()
            try:
                disposable_proc.wait(timeout=5)
            except Exception:
                disposable_proc.kill()

    post_hashes = {
        "obs.dll": _sha256(obs_dll) if obs_dll.exists() else None,
        "droidcam-obs.dll": _sha256(droidcam_dll) if droidcam_dll.exists() else None,
        "obs-frontend-api.dll": _sha256(frontend_dll) if frontend_dll.exists() else None,
    }

    payload = {
        "test_id": "BINTRA-OBS-010",
        "host_obs_binaries_untouched": (pre_hashes == post_hashes),
        "checks": checks,
    }
    write_evidence("obs_010.json", payload)
    return payload


def run_poc_012() -> Dict[str, Any]:
    obs_dll = OBS_BIN_DIR / "obs.dll"
    obs64_exe = OBS_BIN_DIR / "obs64.exe"
    frontend_dll = OBS_BIN_DIR / "obs-frontend-api.dll"

    with tempfile.TemporaryDirectory(prefix="bintra_obs_mcp_") as ws_str:
        ws_dir = Path(ws_str)
        env = os.environ.copy()
        env["BINTRA_MCP_WORKSPACE"] = str(ws_dir)

        proc = subprocess.Popen(
            [sys.executable, str(REPO_ROOT / "src" / "mcp_server.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )

        def send_recv(obj: Any, expect_reply: bool = True) -> Any:
            assert proc.stdin is not None and proc.stdout is not None
            proc.stdin.write(json.dumps(obj) + "\n")
            proc.stdin.flush()
            if not expect_reply:
                return None
            line = proc.stdout.readline()
            return json.loads(line) if line else None

        try:
            init_resp = send_recv(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "bintra-obs-bench", "version": "1.0.0"},
                    },
                }
            )
            # Notification should emit ZERO response line; confirm next ping still gets id=2
            send_recv({"jsonrpc": "2.0", "method": "notifications/initialized"}, expect_reply=False)
            ping_resp = send_recv({"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}})
            tools_resp = send_recv({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}})
            tools_list = tools_resp.get("result", {}).get("tools", []) if tools_resp else []

            # Batch test + empty batch error
            batch_resp = send_recv(
                [
                    {"jsonrpc": "2.0", "id": 4, "method": "ping", "params": {}},
                    {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "bintra_inspect_binary", "arguments": {"file_path": str(frontend_dll)}}},
                ]
            )
            empty_batch_resp = send_recv([])

            # Invalid JSON parse error check
            assert proc.stdin is not None and proc.stdout is not None
            proc.stdin.write("{invalid_json\n")
            proc.stdin.flush()
            parse_err_resp = json.loads(proc.stdout.readline())

            # Real OBS tool calls
            inspect_obs_resp = send_recv(
                {
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {"name": "bintra_inspect_binary", "arguments": {"file_path": str(obs_dll)}},
                }
            )
            deps_obs_resp = send_recv(
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {"name": "bintra_resolve_dependencies", "arguments": {"file_path": str(obs_dll)}},
                }
            )
            sense_obs_resp = send_recv(
                {
                    "jsonrpc": "2.0",
                    "id": 8,
                    "method": "tools/call",
                    "params": {"name": "bintra_sensory_audit", "arguments": {"file_path": str(frontend_dll)}},
                }
            )
            graph_obs_resp = send_recv(
                {
                    "jsonrpc": "2.0",
                    "id": 9,
                    "method": "tools/call",
                    "params": {"name": "bintra_evidence_graph", "arguments": {"binary_path": str(obs64_exe)}},
                }
            )

            # Negative / Security Boundary checks via MCP
            untrusted_ws_resp = send_recv(
                {
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "tools/call",
                    "params": {
                        "name": "bintra_patch_binary",
                        "arguments": {
                            "source_path": str(frontend_dll),
                            "output_path": str(frontend_dll),
                            "file_offset": 0,
                            "patch_hex": "90",
                            "workspace_dir": str(OBS_BIN_DIR),
                        },
                    },
                }
            )
            bad_schema_resp = send_recv(
                {
                    "jsonrpc": "2.0",
                    "id": 11,
                    "method": "tools/call",
                    "params": {"name": "bintra_vad_inspect", "arguments": {"pid": "not_an_int"}},
                }
            )
            unknown_tool_resp = send_recv(
                {
                    "jsonrpc": "2.0",
                    "id": 12,
                    "method": "tools/call",
                    "params": {"name": "nonexistent_tool_xyz", "arguments": {}},
                }
            )

            def _extract_mcp_text(resp: Dict[str, Any]) -> Any:
                if not isinstance(resp, dict):
                    return None
                if "error" in resp:
                    return {"rpc_error": resp["error"]}
                res = resp.get("result", {})
                content = res.get("content", [])
                if content and isinstance(content, list):
                    txt = content[0].get("text", "")
                    try:
                        parsed = json.loads(txt)
                        if isinstance(parsed, dict):
                            return {
                                "isError": res.get("isError", False),
                                "parsed_keys": list(parsed.keys()),
                                "status": parsed.get("status"),
                                "verdict": parsed.get("verdict"),
                                "error": parsed.get("error"),
                            }
                    except Exception:
                        return {"isError": res.get("isError", False), "raw_text_head": txt[:300]}
                return res

            payload = {
                "test_id": "BINTRA-OBS-012",
                "initialize_result": init_resp.get("result") if isinstance(init_resp, dict) else None,
                "notification_silent_ping_id_preserved": (ping_resp.get("id") == 2 and "result" in ping_resp) if isinstance(ping_resp, dict) else False,
                "tools_registered_count": len(tools_list),
                "batch_request_responses_count": len(batch_resp) if isinstance(batch_resp, list) else None,
                "empty_batch_error": empty_batch_resp.get("error") if isinstance(empty_batch_resp, dict) else None,
                "malformed_json_parse_error": parse_err_resp.get("error") if isinstance(parse_err_resp, dict) else None,
                "obs_live_tool_calls": {
                    "bintra_inspect_binary_obs_dll": _extract_mcp_text(inspect_obs_resp),
                    "bintra_resolve_dependencies_obs_dll": _extract_mcp_text(deps_obs_resp),
                    "bintra_sensory_audit_obs_frontend": _extract_mcp_text(sense_obs_resp),
                    "bintra_evidence_graph_obs64": _extract_mcp_text(graph_obs_resp),
                },
                "security_and_schema_rejections": {
                    "untrusted_workspace_or_overwrite": untrusted_ws_resp,
                    "schema_wrong_type_vad_pid": bad_schema_resp,
                    "unknown_tool_call": unknown_tool_resp,
                },
            }
            write_evidence("obs_012.json", payload)
            return payload
        finally:
            try:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5)
            except Exception:
                proc.kill()


def main() -> None:
    r10 = run_poc_010()
    print(f"[010] host_untouched={r10['host_obs_binaries_untouched']}, chain_valid={r10['checks']['audit_logger']['verify_audit_chain']}")
    r12 = run_poc_012()
    print(f"[012] mcp tools={r12['tools_registered_count']}, batch={r12['batch_request_responses_count']}, notif_ok={r12['notification_silent_ping_id_preserved']}")


if __name__ == "__main__":
    main()
