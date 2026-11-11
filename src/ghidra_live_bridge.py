# -*- coding: utf-8 -*-
"""
REA-Neural Ghidra Live Bidirectional IPC Bridge.
Establishes a multithreaded, localhost-bound, authenticated JSON-RPC 2.0 channel
between REA-Neural's diagnostic engine and Ghidra. Queues Crash RCA annotations,
VAD summaries, P-Code plans, and heuristic structure/pointer artifacts for the
Ghidra-side service script to poll (default 1.0 s) and commit in database transactions.
Strictly localhost (127.0.0.1); governed by ExecutionGuard, Capability.WORKSPACE_WRITE,
and Capability.TEMPDIR_MARKER_WRITE (when publishing discovery marker to temp).
"""

import os
import sys
import json
import time
import uuid
import socket
import socketserver
import tempfile
import threading
from collections import OrderedDict
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, List, Optional, Tuple, Callable

from security.execution_guard import ExecutionGuard
from security.capability_registry import Capability
from ghidra_pcode_vectorizer import PcodeDeobfuscator, PcodeVectorizer, PcodeFunctionMatcher


DEFAULT_BRIDGE_PORT = 41718
MAX_BRIDGE_BODY_BYTES = 2 * 1024 * 1024  # 2 MB hard ceiling


class GhidraBridgeRequestHandler(BaseHTTPRequestHandler):
    """Multithreaded JSON-RPC 2.0 handler for the localhost Ghidra Bridge."""

    def setup(self):
        super().setup()
        try:
            self.request.settimeout(5.0)
        except Exception:
            pass

    def log_message(self, format, *args):
        # Suppress standard HTTP request logging to keep CLI output clean
        pass

    def do_POST(self):
        raw_cl = self.headers.get("Content-Length", "0")
        try:
            content_len = int(raw_cl)
        except (ValueError, TypeError):
            self._send_json_error(None, -32600, "Invalid Content-Length header", http_status=400)
            return

        if content_len < 0:
            self._send_json_error(None, -32600, "Negative Content-Length not permitted", http_status=400)
            return

        if content_len > MAX_BRIDGE_BODY_BYTES:
            self._send_json_error(
                None,
                -32002,
                f"Payload too large ({content_len} bytes exceeds {MAX_BRIDGE_BODY_BYTES} byte limit)",
                http_status=413,
            )
            return

        try:
            post_data = self.rfile.read(content_len)
        except (socket.timeout, TimeoutError, OSError):
            self._send_json_error(None, -32700, "Request body read timed out or closed", http_status=408)
            return

        if len(post_data) != content_len:
            self._send_json_error(None, -32700, "Incomplete request body", http_status=400)
            return

        try:
            req = json.loads(post_data.decode("utf-8"))
        except Exception:
            self._send_json_error(None, -32700, "Parse error: Invalid JSON")
            return

        method = req.get("method")
        params = req.get("params", {})
        req_id = req.get("id")

        server: GhidraLiveBridgeServer = self.server.bridge_server  # type: ignore

        # Authenticate request token (except handshake ping)
        if method != "ping" and server.auth_token:
            auth = params.get("auth_token") or self.headers.get("X-REA-Auth-Token")
            if auth != server.auth_token:
                self._send_json_error(req_id, -32001, "Authentication failed: Invalid or missing bridge token")
                return

        try:
            result = server.dispatch_rpc_method(method, params)
            self._send_json_response(req_id, result)
        except Exception as e:
            self._send_json_error(req_id, -32603, f"Internal error: {str(e)}")

    def _safe_write_json(self, payload: Dict[str, Any], http_status: int = 200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        try:
            self.send_response(http_status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            pass

    def _send_json_response(self, req_id: Any, result: Any):
        self._safe_write_json({"jsonrpc": "2.0", "result": result, "id": req_id}, http_status=200)

    def _send_json_error(self, req_id: Any, code: int, message: str, http_status: int = 200):
        self._safe_write_json(
            {"jsonrpc": "2.0", "error": {"code": code, "message": message}, "id": req_id},
            http_status=http_status,
        )


class GhidraLiveBridgeServer:
    """
    Localhost-bound bidirectional JSON-RPC 2.0 server connecting REA-Neural to Ghidra.
    """

    def __init__(self, port: int = DEFAULT_BRIDGE_PORT, auth_token: Optional[str] = None):
        self.host = "127.0.0.1"
        self.port = port
        self.auth_token = auth_token or str(uuid.uuid4())
        self.httpd: Optional[HTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self.is_running = False

        # Connected client state (Ghidra script)
        self.client_metadata: Optional[Dict[str, Any]] = None
        self.last_client_heartbeat: Optional[float] = None

        # Command queues for Ghidra to consume (bounded ring semantics)
        self._max_queue_size = 2000
        self._queue_overflow_count = 0
        self._command_queue: List[Dict[str, Any]] = []
        self._queue_lock = threading.Lock()

        # Bounded LRU cache of decompiled functions pushed by Ghidra
        self._max_cached_functions = 1000
        self._decompiled_functions: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()

    @staticmethod
    def _write_marker_secure(path: str, payload: Dict[str, Any]) -> bool:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        return True

    def start(self, marker_path: Optional[str] = None, publish_temp_marker: bool = True) -> Dict[str, Any]:
        """Starts the multithreaded localhost bridge server in a background thread."""
        scope = ExecutionGuard.get_current_scope()
        ws_dir = scope.workspace_dir if scope else os.path.abspath(".")
        target_marker = marker_path or os.path.join(ws_dir, ".rea_bridge.json")

        ExecutionGuard.request_access(
            component="ghidra_live_bridge",
            operation="start",
            target=target_marker,
            capability=Capability.WORKSPACE_WRITE,
            access_mode="WRITE"
        )

        class ThreadingHttpServer(socketserver.ThreadingMixIn, HTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.httpd = ThreadingHttpServer((self.host, self.port), GhidraBridgeRequestHandler)
        self.httpd.bridge_server = self  # type: ignore
        self.port = self.httpd.server_port  # Resolve actual port if 0 passed

        self.is_running = True
        self.server_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.server_thread.start()

        # Write discovery marker inside authorized workspace
        self._marker_path = target_marker
        self._temp_marker_path = None
        marker_payload = {
            "host": self.host,
            "port": self.port,
            "auth_token": self.auth_token,
            "url": f"http://{self.host}:{self.port}"
        }
        try:
            self._write_marker_secure(target_marker, marker_payload)
        except Exception as err:
            sys.stderr.write(f"[REA-Bridge] Warning writing workspace marker '{target_marker}': {err}\n")

        # Explicitly mediate optional tempdir marker write under Capability.TEMPDIR_MARKER_WRITE
        if publish_temp_marker:
            temp_candidate = os.path.join(tempfile.gettempdir(), ".rea_bridge.json")
            if os.path.abspath(temp_candidate) != os.path.abspath(target_marker):
                ExecutionGuard.request_access(
                    component="ghidra_live_bridge",
                    operation="write_tempdir_discovery_marker",
                    target=temp_candidate,
                    capability=Capability.TEMPDIR_MARKER_WRITE,
                    access_mode="WRITE",
                )
                self._temp_marker_path = temp_candidate
                try:
                    self._write_marker_secure(temp_candidate, marker_payload)
                except Exception as err:
                    sys.stderr.write(f"[REA-Bridge] Warning writing tempdir marker '{temp_candidate}': {err}\n")

        return {
            "status": "running",
            "host": self.host,
            "port": self.port,
            "auth_token": self.auth_token,
            "bridge_url": f"http://{self.host}:{self.port}",
            "marker_file": target_marker,
            "tempdir_marker_published": bool(self._temp_marker_path),
        }

    def stop(self) -> Dict[str, Any]:
        """Stops the bridge server cleanly."""
        self.is_running = False
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None

        for m_path in (getattr(self, "_marker_path", None), getattr(self, "_temp_marker_path", None)):
            if m_path and os.path.exists(m_path):
                try:
                    os.remove(m_path)
                except Exception:
                    pass
        self._marker_path = None
        self._temp_marker_path = None

        return {
            "status": "stopped",
            "port": self.port
        }

    def dispatch_rpc_method(self, method: str, params: Dict[str, Any]) -> Any:
        """Routes incoming JSON-RPC methods from Ghidra client or REA-Neural."""
        if method == "ping":
            return {"status": "ok", "timestamp": time.time(), "bridge_version": "7.4.0"}

        elif method == "get_status":
            with self._queue_lock:
                q_count = len(self._command_queue)
                q_overflow = self._queue_overflow_count
            return {
                "is_running": self.is_running,
                "port": self.port,
                "auth_token": self.auth_token,
                "client_connected": self.is_client_connected(),
                "client_metadata": self.client_metadata,
                "queued_commands_count": q_count,
                "max_queue_size": self._max_queue_size,
                "queue_overflow_count": q_overflow,
                "cached_functions_count": len(self._decompiled_functions)
            }

        elif method == "ghidra.register_client":
            self.client_metadata = {
                "program_name": params.get("program_name", "Unknown"),
                "image_base": params.get("image_base", "0x0"),
                "architecture": params.get("architecture", "Unknown"),
                "ghidra_version": params.get("ghidra_version", "12.x"),
                "registered_at": time.time()
            }
            self.last_client_heartbeat = time.time()
            return {"status": "registered", "auth_token_accepted": True}

        elif method == "ghidra.poll_commands":
            self.last_client_heartbeat = time.time()
            with self._queue_lock:
                cmds = list(self._command_queue)
                self._command_queue.clear()
            return {"commands": cmds, "count": len(cmds)}

        elif method == "ghidra.push_pcode":
            fn_name = params.get("name", "sub_unknown")
            while len(self._decompiled_functions) >= self._max_cached_functions:
                self._decompiled_functions.popitem(last=False)
            self._decompiled_functions[fn_name] = params
            self._decompiled_functions.move_to_end(fn_name)
            return {"status": "cached", "function": fn_name}

        elif method == "rea.deobfuscate_function":
            pcode_ops = params.get("pcode_ops", [])
            blocks = params.get("basic_blocks", [])
            analysis = PcodeDeobfuscator.analyze_function(pcode_ops, blocks)
            return analysis

        elif method == "rea.match_functions":
            func1 = params.get("func1", {})
            func2 = params.get("func2", {})
            v1 = PcodeVectorizer.vectorize_high_function(func1.get("pcode_ops", []), func1.get("basic_blocks", []))
            v2 = PcodeVectorizer.vectorize_high_function(func2.get("pcode_ops", []), func2.get("basic_blocks", []))
            match_res = PcodeFunctionMatcher.match_vectors(v1, v2)
            return match_res

        elif method == "rea.inject_crash_rca":
            rca_report = params.get("rca_report", {})
            return self.inject_crash_rca(rca_report)

        elif method == "rea.inject_vad_snapshot":
            vad_snapshot = params.get("vad_snapshot", {})
            return self.inject_vad_snapshot(vad_snapshot)

        elif method == "rea.inject_etw_timeline":
            timeline_report = params.get("timeline_report", {})
            return self.inject_etw_timeline(timeline_report)

        elif method == "rea.inject_structure_dissection":
            struct_report = params.get("struct_report", {})
            return self.inject_structure_dissection(struct_report)

        elif method == "rea.inject_pointer_chains":
            pointer_report = params.get("pointer_report", {})
            return self.inject_pointer_chains(pointer_report)

        elif method in ("shutdown", "stop"):
            def _delayed_stop():
                time.sleep(0.1)
                self.stop()
            threading.Thread(target=_delayed_stop, daemon=True).start()
            return {"status": "stopping", "port": self.port}

        else:
            raise ValueError(f"Unknown RPC method: '{method}'")

    def is_client_connected(self) -> bool:
        if not self.last_client_heartbeat:
            return False
        # Consider connected if heartbeat received within last 15 seconds
        return (time.time() - self.last_client_heartbeat) < 15.0

    def queue_command(self, action: str, details: Dict[str, Any]) -> None:
        """Pushes an annotation or mutation command into the bounded queue for Ghidra to poll."""
        with self._queue_lock:
            if len(self._command_queue) >= self._max_queue_size:
                self._command_queue.pop(0)
                self._queue_overflow_count += 1
            self._command_queue.append({
                "action": action,
                "timestamp": time.time(),
                "details": details
            })

    # High-Level Diagnostic Injection Methods
    def inject_crash_rca(self, rca_report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translates a Phase 2 Crash RCA Report into live Ghidra annotations:
        1. Plate Comment with root-cause attribution at faulting RVA.
        2. Bookmark at faulting RVA (Category: REA_CRASH_FAULT).
        3. Renames faulting function to prefix 'FAULT_' if deterministic.
        """
        fault_rva = rca_report.get("fault_rva", "0x0")
        root_cause = rca_report.get("root_cause_classification", "UNKNOWN")
        culprit_reg = rca_report.get("culprit_register")
        culprit_val = rca_report.get("culprit_register_value")
        target_addr = rca_report.get("target_address", "0x0")
        advice = rca_report.get("remediation_advice", "")

        comment_lines = [
            f"[REA-Neural CRASH RCA]: {rca_report.get('exception_name')} ({rca_report.get('exception_code')})",
            f"Root Cause: {root_cause} (Confidence: {rca_report.get('confidence')})",
            f"Target Address: {target_addr} ({rca_report.get('access_type')} violation)",
        ]
        if culprit_reg:
            comment_lines.append(f"Culprit Register: {culprit_reg} = {culprit_val}")
        if advice:
            comment_lines.append(f"Remediation: {advice}")

        full_comment = "\n".join(comment_lines)

        # 1. Queue Plate Comment (Crash RCA fault_rva is explicitly module RVA)
        self.queue_command("SET_PLATE_COMMENT", {
            "address": fault_rva,
            "address_space": "rva",
            "comment": full_comment
        })

        # 2. Queue Bookmark
        self.queue_command("CREATE_BOOKMARK", {
            "address": fault_rva,
            "address_space": "rva",
            "category": "REA_CRASH_FAULT",
            "description": f"{root_cause} on target {target_addr}"
        })

        return {
            "status": "queued",
            "fault_rva": fault_rva,
            "actions_queued": 2,
            "root_cause": root_cause
        }

    def inject_vad_snapshot(self, vad_snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translates Phase 1 VAD Memory Map into Ghidra annotations and external block references.
        """
        summary = vad_snapshot.get("summary", {})
        proc_name = vad_snapshot.get("process_name", "target.exe")
        note = (
            f"[REA-Neural VAD MAP]: Process `{proc_name}` (PID {vad_snapshot.get('pid')})\n"
            f"Commit: {summary.get('commit_mb')} MB | Image: {summary.get('image_mb')} MB | Heap: {summary.get('heap_mb')} MB\n"
            f"W^X Violations: {summary.get('wx_regions_count')} | Contiguous Regions: {summary.get('total_regions')}"
        )
        self.queue_command("SET_PROGRAM_NOTE", {
            "title": "REA_VAD_SPATIAL_LAYOUT",
            "content": note
        })
        return {"status": "queued", "note_length": len(note)}

    def inject_etw_timeline(self, timeline_report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translates Phase 3 ETW Timeline Correlation into Ghidra pre-crash audit notes.
        """
        verdict = timeline_report.get("temporal_verdict", "UNKNOWN")
        findings = timeline_report.get("causality_findings", [])
        desc = "; ".join(f"{f.get('category')}: {f.get('description')}" for f in findings)
        note = (
            f"[REA-Neural ETW TIMELINE]: Verdict `{verdict}`\n"
            f"Findings: {desc if desc else 'Stable execution prior to fault'}\n"
            f"Events Evaluated: {timeline_report.get('events_count', 0)}"
        )
        self.queue_command("SET_PROGRAM_NOTE", {
            "title": "REA_ETW_PRE_CRASH_TIMELINE",
            "content": note
        })
        return {"status": "queued", "verdict": verdict}

    def inject_structure_dissection(self, struct_report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translates a runtime Structure Dissection report into Ghidra annotations and composite data types:
        1. Queues APPLY_DATA_STRUCTURE with reconstructed C declaration and fields.
        2. Queues CREATE_BOOKMARK at structure base address (Category: REA_STRUCT_DISSECTION).
        3. Queues SET_PROGRAM_NOTE with the full C struct code.
        """
        base_addr = struct_report.get("base_address", "0x0")
        c_decl = struct_report.get("c_struct_definition", "")
        fields = struct_report.get("fields", [])
        size = struct_report.get("size_analyzed", 0)
        clean_addr = str(base_addr).lower().replace("0x", "").lstrip("0") or "0"
        struct_name = struct_report.get("structure_name") or f"Reconstructed_0x{clean_addr.upper()}"

        addr_space = struct_report.get("address_space", "va")

        # 1. Queue APPLY_DATA_STRUCTURE
        self.queue_command("APPLY_DATA_STRUCTURE", {
            "address": base_addr,
            "address_space": addr_space,
            "name": struct_name,
            "c_declaration": c_decl,
            "fields": fields,
            "size": size,
            "heuristic": bool(struct_report.get("heuristic", True)),
        })

        # 2. Queue Bookmark
        self.queue_command("CREATE_BOOKMARK", {
            "address": base_addr,
            "address_space": addr_space,
            "category": "REA_STRUCT_DISSECTION",
            "description": f"Reconstructed struct {struct_name} ({len(fields)} fields, {size} bytes, heuristic)"
        })

        # 3. Queue Program Note
        self.queue_command("SET_PROGRAM_NOTE", {
            "title": f"REA_STRUCT_{struct_name}",
            "content": c_decl or f"// Reconstructed struct at {base_addr} ({len(fields)} fields)"
        })

        return {
            "status": "queued",
            "base_address": base_addr,
            "structure_name": struct_name,
            "fields_count": len(fields),
            "actions_queued": 3
        }

    def inject_pointer_chains(self, pointer_report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translates a runtime Pointer Scan report into Ghidra annotations:
        1. Plate comments and bookmarks at static module pointer roots.
        2. Program Note summarizing all discovered multi-level pointer paths.
        """
        target_addr = pointer_report.get("target_address", "0x0")
        paths = pointer_report.get("paths", [])
        queued_count = 0

        note_lines = [
            f"[REA-Neural Pointer Scanner Paths]: Target = {target_addr}",
            f"Discovered Paths Count: {len(paths)}",
            "-----------------------------------------------------------------"
        ]

        for p in paths[:10]:
            rva = p.get("base_rva", "0x0")
            expr = p.get("expression", "")
            mod = p.get("base_module", "target.exe")
            offsets = p.get("offsets", [])
            depth = p.get("depth", 1)

            note_lines.append(f"Depth {depth}: {expr} => {target_addr}")

            # 1. Queue Plate comment at static base RVA
            self.queue_command("SET_PLATE_COMMENT", {
                "address": rva,
                "address_space": "rva",
                "module": mod,
                "comment": f"[REA Pointer Root]: Points to target {target_addr}\nExpression: {expr}\nModule: {mod}"
            })

            # 2. Queue Bookmark at static base RVA
            self.queue_command("CREATE_BOOKMARK", {
                "address": rva,
                "address_space": "rva",
                "module": mod,
                "category": "REA_POINTER_ROOT",
                "description": f"Root for {target_addr} via {expr}"
            })
            queued_count += 2

        if paths:
            clean_tgt = str(target_addr).replace("0x", "")
            self.queue_command("SET_PROGRAM_NOTE", {
                "title": f"REA_POINTER_PATHS_{clean_tgt}",
                "content": "\n".join(note_lines)
            })
            queued_count += 1

        return {
            "status": "queued",
            "target_address": target_addr,
            "paths_queued": len(paths[:10]),
            "actions_queued": queued_count
        }


class GhidraLiveBridgeClient:
    """Python client for interacting with a running GhidraLiveBridgeServer."""

    def __init__(self, bridge_url: str = f"http://127.0.0.1:{DEFAULT_BRIDGE_PORT}", auth_token: Optional[str] = None):
        self.bridge_url = bridge_url
        self.auth_token = auth_token

    def call_rpc(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        import urllib.request
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": int(time.time() * 1000)
        }
        if self.auth_token and "auth_token" not in payload["params"]:
            payload["params"]["auth_token"] = self.auth_token

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.bridge_url,
            data=data,
            headers={"Content-Type": "application/json", "X-REA-Auth-Token": self.auth_token or ""}
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            raw = resp.read()
            res_obj = json.loads(raw.decode("utf-8"))
            if "error" in res_obj:
                raise RuntimeError(f"Ghidra Bridge Error [{res_obj['error'].get('code')}]: {res_obj['error'].get('message')}")
            return res_obj.get("result")

    def ping(self) -> Dict[str, Any]:
        return self.call_rpc("ping")

    def get_status(self) -> Dict[str, Any]:
        return self.call_rpc("get_status")

    def register_client(self, program_name: str, image_base: str, architecture: str, ghidra_version: str = "12.x") -> Dict[str, Any]:
        return self.call_rpc("ghidra.register_client", {
            "program_name": program_name,
            "image_base": image_base,
            "architecture": architecture,
            "ghidra_version": ghidra_version
        })

    def poll_commands(self) -> Dict[str, Any]:
        return self.call_rpc("ghidra.poll_commands")

    def inject_crash_rca(self, rca_report: Dict[str, Any]) -> Dict[str, Any]:
        return self.call_rpc("rea.inject_crash_rca", {"rca_report": rca_report})

    def inject_vad_snapshot(self, vad_snapshot: Dict[str, Any]) -> Dict[str, Any]:
        return self.call_rpc("rea.inject_vad_snapshot", {"vad_snapshot": vad_snapshot})

    def inject_etw_timeline(self, timeline_report: Dict[str, Any]) -> Dict[str, Any]:
        return self.call_rpc("rea.inject_etw_timeline", {"timeline_report": timeline_report})

    def inject_structure_dissection(self, struct_report: Dict[str, Any]) -> Dict[str, Any]:
        return self.call_rpc("rea.inject_structure_dissection", {"struct_report": struct_report})

    def inject_pointer_chains(self, pointer_report: Dict[str, Any]) -> Dict[str, Any]:
        return self.call_rpc("rea.inject_pointer_chains", {"pointer_report": pointer_report})


_GLOBAL_BRIDGE_SERVER: Optional[GhidraLiveBridgeServer] = None


def get_or_create_bridge(
    port: int = DEFAULT_BRIDGE_PORT,
    auth_token: Optional[str] = None,
    publish_temp_marker: bool = True,
) -> GhidraLiveBridgeServer:
    """Returns the active bridge server instance, or creates and starts a new one."""
    global _GLOBAL_BRIDGE_SERVER
    if _GLOBAL_BRIDGE_SERVER is None or not _GLOBAL_BRIDGE_SERVER.is_running:
        _GLOBAL_BRIDGE_SERVER = GhidraLiveBridgeServer(port=port, auth_token=auth_token)
        _GLOBAL_BRIDGE_SERVER.start(publish_temp_marker=publish_temp_marker)
    return _GLOBAL_BRIDGE_SERVER


def get_active_bridge() -> Optional[GhidraLiveBridgeServer]:
    """Returns the running bridge server instance if any."""
    global _GLOBAL_BRIDGE_SERVER
    return _GLOBAL_BRIDGE_SERVER


def _read_trusted_marker_file(marker_path: str) -> Optional[Dict[str, Any]]:
    """Reads a bridge discovery marker safely without following symlinks and verifying ownership on POSIX."""
    if not os.path.isfile(marker_path) or os.path.islink(marker_path):
        return None
    try:
        if hasattr(os, "O_NOFOLLOW"):
            flags = os.O_RDONLY | os.O_NOFOLLOW
            fd = os.open(marker_path, flags)
            try:
                st = os.fstat(fd)
                if hasattr(os, "getuid") and st.st_uid != os.getuid():
                    return None
                with os.fdopen(fd, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                try:
                    os.close(fd)
                except OSError:
                    pass
                return None
        else:
            with open(marker_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("port"), int):
            return data
    except Exception:
        return None
    return None


def resolve_bridge_marker() -> Optional[Dict[str, Any]]:
    """Resolves active bridge discovery marker from trusted workspace or verified tempdir locations."""
    scope = ExecutionGuard.get_current_scope()
    default_ws = os.path.join(os.path.expanduser("~"), ".rea_neural", "workspace")
    ws_dir = scope.workspace_dir if scope else default_ws
    candidates = [
        os.path.join(ws_dir, ".rea_bridge.json"),
        os.path.join(tempfile.gettempdir(), ".rea_bridge.json"),
        os.path.join(default_ws, ".rea_bridge.json"),
    ]
    seen = set()
    for c in candidates:
        norm = os.path.normcase(os.path.abspath(c))
        if norm in seen:
            continue
        seen.add(norm)
        data = _read_trusted_marker_file(c)
        if data is not None:
            return data
    return None


def stop_active_bridge(port: Optional[int] = None, auth_token: Optional[str] = None) -> Dict[str, Any]:
    """Stops the running bridge server locally or across process boundaries via RPC shutdown."""
    global _GLOBAL_BRIDGE_SERVER
    if _GLOBAL_BRIDGE_SERVER and _GLOBAL_BRIDGE_SERVER.is_running:
        res = _GLOBAL_BRIDGE_SERVER.stop()
        _GLOBAL_BRIDGE_SERVER = None
        return res

    marker = resolve_bridge_marker()
    target_port = port or (marker.get("port") if marker else DEFAULT_BRIDGE_PORT)
    token = auth_token or (marker.get("auth_token") if marker else None)

    try:
        client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{target_port}", auth_token=token)
        return client.call_rpc("shutdown")
    except Exception as e:
        return {"status": "not_running", "error": str(e)}

