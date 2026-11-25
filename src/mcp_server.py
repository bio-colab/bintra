#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bintra Native Model Context Protocol (MCP) Server.
Standard JSON-RPC 2.0 stdio server providing agent-native reverse engineering
tools for AI models (Antigravity, Claude Code, Codex, Cursor, Devin, etc.).

Zero external dependencies: runs on Python standard library + numpy.
Protocol Version: 2024-11-05
"""

import os
import sys
import json
import traceback
from token_telemetry import (
    TokenSessionTracker,
    compact_tool_schema,
    estimate_tokens,
    prune_payload,
)
from typing import Dict, Any, List, Optional
from pathlib import Path

# Add src to sys.path
SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

SERVER_NAME = "bintra"
SERVER_VERSION = "1.1.0"
PROTOCOL_VERSION = "2024-11-05"
SUPPORTED_PROTOCOL_VERSIONS = [
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    "2025-11-25",
    "2026-07-28",
]
LATEST_PROTOCOL_VERSION = "2026-07-28"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"


from bintra_mcp.tool_schemas import TOOLS_REGISTRY  # noqa: E402,F401  (public re-export)
from bintra_mcp.tools import (  # noqa: E402
    TOOL_HANDLERS, BinaryToolsMixin, DevicesToolsMixin, ForensicsToolsMixin, GhidraToolsMixin,
    RuntimeTelemetryToolsMixin, WeightsToolsMixin, WindowsHostToolsMixin,
)


class BintraMcpServer(
    BinaryToolsMixin, WeightsToolsMixin, GhidraToolsMixin, WindowsHostToolsMixin,
    DevicesToolsMixin, RuntimeTelemetryToolsMixin, ForensicsToolsMixin,
):
    """Standard MCP Stdio JSON-RPC Server."""

    def __init__(
        self,
        workspace_root: Optional[str] = None,
        allowed_workspace_roots: Optional[List[str]] = None,
    ):
        self.handlers = {
            "initialize": self.handle_initialize,
            "notifications/initialized": self.handle_initialized_notification,
            "server/discover": self.handle_server_discover,
            "mcp/discover": self.handle_server_discover,
            "discovery": self.handle_server_discover,
            "tools/list": self.handle_tools_list,
            "tools/call": self.handle_tools_call,
            "resources/list": self.handle_resources_list,
            "resources/read": self.handle_resources_read,
            "prompts/list": self.handle_prompts_list,
            "prompts/get": self.handle_prompts_get,
            "ping": self.handle_ping,
        }
        self._tool_schemas = {
            t["name"]: t.get("inputSchema", {})
            for t in TOOLS_REGISTRY
        }
        self.token_tracker = TokenSessionTracker(model=os.environ.get("BINTRA_MODEL_PRICING", "claude-3.5-sonnet"))
        from security import PathIdentity, TargetScope, AuditLogger
        AuditLogger.ensure_chain_continuity(rotate_on_corrupt=True)
        default_ws = os.path.join(os.path.expanduser("~"), ".bintra", "workspace")
        chosen_ws = workspace_root or os.environ.get("BINTRA_MCP_WORKSPACE") or default_ws
        os.makedirs(chosen_ws, exist_ok=True)
        can_host_ws = PathIdentity.canonicalize(chosen_ws)
        unsafe_reason = TargetScope._is_unsafe_workspace_root(can_host_ws)
        if unsafe_reason:
            raise PermissionError(
                f"UNSAFE_WORKSPACE_ROOT ({unsafe_reason}): Host MCP workspace '{can_host_ws}' is unsafe."
            )
        self._host_workspace = can_host_ws

        raw_allowed = [can_host_ws]
        if allowed_workspace_roots:
            raw_allowed.extend(allowed_workspace_roots)
        env_allowed = os.environ.get("BINTRA_MCP_ALLOWED_WORKSPACES", "")
        if env_allowed:
            raw_allowed.extend([p.strip() for p in env_allowed.split(os.pathsep) if p.strip()])
        self._allowed_workspace_roots: List[str] = []
        for root in raw_allowed:
            if not root:
                continue
            can_root = PathIdentity.canonicalize(root)
            if not TargetScope._is_unsafe_workspace_root(can_root) and can_root not in self._allowed_workspace_roots:
                self._allowed_workspace_roots.append(can_root)

    def _resolve_server_workspace(self, args: Dict[str, Any]) -> str:
        """
        Derives the active workspace server-side.
        Rejects untrusted client-supplied workspace_dir overrides unless explicitly
        inside host-authorized workspace roots.
        """
        from security import PathIdentity, SecurityViolationError, AuditLogger, TargetScope
        client_ws = args.get("workspace_dir") or args.get("workspace")
        if not client_ws:
            return self._host_workspace
        try:
            can_client_ws = PathIdentity.canonicalize(str(client_ws))
        except Exception as exc:
            raise SecurityViolationError(f"UNTRUSTED_WORKSPACE_OVERRIDE: Invalid workspace '{client_ws}': {exc}")

        if not TargetScope._is_unsafe_workspace_root(can_client_ws):
            for allowed_root in self._allowed_workspace_roots:
                if PathIdentity.is_same_file(can_client_ws, allowed_root) or PathIdentity.is_within_directory(can_client_ws, allowed_root):
                    return can_client_ws

        AuditLogger.log_decision(
            component="mcp_server",
            operation="workspace_override",
            target=str(client_ws),
            decision="DENY",
            reason="UNTRUSTED_WORKSPACE_OVERRIDE",
            requested_capability="cap.workspace.write",
            result="DENIED",
        )
        raise SecurityViolationError(
            f"UNTRUSTED_WORKSPACE_OVERRIDE: Client-supplied workspace '{client_ws}' is not authorized by host MCP configuration."
        )

    @staticmethod
    def _matches_json_type(val: Any, json_type: Any) -> bool:
        types = json_type if isinstance(json_type, (list, tuple)) else [json_type]
        for t in types:
            if t == "string" and isinstance(val, str):
                return True
            if t == "integer" and isinstance(val, int) and not isinstance(val, bool):
                return True
            if t == "number" and isinstance(val, (int, float)) and not isinstance(val, bool):
                return True
            if t == "boolean" and isinstance(val, bool):
                return True
            if t == "array" and isinstance(val, list):
                return True
            if t == "object" and isinstance(val, dict):
                return True
            if t == "null" and val is None:
                return True
        return False

    def _validate_tool_arguments(self, tool_name: str, args: Any) -> None:
        """Validates tool arguments strictly against declared JSON inputSchema (required, types, enums, and no unknown fields)."""
        if args is None:
            args = {}
        if not isinstance(args, dict):
            raise ValueError(f"Invalid arguments for '{tool_name}': expected JSON object matching inputSchema.")
        schema = self._tool_schemas.get(tool_name)
        if not schema:
            return
        required = schema.get("required", [])
        missing = [req for req in required if req not in args or args[req] is None]
        if missing:
            raise ValueError(
                f"Missing required parameter(s) for '{tool_name}': {', '.join(missing)}."
            )
        props = schema.get("properties", {})
        unknown = [k for k in args.keys() if k not in props and k not in ("workspace_dir", "compact", "summary_only", "max_list_items")]
        if unknown:
            raise ValueError(
                f"Unknown parameter(s) for '{tool_name}': {', '.join(sorted(unknown))}."
            )
        for key, val in args.items():
            if key not in props or val is None:
                continue
            spec = props[key]
            expected_type = spec.get("type")
            if expected_type and not self._matches_json_type(val, expected_type):
                raise ValueError(
                    f"Invalid type for parameter '{key}' in '{tool_name}': "
                    f"expected {expected_type}, got {type(val).__name__}."
                )
            if expected_type == "array" and isinstance(spec.get("items"), dict) and spec["items"].get("type"):
                item_type = spec["items"]["type"]
                for idx, elem in enumerate(val):
                    if not self._matches_json_type(elem, item_type):
                        raise ValueError(
                            f"Invalid item type at '{key}[{idx}]' in '{tool_name}': "
                            f"expected {item_type}, got {type(elem).__name__}."
                        )
            allowed = spec.get("enum")
            if allowed and val not in allowed:
                raise ValueError(
                    f"Invalid value for parameter '{key}' in '{tool_name}': "
                    f"expected one of {allowed}, got {val!r}."
                )

    def handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        req_ver = None
        if isinstance(params, dict):
            req_ver = params.get("io.modelcontextprotocol/protocolVersion") or params.get("protocolVersion")
        if req_ver is not None:
            if req_ver in SUPPORTED_PROTOCOL_VERSIONS:
                negotiated_version = req_ver
            else:
                # Per MCP 2026-07-28 specification: explicitly reject unsupported protocol versions!
                raise ValueError(
                    f"Unsupported protocol version: '{req_ver}'. "
                    f"Supported versions: {SUPPORTED_PROTOCOL_VERSIONS}"
                )
        else:
            negotiated_version = DEFAULT_PROTOCOL_VERSION

        return {
            "protocolVersion": negotiated_version,
            "supportedProtocolVersions": list(SUPPORTED_PROTOCOL_VERSIONS),
            "capabilities": {
                "tools": {
                    "listChanged": False
                },
                "resources": {
                    "subscribe": False,
                    "listChanged": False
                },
                "prompts": {
                    "listChanged": False
                }
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION
            }
        }

    def handle_server_discover(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Stateless MCP 2026-07-28 server discovery handler."""
        return {
            "name": SERVER_NAME,
            "version": SERVER_VERSION,
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "supportedProtocolVersions": list(SUPPORTED_PROTOCOL_VERSIONS),
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {"subscribe": False, "listChanged": False},
                "prompts": {"listChanged": False},
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION,
            },
        }

    def handle_initialized_notification(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return None

    def handle_ping(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {}

    MCP_TOOL_PROFILES = {
        "core": {
            "bintra_triage_binary", "bintra_inspect_binary", "bintra_pe_deep_forensics",
            "bintra_sensory_audit", "bintra_deobfuscate_binary", "bintra_binary_diff",
            "bintra_list_capabilities",
        },
        "static": {
            "bintra_triage_binary", "bintra_inspect_binary", "bintra_pe_deep_forensics",
            "bintra_deobfuscate_binary", "bintra_dump_bytes", "bintra_match_functions",
            "bintra_scan_hybrid", "bintra_sensory_audit", "bintra_binary_diff",
            "bintra_patch_binary", "bintra_list_capabilities",
        },
        "ghidra": {
            "bintra_ghidra_analyze", "bintra_ghidra_headless", "bintra_ghidra_live_bridge",
            "bintra_ghidra_call_graph", "bintra_ghidra_data_flow", "bintra_ghidra_similar_functions",
            "bintra_match_pcode", "bintra_deobfuscate_pcode", "bintra_fuse_evidence",
            "bintra_list_capabilities",
        },
        "neural": {
            "bintra_sensory_audit", "bintra_scan_hybrid", "bintra_wsp_audit",
            "bintra_patch_weights", "bintra_list_capabilities",
        },
    }

    TOOLS_LIST_PAGE_SIZE = 25

    def handle_tools_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        params = params or {}
        profile = (params.get("profile") or os.environ.get("BINTRA_MCP_PROFILE", "all")).lower()
        compact = (
            bool(params["compact"])
            if "compact" in params
            else (os.environ.get("BINTRA_MCP_COMPACT_SCHEMAS") == "1")
        )
        tools = TOOLS_REGISTRY
        if profile in self.MCP_TOOL_PROFILES:
            allowed = self.MCP_TOOL_PROFILES[profile]
            tools = [t for t in TOOLS_REGISTRY if t["name"] in allowed]
        elif profile == "windows":
            tools = [t for t in TOOLS_REGISTRY if t["name"] not in self.MCP_TOOL_PROFILES["neural"] or t["name"] == "bintra_list_capabilities"]

        # MCP 2025-06-18 pagination: when the client supplies an opaque cursor,
        # serve a fixed-size page and advertise nextCursor while more tools remain.
        # Without a cursor the full (possibly profile-filtered) list is returned in
        # one page for backward compatibility with older clients.
        offset = 0
        cursor = params.get("cursor")
        if cursor is not None:
            if not isinstance(cursor, str) or not cursor.isdigit():
                raise ValueError(
                    f"Invalid tools/list cursor: {cursor!r}. Use the opaque nextCursor value returned by a previous page."
                )
            offset = int(cursor)
            if offset < 0 or offset >= len(tools):
                raise ValueError(f"tools/list cursor out of range: {cursor!r}")
        page = tools[offset : offset + self.TOOLS_LIST_PAGE_SIZE] if cursor is not None else tools
        next_offset = offset + self.TOOLS_LIST_PAGE_SIZE if cursor is not None else 0

        enriched_tools = []
        for t in page:
            item = compact_tool_schema(t) if compact else dict(t)
            item["annotations"] = self._derive_tool_annotations(item["name"])
            enriched_tools.append(item)

        base_tok = estimate_tokens(TOOLS_REGISTRY)
        act_tok = estimate_tokens(enriched_tools)
        self.token_tracker.record_schema_footprint(act_tok, base_tok)
        result: Dict[str, Any] = {
            "tools": enriched_tools
        }
        if cursor is not None and next_offset < len(tools):
            result["nextCursor"] = str(next_offset)
        return result

    @classmethod
    def _derive_tool_annotations(cls, tool_name: str) -> Dict[str, Any]:
        """Derives authoritative MCP Tool Annotations from TOOL_SECURITY_METADATA."""
        sec = cls.TOOL_SECURITY_METADATA.get(tool_name, ("cap.file.read", "READ", None))
        cap_val, mode, _ = sec
        is_read_only = mode in ("READ", "QUERY") and cap_val not in (
            "cap.workspace.write", "cap.ghidra.headless_exec", "cap.ghidra.project_mutate", "cap.binary.patch"
        )
        is_destructive = not is_read_only and (
            cap_val in ("cap.workspace.write", "cap.ghidra.project_mutate", "cap.binary.patch")
            or any(kw in tool_name for kw in ("patch", "modify", "mutate"))
        )
        return {
            "readOnlyHint": is_read_only,
            "destructiveHint": is_destructive,
            "idempotentHint": is_read_only,
            "openWorldHint": False,
        }

    MCP_RESOURCES: List[Dict[str, Any]] = [
        {
            "uri": "bintra://capabilities",
            "name": "Bintra Capability Catalog",
            "description": "Live platform-aware manifest of all registered Bintra MCP tools, capabilities, and workflows.",
            "mimeType": "application/json",
        },
        {
            "uri": "bintra://security/policy",
            "name": "Bintra Security Kernel Policy",
            "description": "Active workspace boundary, prohibited hazard capabilities, and component capability grants.",
            "mimeType": "application/json",
        },
        {
            "uri": "bintra://telemetry/session",
            "name": "Bintra Token Efficiency Telemetry",
            "description": "Current MCP session token footprint, call count, and token savings summary.",
            "mimeType": "application/json",
        },
        {
            "uri": "bintra://workflows/playbooks",
            "name": "Bintra Reverse Engineering Playbooks",
            "description": "Structured multi-tool workflows for PE triage, crash RCA, Ghidra analysis, and Windows auditing.",
            "mimeType": "application/json",
        },
    ]

    MCP_PROMPTS: List[Dict[str, Any]] = [
        {
            "name": "triage_pe_binary",
            "description": "Run a complete read-only triage of a Windows PE binary combining headers, .pdata/RTTI/PDB, digital signature trust, obfuscation, and optional crash/Ghidra correlation.",
            "arguments": [
                {"name": "file_path", "description": "Absolute path to the target binary (.exe, .dll, .sys)", "required": True},
                {"name": "dmp_path", "description": "Optional MiniDump (.dmp) file path", "required": False},
                {"name": "ghidra_export_path", "description": "Optional Ghidra export (.json/.jsonl/.db) path", "required": False},
            ],
        },
        {
            "name": "root_cause_crash",
            "description": "Correlate a Windows MiniDump (.dmp) crash with static PE forensics and Ghidra call-graph/data-flow evidence.",
            "arguments": [
                {"name": "dmp_path", "description": "Path to MiniDump (.dmp) file", "required": True},
                {"name": "binary_path", "description": "Optional faulting binary path", "required": False},
                {"name": "ghidra_export_path", "description": "Optional Ghidra export path", "required": False},
            ],
        },
        {
            "name": "audit_windows_host",
            "description": "Perform a read-only Windows host security, driver, service, and telemetry audit.",
            "arguments": [
                {"name": "focus", "description": "Audit domain: all, drivers, network, processes, or registry", "required": False},
            ],
        },
        {
            "name": "diff_binary_versions",
            "description": "Compare two versions of a binary semantically using WL-CFG hashing, P-Code behavior vectors, and API anchors.",
            "arguments": [
                {"name": "baseline_path", "description": "Path to baseline binary or Ghidra export", "required": True},
                {"name": "target_path", "description": "Path to target binary or Ghidra export", "required": True},
            ],
        },
        {
            "name": "audit_neural_weights",
            "description": "Zero-execution security audit of neural weights embedded in a binary or shipped as a Safetensors model: outlier-neuron trojan detection, spectral effective rank, and surgical amenability.",
            "arguments": [
                {"name": "target_path", "description": "Path to the hybrid binary or .safetensors model to audit", "required": True},
                {"name": "scan_embedded", "description": "First run hybrid embedded-AI scanning on a PE binary (default true)", "required": False},
            ],
        },
    ]

    def handle_resources_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {"resources": list(self.MCP_RESOURCES)}

    def handle_resources_read(self, params: Dict[str, Any]) -> Dict[str, Any]:
        uri = (params or {}).get("uri")
        if not uri or not isinstance(uri, str):
            raise ValueError("Missing required parameter 'uri' for resources/read.")

        if uri == "bintra://capabilities":
            payload = self.dispatch_tool("bintra_list_capabilities", {"platform_filter": "all"})
        elif uri == "bintra://security/policy":
            from security.capability_registry import PROHIBITED_HAZARDS, CapabilityRegistry
            payload = {
                "host_workspace": self._host_workspace,
                "allowed_workspace_roots": list(self._allowed_workspace_roots),
                "prohibited_hazards": sorted(h.value for h in PROHIBITED_HAZARDS),
                "registered_components_count": len(CapabilityRegistry.COMPONENT_CAPABILITIES),
                "target_immutability": True,
            }
        elif uri == "bintra://telemetry/session":
            payload = self.token_tracker.summary()
        elif uri == "bintra://workflows/playbooks":
            payload = {
                "playbooks": {
                    "unified_binary_triage": ["bintra_triage_binary"],
                    "static_pe_deep_audit": ["bintra_inspect_binary", "bintra_pe_deep_forensics", "bintra_deobfuscate_binary", "bintra_scan_hybrid", "bintra_sensory_audit"],
                    "ghidra_deep_re": ["bintra_ghidra_analyze", "bintra_ghidra_call_graph", "bintra_ghidra_data_flow", "bintra_ghidra_similar_functions"],
                    "crash_root_cause_fusion": ["bintra_dmp_inspect", "bintra_crash_rca", "bintra_pe_deep_forensics", "bintra_fuse_evidence"],
                    "differential_binary_audit": ["bintra_binary_diff", "bintra_match_functions", "bintra_match_pcode", "bintra_ghidra_similar_functions"],
                    "windows_host_audit": ["bintra_windows_env_audit", "bintra_driver_audit", "bintra_service_audit", "bintra_network_connections"],
                }
            }
        else:
            raise ValueError(f"Unknown Bintra MCP resource URI: '{uri}'.")

        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": json.dumps(payload, indent=2, ensure_ascii=False),
                }
            ]
        }

    def handle_prompts_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {"prompts": list(self.MCP_PROMPTS)}

    def handle_prompts_get(self, params: Dict[str, Any]) -> Dict[str, Any]:
        params = params or {}
        name = params.get("name")
        p_args = params.get("arguments") or {}
        if not name or not isinstance(name, str):
            raise ValueError("Missing required parameter 'name' for prompts/get.")

        if name == "triage_pe_binary":
            fp = p_args.get("file_path")
            if not fp:
                raise ValueError("Prompt 'triage_pe_binary' requires argument 'file_path'.")
            extra = []
            if p_args.get("dmp_path"):
                extra.append(f"dmp_path='{p_args['dmp_path']}'")
            if p_args.get("ghidra_export_path"):
                extra.append(f"ghidra_export_path='{p_args['ghidra_export_path']}'")
            extra_str = (", " + ", ".join(extra)) if extra else ""
            text = (
                f"Perform a read-only Bintra binary triage on '{fp}'. "
                f"Start by calling bintra_triage_binary(file_path='{fp}'{extra_str}). "
                f"Report observed facts separately from heuristic indicators, include digital signature trust status, "
                f"and recommend concrete next tools if obfuscation or missing symbols are detected."
            )
        elif name == "root_cause_crash":
            dp = p_args.get("dmp_path")
            if not dp:
                raise ValueError("Prompt 'root_cause_crash' requires argument 'dmp_path'.")
            bp = p_args.get("binary_path", "")
            gp = p_args.get("ghidra_export_path", "")
            text = (
                f"Investigate the Windows crash dump at '{dp}'. "
                f"Run bintra_dmp_inspect and bintra_crash_rca on '{dp}', then fuse evidence with "
                f"bintra_fuse_evidence(dmp_path='{dp}', binary_path='{bp}', ghidra_export_path='{gp}'). "
                f"Distinguish confirmed faulting module/RVA facts from root-cause hypotheses."
            )
        elif name == "audit_windows_host":
            focus = p_args.get("focus", "all")
            text = (
                f"Run a read-only Windows host audit focused on '{focus}'. "
                f"Use bintra_windows_env_audit alongside relevant introspection tools "
                f"(bintra_driver_audit, bintra_service_audit, bintra_network_connections, bintra_registry_audit). "
                f"Flag any non-Windows degradation explicitly instead of guessing host state."
            )
        elif name == "diff_binary_versions":
            b_path = p_args.get("baseline_path")
            t_path = p_args.get("target_path")
            if not b_path or not t_path:
                raise ValueError("Prompt 'diff_binary_versions' requires 'baseline_path' and 'target_path'.")
            text = (
                f"Perform a semantic binary differential analysis between baseline '{b_path}' and target '{t_path}'. "
                f"Call bintra_binary_diff(baseline_path='{b_path}', target_path='{t_path}') and summarize added, "
                f"removed, and behaviorally modified routines."
            )
        elif name == "audit_neural_weights":
            tp = p_args.get("target_path")
            if not tp:
                raise ValueError("Prompt 'audit_neural_weights' requires argument 'target_path'.")
            text = (
                f"Audit the neural inference logic at '{tp}' without executing it. "
                f"If it is a PE binary, first call bintra_scan_hybrid(file_path='{tp}') to enumerate embedded AI "
                f"assets (ONNX, TFLite, DirectML, GGUF), then call bintra_wsp_audit(model_path='{tp}') when a "
                f"Safetensors-compatible tensor store is present. Report trojan/outlier-neuron indicators, "
                f"spectral effective rank, and whether selective column surgery (bintra_patch_weights) is "
                f"indicated. Separate measured facts from heuristic indicators."
            )
        else:
            raise ValueError(f"Unknown Bintra MCP prompt: '{name}'.")

        return {
            "description": next((p["description"] for p in self.MCP_PROMPTS if p["name"] == name), ""),
            "messages": [
                {
                    "role": "user",
                    "content": {"type": "text", "text": text},
                }
            ],
        }

    TOOL_SECURITY_METADATA = {
        "bintra_inspect_binary": ("cap.file.read", "READ", "file_path"),
        "bintra_deobfuscate_binary": ("cap.file.read", "READ", "file_path"),
        "bintra_dump_bytes": ("cap.file.read", "READ", "file_path"),
        "bintra_match_functions": ("cap.file.read", "READ", None),
        "bintra_patch_binary": ("cap.workspace.write", "WRITE", "output_path"),
        "bintra_scan_hybrid": ("cap.file.read", "READ", "file_path"),
        "bintra_sensory_audit": ("cap.file.read", "READ", "file_path"),
        "bintra_match_pcode": ("cap.file.read", "READ", None),
        "bintra_deobfuscate_pcode": ("cap.file.read", "READ", None),
        "bintra_ghidra_analyze": ("cap.file.read", "READ", "input_file"),
        "bintra_ghidra_headless": ("cap.ghidra.headless_exec", "EXECUTE", "binary_path"),
        "bintra_windows_env_audit": ("cap.registry.read", "READ", "file_path"),
        "bintra_resolve_dependencies": ("cap.file.read", "READ", "file_path"),
        "bintra_inspect_crash_reports": ("cap.minidump.read", "READ", "file_path"),
        "bintra_correlate_failure_evidence": ("cap.file.read", "READ", "binary_path"),
        "bintra_win_catalog_cmd": ("cap.subprocess.catalog_exec", "EXECUTE", "command_id"),
        "bintra_registry_audit": ("cap.registry.read", "READ", "domain"),
        "bintra_hardware_audit": ("cap.device.query", "QUERY", None),
        "bintra_port_audit": ("cap.device.query", "QUERY", "port_name"),
        "bintra_hardware_topology": ("cap.device.query", "QUERY", "bus_filter"),
        "bintra_network_audit": ("cap.device.query", "QUERY", None),
        "bintra_network_hardware_dissect": ("cap.device.query", "QUERY", "target_query"),
        "bintra_network_connections": ("cap.device.query", "QUERY", "pid"),
        "bintra_driver_audit": ("cap.driver.query", "QUERY", None),
        "bintra_service_audit": ("cap.service.query", "QUERY", None),
        "bintra_dmp_inspect": ("cap.minidump.read", "READ", "dmp_path"),
        "bintra_etw_audit": ("cap.event_log.read", "READ", "session_name"),
        "bintra_etw_capture": ("cap.event_log.read", "READ", "session_name"),
        "bintra_vad_inspect": ("cap.process.query", "QUERY", "pid"),
        "bintra_memory_scan": ("cap.process.query", "READ", "pid"),
        "bintra_pointer_scan": ("cap.process.query", "READ", "pid"),
        "bintra_struct_dissect": ("cap.process.query", "READ", "pid"),
        "bintra_crash_rca": ("cap.minidump.read", "READ", "dmp_path"),
        "bintra_ghidra_live_bridge": ("cap.file.read", "READ", None),
        "bintra_evidence_graph": ("cap.file.read", "READ", "binary_path"),
        "bintra_wsp_audit": ("cap.file.read", "READ", "model_path"),
        "bintra_patch_weights": ("cap.workspace.write", "WRITE", "output_path"),
        "bintra_device_driver_intelligence": ("cap.device.query", "QUERY", "device_query"),
        "bintra_process_resource_audit": ("cap.process.query", "QUERY", "file_path"),
        "bintra_python_bytecode": ("cap.file.read", "READ", "file_path"),
        "bintra_cpython_memory_forensics": ("cap.process.query", "READ", "pid"),
        "bintra_pe_deep_forensics": ("cap.file.read", "READ", "file_path"),
        "bintra_binary_diff": ("cap.file.read", "READ", "baseline_path"),
        "bintra_ghidra_call_graph": ("cap.file.read", "READ", "export_path"),
        "bintra_ghidra_data_flow": ("cap.file.read", "READ", "export_path"),
        "bintra_ghidra_similar_functions": ("cap.file.read", "READ", "export_path"),
        "bintra_fuse_evidence": ("cap.file.read", "READ", "binary_path"),
        "bintra_triage_binary": ("cap.file.read", "READ", "file_path"),
        "bintra_profile_process": ("cap.process.query", "QUERY", "pid"),
        "bintra_inspect_slack_space": ("cap.file.read", "READ", "file_path"),
        "bintra_list_capabilities": ("cap.file.read", "READ", None)
    }

    @staticmethod
    def _apply_token_diet(tool_name: str, result_data: Any, args: Dict[str, Any]) -> Any:
        """Prune verbose boilerplate and bound large arrays when compact/summary_only is enabled."""
        if not isinstance(result_data, dict):
            return result_data
        compact = bool(args.get("compact")) or (os.environ.get("BINTRA_COMPACT_OUTPUT") == "1")
        summary_only = bool(args.get("summary_only"))
        max_items = args.get("max_list_items")
        if max_items is None and (compact or summary_only):
            max_items = 20

        if not (compact or summary_only or max_items is not None):
            return result_data

        data = dict(result_data)
        if tool_name == "bintra_sensory_audit" and (compact or summary_only):
            data.pop("score_semantics", None)
            senses = data.get("senses")
            if isinstance(senses, dict) and summary_only:
                condensed = {}
                for s_name, s_val in senses.items():
                    if isinstance(s_val, dict):
                        condensed[s_name] = {
                            k: v for k, v in s_val.items()
                            if k in ("status", "score", "efficiency", "entropy", "anomalies_count", "is_safe", "recommendation")
                        }
                    else:
                        condensed[s_name] = s_val
                data["senses"] = condensed

        elif tool_name == "bintra_ghidra_call_graph" and (compact or summary_only):
            if summary_only:
                data.pop("callees_map", None)
                data.pop("callers_map", None)
            elif isinstance(max_items, int) and max_items > 0:
                for map_key in ("callees_map", "callers_map"):
                    m = data.get(map_key)
                    if isinstance(m, dict) and len(m) > max_items:
                        keys = list(m.keys())[:max_items]
                        data[map_key] = {k: m[k] for k in keys}
                        data[f"_{map_key}_truncated"] = {"total": len(m), "shown": max_items}

        if isinstance(max_items, int) and max_items > 0:
            data, _ = prune_payload(data, max_list_items=max_items, drop_empty=compact)
        elif compact:
            data, _ = prune_payload(data, max_list_items=0, drop_empty=True)
        return data

    def handle_tools_call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        tool_name = params.get("name")
        args = params.get("arguments", {})
        if tool_name not in self.TOOL_SECURITY_METADATA and f"bintra_{tool_name}" in self.TOOL_SECURITY_METADATA:
            tool_name = f"bintra_{tool_name}"

        try:
            from security import ExecutionGuard, Capability, SecurityViolationError

            sec_meta = self.TOOL_SECURITY_METADATA.get(tool_name)
            if not sec_meta:
                raise SecurityViolationError(f"UNREGISTERED_TOOL: Tool '{tool_name}' has no registered security capability in PolicyEngine.")

            cap_val, mode, target_param = sec_meta
            cap = Capability(cap_val)

            # Extract target path and derive workspace strictly server-side
            target_path = (
                args.get("file_path") or args.get("binary_path") or
                args.get("model_path") or args.get("source_path") or
                args.get("target_path") or args.get("dump_path") or
                args.get("input_file") or args.get("dmp_path")
            )
            workspace_dir = self._resolve_server_workspace(args if isinstance(args, dict) else {})

            # Determine mediated target name
            effective_target = args.get(target_param) if target_param else (target_path or tool_name)
            if not effective_target:
                effective_target = tool_name

            req_metadata = {}
            if tool_name == "bintra_win_catalog_cmd":
                req_metadata["is_catalog_command"] = True

            self._validate_tool_arguments(tool_name, args)
            with ExecutionGuard.scoped_session(target_binary_path=target_path, workspace_dir=workspace_dir):
                # COMPLETE MEDIATION: All MCP tool invocations MUST be authorized by Reference Monitor
                ExecutionGuard.request_access(
                    component="mcp_server",
                    operation=tool_name,
                    target=str(effective_target),
                    capability=cap,
                    access_mode=mode,
                    metadata=req_metadata
                )
                raw_result_data = self.dispatch_tool(tool_name, args)
                pretty_print = (os.environ.get("BINTRA_PRETTY_PRINT") == "1")
                baseline_pretty_str = json.dumps(raw_result_data, indent=2, ensure_ascii=False)
                baseline_tok = estimate_tokens(baseline_pretty_str)
                result_data = self._apply_token_diet(tool_name, raw_result_data, args if isinstance(args, dict) else {})
                serialized_text = (
                    json.dumps(result_data, indent=2, ensure_ascii=False)
                    if pretty_print
                    else json.dumps(result_data, separators=(",", ":"), ensure_ascii=False)
                )
                call_stats = self.token_tracker.record_tool_call(
                    tool_name=tool_name,
                    args_text=json.dumps(args, separators=(",", ":"), ensure_ascii=False),
                    output_text=serialized_text,
                    baseline_output_tokens=baseline_tok,
                )
                if os.environ.get("BINTRA_TOKEN_TELEMETRY") == "1" and isinstance(result_data, dict):
                    result_data = dict(result_data)
                    result_data["_token_telemetry"] = {
                        "call": call_stats,
                        "session": self.token_tracker.summary(),
                    }
                    serialized_text = (
                        json.dumps(result_data, indent=2, ensure_ascii=False)
                        if pretty_print
                        else json.dumps(result_data, separators=(",", ":"), ensure_ascii=False)
                    )
                is_structured_error = (
                    isinstance(raw_result_data, dict)
                    and (
                        raw_result_data.get("status") == "error"
                        or raw_result_data.get("decision") == "DENY"
                    )
                )
                ret_obj = {
                    "content": [
                        {
                            "type": "text",
                            "text": serialized_text
                        }
                    ],
                    "isError": is_structured_error
                }
                if isinstance(result_data, dict):
                    ret_obj["structuredContent"] = result_data
                return ret_obj
        except Exception as exc:
            tb = traceback.format_exc()
            err_msg = f"Missing required parameter: {exc}" if isinstance(exc, KeyError) else str(exc)
            err_payload = {
                "status": "error",
                "tool": tool_name,
                "error": err_msg,
            }
            if os.environ.get("BINTRA_DEBUG") == "1":
                err_payload["traceback"] = tb
            err_text = (
                json.dumps(err_payload, indent=2)
                if os.environ.get("BINTRA_PRETTY_PRINT") == "1"
                else json.dumps(err_payload, separators=(",", ":"))
            )
            return {
                "content": [
                    {
                        "type": "text",
                        "text": err_text
                    }
                ],
                "structuredContent": err_payload,
                "isError": True
            }

    def dispatch_tool(self, name: str, args: Dict[str, Any]) -> Any:
        if name not in self.TOOL_SECURITY_METADATA and f"bintra_{name}" in self.TOOL_SECURITY_METADATA:
            name = f"bintra_{name}"
        method_name = TOOL_HANDLERS.get(name)
        if method_name is None:
            raise ValueError(f"Unknown tool name: '{name}'")
        return getattr(self, method_name)(name, args)

    def _handle_single_request(self, msg: Any) -> Optional[Dict[str, Any]]:
        """Processes a single JSON-RPC 2.0 request or notification according to specification."""
        if not isinstance(msg, dict):
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32600,
                    "message": "Invalid Request: message must be a JSON object"
                }
            }

        is_notification = ("id" not in msg)
        msg_id = msg.get("id")
        method = msg.get("method")
        params = msg.get("params", {})

        if not isinstance(params, (dict, list)):
            params = {}

        # Stateless MCP 2026-07-28: per-request protocolVersion check via _meta
        meta = params.get("_meta") if isinstance(params, dict) else None
        if not meta and isinstance(msg, dict):
            meta = msg.get("_meta")
        if meta and isinstance(meta, dict):
            meta_ver = meta.get("io.modelcontextprotocol/protocolVersion") or meta.get("protocolVersion")
            client_caps = meta.get("io.modelcontextprotocol/clientCapabilities") or meta.get("clientCapabilities")
            if client_caps and isinstance(client_caps, dict):
                self.current_client_capabilities = client_caps
            if meta_ver is not None and meta_ver not in SUPPORTED_PROTOCOL_VERSIONS:
                if not is_notification:
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32022,
                            "message": f"Unsupported protocol version: '{meta_ver}'. Supported versions: {list(SUPPORTED_PROTOCOL_VERSIONS)}",
                            "data": {
                                "supported": list(SUPPORTED_PROTOCOL_VERSIONS),
                                "requested": meta_ver,
                                "supportedProtocolVersions": list(SUPPORTED_PROTOCOL_VERSIONS),
                                "latestProtocolVersion": LATEST_PROTOCOL_VERSION,
                            }
                        }
                    }
                return None

        if method not in self.handlers:
            if not is_notification:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: '{method}'"
                    }
                }
            return None

        try:
            handler = self.handlers[method]
            result = handler(params)
            if not is_notification:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": result
                }
        except ValueError as ve:
            if not is_notification:
                is_ver_err = "Unsupported protocol version" in str(ve)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32022 if is_ver_err else -32602,
                        "message": str(ve),
                        "data": {
                            "supported": list(SUPPORTED_PROTOCOL_VERSIONS),
                            "requested": params.get("io.modelcontextprotocol/protocolVersion") or params.get("protocolVersion") if isinstance(params, dict) else None,
                            "supportedProtocolVersions": list(SUPPORTED_PROTOCOL_VERSIONS),
                            "latestProtocolVersion": LATEST_PROTOCOL_VERSION,
                        }
                    }
                }
            return None
        except Exception as ex:
            if not is_notification:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32603,
                        "message": f"Internal error: {ex}"
                    }
                }
        return None

    def run_stdio(self):
        """Standard JSON-RPC 2.0 loop reading from stdin and writing to stdout."""
        # Ensure utf-8 stdio. stdin MUST be reconfigured too: on Windows a piped
        # stdin defaults to the ANSI code page (e.g. cp1252), which silently
        # mangles non-ASCII file paths sent by MCP clients (JSON-RPC is UTF-8).
        # stdout uses newline="\n" so frames are not rewritten to CRLF.
        for stream_name, extra in (("stdin", {}), ("stdout", {"newline": "\n"}), ("stderr", {})):
            s = getattr(sys, stream_name, None)
            if s and hasattr(s, "reconfigure"):
                try:
                    s.reconfigure(encoding="utf-8", errors="replace", **extra)
                except Exception:
                    pass

        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue

                msg = json.loads(line)
                if isinstance(msg, list):
                    if len(msg) == 0:
                        err_resp = {
                            "jsonrpc": "2.0",
                            "id": None,
                            "error": {
                                "code": -32600,
                                "message": "Invalid Request: empty batch"
                            }
                        }
                        sys.stdout.write(json.dumps(err_resp, ensure_ascii=False) + "\n")
                        sys.stdout.flush()
                    else:
                        batch_resps = []
                        for item in msg:
                            r = self._handle_single_request(item)
                            if r is not None:
                                batch_resps.append(r)
                        if batch_resps:
                            sys.stdout.write(json.dumps(batch_resps, ensure_ascii=False) + "\n")
                            sys.stdout.flush()
                else:
                    r = self._handle_single_request(msg)
                    if r is not None:
                        sys.stdout.write(json.dumps(r, ensure_ascii=False) + "\n")
                        sys.stdout.flush()

            except json.JSONDecodeError as jde:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32700,
                        "message": f"Parse error: {jde}"
                    }
                }
                sys.stdout.write(json.dumps(err_resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()
            except Exception as ex:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32603,
                        "message": f"Internal error: {ex}"
                    }
                }
                sys.stdout.write(json.dumps(err_resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()


def main():
    server = BintraMcpServer()
    server.run_stdio()


if __name__ == "__main__":
    main()
