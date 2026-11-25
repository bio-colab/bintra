# -*- coding: utf-8 -*-
"""Centralized static configuration, metadata, resources, and prompts for Bintra MCP Server."""

from typing import Any, Dict, List, Set, Tuple

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

TOOLS_LIST_PAGE_SIZE = 25

TARGET_PATH_ARG_KEYS: Tuple[str, ...] = (
    "file_path",
    "binary_path",
    "model_path",
    "source_path",
    "target_path",
    "baseline_path",
    "dump_path",
    "crash_dmp_path",
    "input_file",
    "export_path",
    "dmp_path",
)

MCP_TOOL_PROFILES: Dict[str, Set[str]] = {
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

WORKFLOW_PLAYBOOKS: Dict[str, List[str]] = {
    "unified_binary_triage": ["bintra_triage_binary"],
    "static_pe_deep_audit": [
        "bintra_inspect_binary",
        "bintra_pe_deep_forensics",
        "bintra_deobfuscate_binary",
        "bintra_scan_hybrid",
        "bintra_sensory_audit",
    ],
    "ghidra_deep_re": [
        "bintra_ghidra_analyze",
        "bintra_ghidra_call_graph",
        "bintra_ghidra_data_flow",
        "bintra_ghidra_similar_functions",
    ],
    "crash_root_cause_fusion": [
        "bintra_dmp_inspect",
        "bintra_crash_rca",
        "bintra_pe_deep_forensics",
        "bintra_fuse_evidence",
    ],
    "differential_binary_audit": [
        "bintra_binary_diff",
        "bintra_match_functions",
        "bintra_match_pcode",
        "bintra_ghidra_similar_functions",
    ],
    "windows_host_audit": [
        "bintra_windows_env_audit",
        "bintra_driver_audit",
        "bintra_service_audit",
        "bintra_network_connections",
    ],
}

WINDOWS_NATIVE_TOOLS: Set[str] = {
    "bintra_windows_env_audit", "bintra_resolve_dependencies", "bintra_inspect_crash_reports",
    "bintra_win_catalog_cmd", "bintra_registry_audit", "bintra_hardware_audit",
    "bintra_port_audit", "bintra_hardware_topology", "bintra_network_audit",
    "bintra_network_hardware_dissect", "bintra_network_connections",
    "bintra_driver_audit", "bintra_service_audit", "bintra_etw_audit",
    "bintra_vad_inspect", "bintra_memory_scan", "bintra_pointer_scan",
    "bintra_struct_dissect", "bintra_etw_capture", "bintra_device_driver_intelligence",
    "bintra_process_resource_audit",
}

GHIDRA_REQUIRED_TOOLS: Set[str] = {
    "bintra_ghidra_headless", "bintra_ghidra_live_bridge", "bintra_match_pcode",
    "bintra_deobfuscate_pcode", "bintra_ghidra_analyze", "bintra_ghidra_call_graph",
    "bintra_ghidra_data_flow", "bintra_ghidra_similar_functions",
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

TOOL_SECURITY_METADATA: Dict[str, Tuple[str, str, Any]] = {
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
    "bintra_list_capabilities": ("cap.file.read", "READ", None),
}
