"""MCP tool handler mixins and the tool-name -> handler-method table."""
from bintra_mcp.tools.binary import BinaryToolsMixin
from bintra_mcp.tools.weights import WeightsToolsMixin
from bintra_mcp.tools.ghidra import GhidraToolsMixin
from bintra_mcp.tools.host import WindowsHostToolsMixin
from bintra_mcp.tools.devices import DevicesToolsMixin
from bintra_mcp.tools.runtime import RuntimeTelemetryToolsMixin
from bintra_mcp.tools.forensics import ForensicsToolsMixin

TOOL_MIXINS = (BinaryToolsMixin, WeightsToolsMixin, GhidraToolsMixin, WindowsHostToolsMixin, DevicesToolsMixin, RuntimeTelemetryToolsMixin, ForensicsToolsMixin,)

TOOL_HANDLERS = {
    "bintra_inspect_binary": "_tool_inspect_binary",
    "bintra_deobfuscate_binary": "_tool_deobfuscate_binary",
    "bintra_dump_bytes": "_tool_dump_bytes",
    "bintra_match_functions": "_tool_match_functions",
    "bintra_patch_binary": "_tool_patch_binary",
    "bintra_scan_hybrid": "_tool_scan_hybrid",
    "bintra_sensory_audit": "_tool_sensory_audit",
    "bintra_match_pcode": "_tool_match_pcode",
    "bintra_deobfuscate_pcode": "_tool_deobfuscate_pcode",
    "bintra_ghidra_analyze": "_tool_ghidra_analyze",
    "bintra_ghidra_headless": "_tool_ghidra_headless",
    "bintra_windows_env_audit": "_tool_windows_env_audit",
    "bintra_resolve_dependencies": "_tool_resolve_dependencies",
    "bintra_inspect_crash_reports": "_tool_inspect_crash_reports",
    "bintra_correlate_failure_evidence": "_tool_correlate_failure_evidence",
    "bintra_win_catalog_cmd": "_tool_win_catalog_cmd",
    "bintra_registry_audit": "_tool_registry_audit",
    "bintra_hardware_audit": "_tool_hardware_audit",
    "bintra_port_audit": "_tool_port_audit",
    "bintra_hardware_topology": "_tool_hardware_topology",
    "bintra_network_audit": "_tool_network_audit",
    "bintra_network_hardware_dissect": "_tool_network_hardware_dissect",
    "bintra_network_connections": "_tool_network_connections",
    "bintra_driver_audit": "_tool_driver_audit",
    "bintra_service_audit": "_tool_service_audit",
    "bintra_dmp_inspect": "_tool_dmp_inspect",
    "bintra_etw_audit": "_tool_etw_audit",
    "bintra_etw_capture": "_tool_etw_capture",
    "bintra_ghidra_live_bridge": "_tool_ghidra_live_bridge",
    "bintra_vad_inspect": "_tool_vad_inspect",
    "bintra_memory_scan": "_tool_memory_scan",
    "bintra_pointer_scan": "_tool_pointer_scan",
    "bintra_struct_dissect": "_tool_struct_dissect",
    "bintra_crash_rca": "_tool_crash_rca",
    "bintra_evidence_graph": "_tool_evidence_graph",
    "bintra_wsp_audit": "_tool_wsp_audit",
    "bintra_patch_weights": "_tool_patch_weights",
    "bintra_device_driver_intelligence": "_tool_device_driver_intelligence",
    "bintra_process_resource_audit": "_tool_process_resource_audit",
    "bintra_python_bytecode": "_tool_python_bytecode",
    "bintra_cpython_memory_forensics": "_tool_cpython_memory_forensics",
    "bintra_pe_deep_forensics": "_tool_pe_deep_forensics",
    "bintra_binary_diff": "_tool_binary_diff",
    "bintra_ghidra_call_graph": "_tool_ghidra_call_graph",
    "bintra_ghidra_data_flow": "_tool_ghidra_data_flow",
    "bintra_ghidra_similar_functions": "_tool_ghidra_similar_functions",
    "bintra_fuse_evidence": "_tool_fuse_evidence",
    "bintra_triage_binary": "_tool_triage_binary",
    "bintra_profile_process": "_tool_profile_process",
    "bintra_inspect_slack_space": "_tool_inspect_slack_space",
    "bintra_list_capabilities": "_tool_list_capabilities",
}
