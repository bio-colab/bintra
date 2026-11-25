"""
Lazy command registry for the Bintra CLI.

Maps every command name (including aliases) to `bintra_cli.commands.<module>:<handler>`.
Handler modules are imported only when one of their commands runs, so CLI start-up
cost does not grow with the number of commands.
"""
import importlib
from typing import Callable, Dict, Optional, Tuple

COMMANDS: Dict[str, Tuple[str, str]] = {
    "capabilities": ("forensics", "cmd_capabilities"),
    "crash-rca": ("runtime", "cmd_crash_rca"),
    "decompile": ("weights", "cmd_decompile"),
    "decompile-circuit": ("weights", "cmd_decompile_circuit"),
    "deobfuscate": ("binary", "cmd_deobfuscate"),
    "deobfuscate-pcode": ("ghidra", "cmd_deobfuscate_pcode"),
    "dev-classes": ("devices", "cmd_dev_classes"),
    "dev-info": ("devices", "cmd_dev_info"),
    "dev-list": ("devices", "cmd_dev_list"),
    "dev-match": ("devices", "cmd_dev_match"),
    "dev-search": ("devices", "cmd_dev_search"),
    "diagnose": ("host", "cmd_diagnose"),
    "diff": ("weights", "cmd_decompile"),
    "diff-binaries": ("forensics", "cmd_diff_binaries"),
    "diff-weights": ("weights", "cmd_diff_weights"),
    "dissect-struct": ("runtime", "cmd_dissect_struct"),
    "dmp-inspect": ("runtime", "cmd_dmp_inspect"),
    "driver-audit": ("devices", "cmd_driver_audit"),
    "dump": ("binary", "cmd_deobfuscate"),
    "etw-audit": ("runtime", "cmd_etw_audit"),
    "etw-capture": ("runtime", "cmd_etw_capture"),
    "evidence-graph": ("forensics", "cmd_evidence_graph"),
    "file-locks": ("processes", "cmd_file_locks"),
    "fuse-evidence": ("forensics", "cmd_fuse_evidence"),
    "ghidra-analyze": ("ghidra", "cmd_ghidra_analyze"),
    "ghidra-bridge": ("ghidra", "cmd_ghidra_bridge"),
    "ghidra-callgraph": ("ghidra", "cmd_ghidra_callgraph"),
    "ghidra-dataflow": ("ghidra", "cmd_ghidra_dataflow"),
    "ghidra-headless": ("ghidra", "cmd_ghidra_headless"),
    "ghidra-plan": ("ghidra", "cmd_ghidra_plan"),
    "ghidra-similar": ("ghidra", "cmd_ghidra_similar"),
    "hw-audit": ("devices", "cmd_hw_audit"),
    "hw-dissect": ("devices", "cmd_hw_dissect"),
    "hw-net": ("devices", "cmd_hw_net"),
    "hw-tree": ("devices", "cmd_hw_tree"),
    "inspect": ("binary", "cmd_deobfuscate"),
    "inspect-slack": ("forensics", "cmd_slack_audit"),
    "leak-audit": ("processes", "cmd_proc_profile"),
    "match": ("binary", "cmd_deobfuscate"),
    "match-functions": ("binary", "cmd_match_functions"),
    "match-pcode": ("ghidra", "cmd_match_pcode"),
    "mcp": ("maintenance", "cmd_mcp"),
    "mcp-server": ("maintenance", "cmd_mcp"),
    "mem-scan": ("runtime", "cmd_mem_scan"),
    "net-conns": ("devices", "cmd_net_conns"),
    "overlay-inspect": ("forensics", "cmd_slack_audit"),
    "patch-binary": ("binary", "cmd_patch_binary"),
    "patch-weights": ("weights", "cmd_patch_weights"),
    "pe-forensics": ("forensics", "cmd_pe_forensics"),
    "pointer-scan": ("runtime", "cmd_pointer_scan"),
    "port-audit": ("devices", "cmd_port_audit"),
    "probe-trace": ("weights", "cmd_decompile"),
    "proc-info": ("processes", "cmd_proc_info"),
    "proc-list": ("processes", "cmd_proc_list"),
    "proc-modules": ("processes", "cmd_proc_modules"),
    "proc-profile": ("processes", "cmd_proc_profile"),
    "proc-search": ("processes", "cmd_proc_search"),
    "process-mitigations": ("processes", "cmd_process_mitigations"),
    "process-profile": ("processes", "cmd_proc_profile"),
    "py-bytecode": ("forensics", "cmd_py_bytecode"),
    "py-dissect": ("forensics", "cmd_py_bytecode"),
    "py-mem-inspect": ("forensics", "cmd_py_mem_inspect"),
    "reg-audit": ("host", "cmd_reg_audit"),
    "reg-export": ("host", "cmd_reg_export"),
    "reg-import": ("host", "cmd_reg_import"),
    "reg-read": ("host", "cmd_registry_read"),
    "reg-search": ("host", "cmd_reg_search"),
    "registry-read": ("host", "cmd_registry_read"),
    "resolve-deps": ("host", "cmd_resolve_deps"),
    "scan-hybrid": ("binary", "cmd_deobfuscate"),
    "self-update": ("maintenance", "cmd_update"),
    "sense": ("binary", "cmd_sense"),
    "sensory-audit": ("binary", "cmd_sense"),
    "service-audit": ("devices", "cmd_service_audit"),
    "sig-audit": ("forensics", "cmd_sig_audit"),
    "sig-verify": ("forensics", "cmd_sig_verify"),
    "slack-audit": ("forensics", "cmd_slack_audit"),
    "subspace": ("weights", "cmd_decompile"),
    "synthesize-weights": ("weights", "cmd_synthesize_weights"),
    "sys-perf": ("processes", "cmd_sys_perf"),
    "triage": ("forensics", "cmd_triage"),
    "triage-binary": ("forensics", "cmd_triage"),
    "update": ("maintenance", "cmd_update"),
    "vad-inspect": ("runtime", "cmd_vad_inspect"),
    "verify-behavior": ("weights", "cmd_decompile"),
    "wer-inspect": ("host", "cmd_wer_inspect"),
    "win-audit": ("host", "cmd_win_audit"),
    "win-cmd": ("host", "cmd_win_cmd"),
    "wsp-audit": ("weights", "cmd_decompile"),
}

BINARY_COMMANDS = {'deobfuscate', 'dump', 'inspect', 'match', 'match-functions', 'patch-binary', 'scan-hybrid'}
WEIGHT_COMMANDS = {'decompile', 'decompile-circuit', 'diff', 'diff-weights', 'patch-weights', 'probe-trace', 'subspace', 'verify-behavior', 'wsp-audit'}
ARCHIVED_SCOPE_COMMANDS = {'synthesize-weights'}
SENSORY_COMMANDS = {'sense', 'sensory-audit'}
GHIDRA_COMMANDS = {'deobfuscate-pcode', 'ghidra-analyze', 'ghidra-bridge', 'ghidra-headless', 'ghidra-plan', 'ghidra-similar', 'match-pcode'}
WIN_INTEL_COMMANDS = {'crash-rca', 'dev-classes', 'dev-info', 'dev-list', 'dev-match', 'dev-search', 'diagnose', 'dissect-struct', 'dmp-inspect', 'driver-audit', 'etw-audit', 'etw-capture', 'evidence-graph', 'file-locks', 'hw-audit', 'hw-dissect', 'hw-net', 'hw-tree', 'inspect-slack', 'leak-audit', 'mem-scan', 'net-conns', 'overlay-inspect', 'pointer-scan', 'port-audit', 'proc-info', 'proc-list', 'proc-modules', 'proc-profile', 'proc-search', 'process-mitigations', 'process-profile', 'reg-audit', 'reg-export', 'reg-import', 'reg-read', 'reg-search', 'registry-read', 'resolve-deps', 'service-audit', 'sig-audit', 'sig-verify', 'slack-audit', 'sys-perf', 'vad-inspect', 'wer-inspect', 'win-audit', 'win-cmd'}


def resolve(name: str) -> Optional[Callable[[str], None]]:
    """Returns the handler for `name`, importing its module on first use (None if unknown)."""
    entry = COMMANDS.get(name)
    if entry is None:
        return None
    module_name, func_name = entry
    module = importlib.import_module(f"bintra_cli.commands.{module_name}")
    return getattr(module, func_name)
