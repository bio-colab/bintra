"""MCP tool handlers: host. Methods are bound into BintraMcpServer via mixin inheritance."""
import os
from typing import Any, Dict




class WindowsHostToolsMixin:
    """Handlers for the host MCP tools (signature: (self, name, args) -> result)."""

    def _tool_windows_env_audit(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_windows_env_audit"""
        from windows_intelligence import WindowsOSProfiler, WindowsDeviceInspector, WindowsSecurityInspector
        b = args.get("file_path") or args.get("binary_path")
        return {
            "os": WindowsOSProfiler.profile(b),
            "devices": WindowsDeviceInspector.audit(),
            "security": WindowsSecurityInspector.audit(b)
        }

    def _tool_resolve_dependencies(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_resolve_dependencies"""
        from windows_intelligence import WindowsDependencyResolver
        b = args.get("file_path") or args.get("binary_path")
        return WindowsDependencyResolver.audit_dependencies(b)

    def _tool_inspect_crash_reports(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_inspect_crash_reports"""
        from windows_intelligence import WindowsCrashAnalyzer
        b = args.get("file_path") or args.get("binary_path")
        return WindowsCrashAnalyzer.collect_crash_evidence(b)

    def _tool_correlate_failure_evidence(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_correlate_failure_evidence"""
        from windows_intelligence import DiagnosticEvidenceCorrelator
        b = args.get("binary_path") or args.get("file_path")
        c = args.get("crash_record")
        g = args.get("ghidra_export")
        return DiagnosticEvidenceCorrelator.correlate(b, crash_record=c, ghidra_export=g)

    def _tool_win_catalog_cmd(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_win_catalog_cmd"""
        from windows_intelligence import CommandCatalog, CommandExecutor
        cmd_id = str(args.get("command_id", "")).strip()
        if cmd_id.lower() in ("list", "__list__"):
            commands = CommandCatalog.list_available_commands()
            return {
                "status": "success",
                "action": "list",
                "commands_count": len(commands),
                "commands": commands,
            }
        flags = tuple(args.get("extra_flags", [])) if args.get("extra_flags") else None
        return CommandExecutor.execute(cmd_id, extra_flags=flags)

    def _tool_registry_audit(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_registry_audit"""
        from windows_intelligence import WindowsRegistryAnalyzer, WindowsRegistryEditor
        action = args.get("action", "audit")
        if action == "read":
            hive = args.get("hive", "HKLM")
            subkey = args.get("subkey") or args.get("key", "")
            view = args.get("view", "dual")
            return WindowsRegistryEditor.read_key(hive=hive, subkey=subkey, view=view)
        elif action == "search":
            q = args.get("query") or args.get("search_query", "")
            hive = args.get("hive", "HKLM")
            root_k = args.get("root_key") or args.get("subkey") or args.get("key", "")
            limit = int(args.get("limit", 50))
            max_d = int(args.get("max_depth", 3))
            view = args.get("view", "64")
            return WindowsRegistryEditor.search(query=q, hive=hive, root_key=root_k, limit=limit, max_depth=max_d, view=view)
        elif action == "parse_reg":
            from security import ExecutionGuard, Capability
            target = args.get("reg_path") or args.get("reg_content") or ""
            if args.get("reg_path") or (isinstance(target, str) and len(target) < 1024 and os.path.isfile(target)):
                ExecutionGuard.request_access(
                    component="mcp_server",
                    operation="parse_reg_file",
                    target=str(target),
                    capability=Capability.FILE_READ,
                    access_mode="READ"
                )
            return WindowsRegistryEditor.parse_reg_file(target)
        elif action == "export_reg":
            from security import ExecutionGuard, Capability
            hive = args.get("hive", "HKLM")
            subkey = args.get("subkey") or args.get("key", "")
            out_path = args.get("output_path") or args.get("reg_path")
            rec = bool(args.get("recursive", False))
            max_d = int(args.get("max_depth", 1))
            view = args.get("view", "64")
            if out_path:
                ExecutionGuard.request_access(
                    component="mcp_server",
                    operation="export_reg",
                    target=str(out_path),
                    capability=Capability.WORKSPACE_WRITE,
                    access_mode="WRITE"
                )
            return WindowsRegistryEditor.export_key(hive=hive, subkey=subkey, output_path=out_path, recursive=rec, max_depth=max_d, view=view)
        elif action == "diff_reg":
            from security import ExecutionGuard, Capability
            target = args.get("reg_path") or args.get("reg_content") or ""
            if args.get("reg_path") or (isinstance(target, str) and len(target) < 1024 and os.path.isfile(target)):
                ExecutionGuard.request_access(
                    component="mcp_server",
                    operation="diff_reg_file",
                    target=str(target),
                    capability=Capability.FILE_READ,
                    access_mode="READ"
                )
            view = args.get("view", "64")
            return WindowsRegistryEditor.diff_reg_file(target, view=view)

        domain = args.get("domain")
        target_b = args.get("target_binary")
        if domain:
            return WindowsRegistryAnalyzer.audit_domain(domain)
        return WindowsRegistryAnalyzer.audit_all(target_binary_path=target_b)

    def _tool_evidence_graph(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_evidence_graph"""
        from windows_intelligence import CausalitySynthesizer, MiniDumpParser
        b = args.get("binary_path") or args.get("file_path")
        dmp_p = args.get("crash_dmp_path")
        g = args.get("ghidra_export")
        c_rec = None
        if dmp_p:
            parsed_dmp = MiniDumpParser.parse_minidump(dmp_p)
            if parsed_dmp.get("status") == "success":
                exc = parsed_dmp.get("exception_info") or {}
                c_rec = {
                    "source": "MINIDUMP",
                    "file_path": dmp_p,
                    "exception_code": exc.get("exception_code"),
                    "exception_name": exc.get("exception_name"),
                    "fault_module": exc.get("fault_module"),
                    "fault_offset": exc.get("fault_offset", "0x0"),
                    "access_violation_details": exc.get("access_violation_details")
                }
        graph = CausalitySynthesizer.build_evidence_graph(b, crash_record=c_rec, ghidra_export=g)
        return {
            "status": "success",
            "binary_path": b,
            "total_nodes": len(graph.nodes),
            "total_edges": len(graph.edges),
            "graph": graph.to_dict(),
            "mermaid_diagram": graph.to_mermaid()
        }
