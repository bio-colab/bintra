"""MCP tool handlers: runtime. Methods are bound into BintraMcpServer via mixin inheritance."""
import os
from typing import Any, Dict

from bintra_mcp.tools._common import parse_int_arg




class RuntimeTelemetryToolsMixin:
    """Handlers for the runtime MCP tools (signature: (self, name, args) -> result)."""

    def _tool_dmp_inspect(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_dmp_inspect"""
        from windows_intelligence import MiniDumpParser
        dmp_p = args.get("dmp_path")
        app_flt = args.get("app_name_filter")
        if dmp_p:
            return MiniDumpParser.parse_minidump(dmp_p)
        return MiniDumpParser.audit_dumps(app_name_filter=app_flt)

    def _tool_etw_audit(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_etw_audit"""
        from windows_intelligence import EtwController
        act = args.get("action", "audit")
        sname = args.get("session_name")
        if sname or act == "session":
            return EtwController.query_trace_session(sname or "Eventlog-Application")
        if act == "providers":
            return EtwController.enumerate_registered_providers(query=args.get("query"), limit=int(args.get("limit", 50)))
        if act == "active_kernel":
            return EtwController.audit_active_kernel_providers(limit=int(args.get("limit", 50)))
        if act == "provider_info":
            guid = args.get("guid") or "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"
            return EtwController.query_provider_instances(guid)
        return EtwController.audit_telemetry_system()

    def _tool_etw_capture(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_etw_capture"""
        s_name = args.get("session_name", "Bintra_Diagnostic_Trace")
        t_pid = args.get("pid")
        dur = float(args.get("duration_seconds", 1.0))
        import time
        from windows_intelligence import EtwLiveCaptureSession, EtwTimelineCorrelator
        session = EtwLiveCaptureSession(session_name=s_name, target_pid=t_pid)
        s_info = session.start_session()
        time.sleep(min(dur, 5.0))
        stop_info = session.stop_session()
        timeline = session.get_timeline(pid=t_pid)
        report = EtwTimelineCorrelator.correlate_crash_timeline(timeline)
        report["session_info"] = s_info
        report["stop_info"] = stop_info
        return report

    def _tool_vad_inspect(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_vad_inspect"""
        pid = int(args.get("pid", 0))
        if pid <= 0:
            raise ValueError("Valid 'pid' (> 0) is required.")
        from windows_intelligence import VirtualMemoryInspector
        snapshot = VirtualMemoryInspector.inspect_process(pid)
        addr_str = args.get("address")
        if addr_str:
            addr = parse_int_arg(addr_str, "address")
            return snapshot.classify_address(addr)
        return snapshot.to_dict(include_regions=bool(args.get("include_regions", False)))

    def _tool_memory_scan(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_memory_scan"""
        pid = int(args.get("pid", 0))
        if pid <= 0:
            raise ValueError("Valid 'pid' (> 0) is required.")
        from windows_intelligence import ProcessMemoryScanner
        val_type = str(args.get("value_type", "int32")).lower()
        valid_types = {
            "int8", "uint8", "int16", "uint16",
            "int32", "uint32", "int64", "uint64",
            "float", "double", "bytes", "string",
        }
        if val_type not in valid_types:
            raise ValueError(f"Unsupported value_type '{val_type}'.")
        mode = str(args.get("scan_mode", "exact")).lower()
        mode_map = {
            "exact": "EXACT_VALUE",
            "between": "VALUE_BETWEEN",
            "unknown": "UNKNOWN_INITIAL_VALUE",
            "increased": "INCREASED_VALUE",
            "decreased": "DECREASED_VALUE",
            "changed": "CHANGED_VALUE",
            "unchanged": "UNCHANGED_VALUE",
        }
        if mode not in mode_map:
            raise ValueError(f"Unsupported scan_mode '{mode}'. Allowed: {sorted(mode_map.keys())}")
        scan_mode = mode_map[mode]
        val = args.get("target_value")
        high_val = args.get("high_value")
        int_types = ("int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64")
        if val is not None:
            if val_type in int_types and isinstance(val, str):
                val = int(val, 0)
            elif val_type in ("float", "double") and isinstance(val, str):
                val = float(val)
            elif val_type == "bytes" and isinstance(val, str):
                val = bytes.fromhex(val.replace(" ", "").replace("0x", "").replace("0X", ""))
        if high_val is not None:
            if val_type in int_types and isinstance(high_val, str):
                high_val = int(high_val, 0)
            elif val_type in ("float", "double") and isinstance(high_val, str):
                high_val = float(high_val)

        sid = args.get("session_id")
        cand_addrs = args.get("candidate_addresses")
        if sid:
            return ProcessMemoryScanner.next_scan(
                session_id=sid,
                scan_type=scan_mode,
                value=val,
                min_val=val,
                max_val=high_val,
            )
        elif cand_addrs is not None:
            return ProcessMemoryScanner.next_scan(
                pid=pid,
                data_type=val_type,
                candidate_addresses=cand_addrs,
                scan_type=scan_mode,
                value=val,
                min_val=val,
                max_val=high_val,
            )
        else:
            alignment = args.get("alignment")
            return ProcessMemoryScanner.first_scan(
                pid=pid,
                data_type=val_type,
                scan_type=scan_mode,
                value=val,
                min_val=val,
                max_val=high_val,
                writable_only=bool(args.get("writable_only", True)),
                max_candidates=int(args.get("max_results", 50000)),
                alignment=int(alignment) if alignment is not None else None,
            )

    def _tool_pointer_scan(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_pointer_scan"""
        pid = int(args.get("pid", 0))
        if pid <= 0:
            raise ValueError("Valid 'pid' (> 0) is required.")
        target_str = args.get("target_address")
        if not target_str:
            raise ValueError("'target_address' is required.")
        target_addr = parse_int_arg(target_str, "target_address")
        from windows_intelligence import PointerScanner
        depth = int(args.get("max_depth", 2))
        offset = int(args.get("max_offset", 4096))
        max_r = int(args.get("max_results", 20))
        align = int(args.get("alignment", 4))
        return PointerScanner.find_pointer_paths(
            pid=pid,
            target_address=target_addr,
            max_depth=depth,
            max_offset=offset,
            max_results=max_r,
            alignment=align,
        )

    def _tool_struct_dissect(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_struct_dissect"""
        pid = int(args.get("pid", 0))
        if pid <= 0:
            raise ValueError("Valid 'pid' (> 0) is required.")
        addr_str = args.get("address")
        if not addr_str:
            raise ValueError("'address' is required.")
        addr = parse_int_arg(addr_str, "address")
        size = min(4096, max(8, int(args.get("size", 64))))
        s_name = args.get("struct_name")
        from windows_intelligence import StructureDissector
        return StructureDissector.dissect(pid=pid, base_address=addr, size=size, struct_name=s_name)

    def _tool_crash_rca(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_crash_rca"""
        dmp_p = args.get("dmp_path")
        if not dmp_p:
            raise ValueError("'dmp_path' is required.")
        b_path = args.get("binary_path")
        from windows_intelligence import CrashRootCauseAnalyzer
        return CrashRootCauseAnalyzer.analyze_crash(dump_target=dmp_p, binary_path=b_path)

    def _tool_process_resource_audit(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_process_resource_audit"""
        from windows_intelligence.process_intelligence import (
            FileUsageInspector,
            ModuleInventory,
            ProcessInventory,
            ServiceProcessMapper,
            TaskManagerInspector
        )
        action = args.get("action", "find_file_locks")
        f_path = args.get("file_path")
        pid = args.get("pid")
        mod_q = args.get("module_query")
        query = args.get("query")
        sort_by = args.get("sort_by", "memory")
        limit = int(args.get("limit", 50))

        if action == "find_file_locks":
            if not f_path:
                return {"status": "error", "error": "file_path is required for action 'find_file_locks'"}
            return FileUsageInspector.inspect_file_locks(f_path)
        elif action == "find_module_holders":
            if not mod_q:
                return {"status": "error", "error": "module_query is required for action 'find_module_holders'"}
            return ModuleInventory.find_processes_hosting_module(mod_q)
        elif action == "process_tree":
            return ProcessInventory.get_process_tree()
        elif action == "service_process_map":
            return ServiceProcessMapper.get_service_process_mapping()
        elif action == "list_processes":
            return TaskManagerInspector.list_processes(limit=limit, sort_by=sort_by, query=query)
        elif action == "search_processes":
            if not query:
                return {"status": "error", "error": "query parameter is required for action 'search_processes'"}
            return TaskManagerInspector.search_processes(query=query, max_results=limit)
        elif action == "system_performance":
            return TaskManagerInspector.get_system_performance()
        elif action == "audit_process":
            target_pid = pid or os.getpid()
            return TaskManagerInspector.get_process_details(target_pid)
        else:
            return {"status": "error", "error": f"Unknown action: '{action}'"}

    def _tool_profile_process(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_profile_process"""
        pid = int(args["pid"])
        if pid <= 0:
            raise ValueError("Valid 'pid' (> 0) is required.")
        samples = max(2, min(int(args.get("samples_count", 10)), 120))
        interval = max(0.01, min(float(args.get("interval_seconds", 0.2)), 10.0))
        if (samples - 1) * interval > 60.0:
            interval = round(60.0 / max(1, samples - 1), 3)
        from windows_intelligence.process_intelligence import ProcessLongitudinalProfiler
        return ProcessLongitudinalProfiler.profile_pid_longitudinal(
            pid=pid,
            samples_count=samples,
            interval_seconds=interval,
        )
