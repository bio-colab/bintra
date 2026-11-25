"""MCP tool handlers: ghidra. Methods are bound into BintraMcpServer via mixin inheritance."""
from typing import Any, Dict

from ghidra_pcode_vectorizer import GhidraAnnotationPlanner, PcodeDeobfuscator, PcodeFunctionMatcher



class GhidraToolsMixin:
    """Handlers for the ghidra MCP tools (signature: (self, name, args) -> result)."""

    def _tool_match_pcode(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_match_pcode"""
        p1 = args["func1_pcode"]
        p2 = args["func2_pcode"]
        return PcodeFunctionMatcher.match(p1, p2)

    def _tool_deobfuscate_pcode(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_deobfuscate_pcode"""
        pcode_ops = args["pcode_ops"]
        return PcodeDeobfuscator.detect_opaque_predicates(pcode_ops)

    def _tool_ghidra_analyze(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_ghidra_analyze"""
        from security import ExecutionGuard, Capability
        from ghidra_export_store import GhidraExportStore
        payload = args.get("payload")
        input_file = args.get("input_file")
        if input_file:
            ExecutionGuard.request_access(
                component="ghidra_analyzer",
                operation="read_ghidra_export",
                target=input_file,
                capability=Capability.FILE_READ,
                access_mode="READ",
                metadata={"file_path": input_file}
            )
        if not payload and not input_file:
            raise ValueError("Must provide 'payload' object or valid 'input_file'")

        with GhidraExportStore.from_path(input_file if input_file else payload) as store:
            # 1. Targeted single-function deep architectural inspection
            fn_target = args.get("function_name")
            if fn_target:
                res = store.inspect_function(fn_target)
                if not res:
                    return {"status": "not_found", "function_name": fn_target}
                return res

            # 2. Advanced search across functions, opcodes, xrefs, and decompiled C
            query = args.get("query")
            opcode_filter = args.get("opcode_filter")
            xref_target = args.get("xref_target")
            sensitive_only = bool(args.get("sensitive_only", False))
            if query or opcode_filter or xref_target or sensitive_only:
                limit = int(args.get("limit", 50))
                offset = int(args.get("offset", 0))
                return store.search_functions(
                    query=query,
                    opcode=opcode_filter,
                    xref_target=xref_target,
                    sensitive_only=sensitive_only,
                    limit=limit,
                    offset=offset
                )

            # 3. Global computational and architectural profile
            if args.get("profile"):
                return store.query_computational_profile()

            # 4. Standard batch mutation plan generation (default)
            return GhidraAnnotationPlanner.analyze_program_export(store)

    def _tool_ghidra_headless(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_ghidra_headless"""
        from security import ExecutionGuard, Capability
        from ghidra_headless_runner import GhidraHeadlessRunner
        bin_path = args["binary_path"]
        apply_flag = bool(args.get("apply", False))
        timeout_sec = int(args.get("timeout_seconds", 300))
        delete_proj = bool(args.get("delete_project", True))

        ExecutionGuard.request_access(
            component="ghidra_headless",
            operation="run_ghidra_headless",
            target=bin_path,
            capability=Capability.GHIDRA_HEADLESS_EXEC,
            access_mode="EXECUTE",
            metadata={"shell": False, "apply": apply_flag, "timeout": timeout_sec}
        )
        if apply_flag:
            ExecutionGuard.request_access(
                component="ghidra_headless",
                operation="apply_project_mutations",
                target=bin_path,
                capability=Capability.GHIDRA_PROJECT_MUTATE,
                access_mode="WRITE",
                metadata={"target": "ghidra_project_database"}
            )

        run_res = GhidraHeadlessRunner.run(
            binary_path=bin_path,
            apply=apply_flag,
            timeout_sec=timeout_sec,
            delete_project=delete_proj,
            ghidra_path=args.get("ghidra_path"),
            post_script=args.get("post_script") or "BintraGhidraBridge.java",
            project_name=args.get("project_name"),
            project_dir=args.get("project_dir"),
            max_cpu=args.get("max_cpu"),
            script_args=list(args.get("script_args", [])),
            guard_component="ghidra_headless",
        )

        return {
            "exit_code": run_res["exit_code"],
            "is_timeout": run_res["is_timeout"],
            "timeout_seconds": run_res["timeout_seconds"],
            "script_error_detected": run_res["script_error_detected"],
            "is_error": run_res["is_error"],
            "project_name": run_res["project_name"],
            "project_cleaned": run_res["project_cleaned"],
            "analyzed_functions_count": run_res["analyzed_functions_count"],
            "opaque_predicates_detected": run_res["opaque_predicates_detected"],
            "cff_backbones_detected": run_res["cff_backbones_detected"],
            "stdout_tail": run_res["stdout"][-3000:],
            "stderr_tail": run_res["stderr"][-2000:],
            "epistemic_classification": "GHIDRA_HEADLESS_BATCH_EXECUTION"
        }

    def _tool_ghidra_live_bridge(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_ghidra_live_bridge"""
        from ghidra_live_bridge import (
            GhidraLiveBridgeClient,
            get_or_create_bridge, get_active_bridge, stop_active_bridge
        )
        act = args.get("action", "status")
        port = int(args.get("port", 41718))
        token = args.get("auth_token")

        if act == "start":
            server = get_or_create_bridge(
                port=port,
                auth_token=token,
                publish_temp_marker=bool(args.get("publish_temp_marker", True)),
            )
            st = server.dispatch_rpc_method("get_status", {})
            st["marker_file"] = getattr(server, "_marker_path", None)
            return st
        elif act == "stop":
            return stop_active_bridge()
        elif act == "status":
            server = get_active_bridge()
            if server and server.is_running:
                return server.dispatch_rpc_method("get_status", {})
            client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{port}", auth_token=token)
            try:
                return client.call_rpc("get_status")
            except Exception as e:
                return {"is_running": False, "error": str(e)}
        elif act == "inject_crash_rca":
            dmp = args.get("crash_dmp_path")
            if not dmp:
                raise ValueError("'crash_dmp_path' is required for action 'inject_crash_rca'")
            from windows_intelligence import CrashRootCauseAnalyzer
            rca = CrashRootCauseAnalyzer.analyze_crash(dmp)
            server = get_active_bridge()
            if server and server.is_running:
                return server.inject_crash_rca(rca)
            client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{port}", auth_token=token)
            return client.call_rpc("bintra.inject_crash_rca", {"rca_report": rca})
        elif act == "inject_vad":
            pid = int(args.get("pid", 0))
            if pid <= 0:
                raise ValueError("Valid 'pid' (> 0) is required for action 'inject_vad'")
            from windows_intelligence import VirtualMemoryInspector
            snap = VirtualMemoryInspector.inspect_process(pid)
            server = get_active_bridge()
            if server and server.is_running:
                return server.inject_vad_snapshot(snap.to_dict())
            client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{port}", auth_token=token)
            return client.call_rpc("bintra.inject_vad_snapshot", {"vad_snapshot": snap.to_dict()})
        elif act == "inject_etw":
            tl = args.get("timeline_report")
            if not tl:
                import time
                from windows_intelligence import EtwLiveCaptureSession, EtwTimelineCorrelator
                sess = EtwLiveCaptureSession(session_name="QuickProbe")
                sess.start_session()
                time.sleep(0.5)
                sess.stop_session()
                tl = EtwTimelineCorrelator.correlate_crash_timeline(sess.get_timeline())
            server = get_active_bridge()
            if server and server.is_running:
                return server.inject_etw_timeline(tl)
            client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{port}", auth_token=token)
            return client.call_rpc("bintra.inject_etw_timeline", {"timeline_report": tl})
        elif act == "inject_struct":
            s_rep = args.get("struct_report")
            if not s_rep:
                pid = int(args.get("pid", 0))
                addr_str = args.get("address")
                if pid <= 0 or not addr_str:
                    raise ValueError("'struct_report' or both 'pid' and 'address' are required for 'inject_struct'")
                base_addr = int(addr_str, 16) if addr_str.lower().startswith("0x") else int(addr_str)
                from windows_intelligence import StructureDissector
                s_rep = StructureDissector.dissect(pid, base_addr)
            server = get_active_bridge()
            if server and server.is_running:
                return server.inject_structure_dissection(s_rep)
            client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{port}", auth_token=token)
            return client.call_rpc("bintra.inject_structure_dissection", {"struct_report": s_rep})
        elif act == "inject_pointers":
            p_rep = args.get("pointer_report")
            if not p_rep:
                pid = int(args.get("pid", 0))
                addr_str = args.get("address")
                if pid <= 0 or not addr_str:
                    raise ValueError("'pointer_report' or both 'pid' and 'address' are required for 'inject_pointers'")
                target_addr = int(addr_str, 16) if addr_str.lower().startswith("0x") else int(addr_str)
                from windows_intelligence import PointerScanner
                p_rep = PointerScanner.find_pointer_paths(pid, target_addr)
            server = get_active_bridge()
            if server and server.is_running:
                return server.inject_pointer_chains(p_rep)
            client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{port}", auth_token=token)
            return client.call_rpc("bintra.inject_pointer_chains", {"pointer_report": p_rep})
        else:
            raise ValueError(f"Unknown ghidra_live_bridge action: '{act}'")

    def _tool_ghidra_call_graph(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_ghidra_call_graph"""
        from security import ExecutionGuard, Capability
        from ghidra_pcode_vectorizer import GhidraDeepAnalyzer
        from ghidra_export_store import GhidraExportStore
        ep = args["export_path"]
        ExecutionGuard.request_access(
            component="ghidra_analyzer",
            operation="read_ghidra_export_call_graph",
            target=ep,
            capability=Capability.FILE_READ,
            access_mode="READ",
            metadata={"file_path": ep}
        )
        with GhidraExportStore.from_path(ep) as store:
            return GhidraDeepAnalyzer().build_call_graph_and_xrefs(
                store,
                target_function=args.get("target_function"),
                max_depth=int(args.get("max_depth", 4)),
            )

    def _tool_ghidra_data_flow(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_ghidra_data_flow"""
        from security import ExecutionGuard, Capability
        from ghidra_pcode_vectorizer import GhidraDeepAnalyzer
        from ghidra_export_store import GhidraExportStore
        ep = args["export_path"]
        fn_target = args["function_name"]
        ExecutionGuard.request_access(
            component="ghidra_analyzer",
            operation="read_ghidra_export_data_flow",
            target=ep,
            capability=Capability.FILE_READ,
            access_mode="READ",
            metadata={"file_path": ep, "function_name": fn_target}
        )
        with GhidraExportStore.from_path(ep) as store:
            matched_fn = store.get_function(fn_target)
            if not matched_fn:
                return {"status": "not_found", "function_name": fn_target}
            return GhidraDeepAnalyzer().slice_data_flow(matched_fn, target_var=args.get("target_var"))

    def _tool_ghidra_similar_functions(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_ghidra_similar_functions"""
        from security import ExecutionGuard, Capability
        from ghidra_export_store import GhidraExportStore
        ep = args["export_path"]
        ExecutionGuard.request_access(
            component="ghidra_analyzer",
            operation="search_similar_functions",
            target=ep,
            capability=Capability.FILE_READ,
            access_mode="READ",
            metadata={"file_path": ep}
        )
        ref_fn = args.get("reference_function")
        ref_pcode = args.get("reference_pcode")
        if not ref_fn and not ref_pcode:
            raise ValueError(
                "Must provide either 'reference_function' (name/entry in the export) "
                "or 'reference_pcode' (external P-code operation stream)."
            )
        with GhidraExportStore.from_path(ep) as store:
            return store.search_similar_functions(
                reference_function=ref_fn,
                reference_pcode=ref_pcode,
                threshold=float(args.get("threshold", 0.75)),
                limit=int(args.get("limit", 20)),
                min_pcode_ops=int(args.get("min_pcode_ops", 1)),
            )
