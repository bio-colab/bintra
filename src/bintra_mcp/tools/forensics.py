"""MCP tool handlers: forensics. Methods are bound into BintraMcpServer via mixin inheritance."""
import os
from typing import Any, Dict


from bintra_mcp.config import GHIDRA_REQUIRED_TOOLS, WINDOWS_NATIVE_TOOLS, WORKFLOW_PLAYBOOKS
from bintra_mcp.tool_schemas import TOOLS_REGISTRY
from bintra_mcp.tools._common import parse_int_arg


class ForensicsToolsMixin:
    """Handlers for the forensics MCP tools (signature: (self, name, args) -> result)."""

    def _tool_python_bytecode(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_python_bytecode"""
        from python_intelligence import PythonBytecodeAnalyzer, PythonPackageArchitect
        target_path = args["file_path"]
        if os.path.isdir(target_path) or bool(args.get("package_mode")):
            return PythonPackageArchitect.analyze_package(
                target_path,
                max_files=int(args.get("max_files", 500)),
                complexity_threshold=int(args.get("complexity_threshold", 15))
            )
        if args.get("compare_with"):
            return PythonBytecodeAnalyzer.compare_bytecode(target_path, args["compare_with"])
        return PythonBytecodeAnalyzer.analyze_file(target_path, limit=int(args.get("limit", 50)))

    def _tool_cpython_memory_forensics(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_cpython_memory_forensics"""
        from windows_intelligence.runtime_telemetry.cpython_memory_forensics import CPythonMemoryForensics
        addr = parse_int_arg(args["address"], "address")
        return CPythonMemoryForensics.inspect_live_process(
            pid=int(args["pid"]),
            address=addr,
            object_type=args.get("object_type", "pyobject"),
        )

    def _tool_pe_deep_forensics(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_pe_deep_forensics"""
        from pe_deep_forensics import PeDeepForensicsInspector
        return PeDeepForensicsInspector().inspect(
            file_path=args["file_path"],
            pdb_path=args.get("pdb_path"),
            limit=int(args.get("limit", 25)),
        )

    def _tool_binary_diff(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_binary_diff"""
        from pe_deep_forensics import SemanticBinaryDiffer
        from security import ExecutionGuard, Capability
        mode_val = args.get("mode", "pe")
        b_path = args["baseline_path"]
        t_path = args["target_path"]
        if mode_val == "ghidra_export":
            from ghidra_export_store import GhidraExportStore
            ExecutionGuard.request_access(component="binary_diff", operation="diff_ghidra_baseline", target=b_path, capability=Capability.FILE_READ, access_mode="READ")
            ExecutionGuard.request_access(component="binary_diff", operation="diff_ghidra_target", target=t_path, capability=Capability.FILE_READ, access_mode="READ")
            with GhidraExportStore.from_path(b_path) as b_store, GhidraExportStore.from_path(t_path) as t_store:
                b_funcs = list(b_store.iter_functions()) if b_store.is_sqlite else b_store.to_dict().get("functions", [])
                t_funcs = list(t_store.iter_functions()) if t_store.is_sqlite else t_store.to_dict().get("functions", [])
                return SemanticBinaryDiffer().diff_function_exports(b_funcs, t_funcs)
        return SemanticBinaryDiffer().diff_pe_binaries(b_path, t_path)

    def _tool_fuse_evidence(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_fuse_evidence"""
        from windows_intelligence.evidence_engine.graph_model import fuse_static_dynamic_ghidra
        pe_res = None
        sig_res = None
        rca_res = None
        cg_res = None
        df_res = None
        ghidra_provenance = {"status": "NOT_PROVIDED", "verified": False}
        if args.get("binary_path"):
            from pe_deep_forensics import PeDeepForensicsInspector
            from windows_intelligence.signature_intelligence import WindowsSignatureIntelligence
            pe_res = PeDeepForensicsInspector().inspect(args["binary_path"], limit=200)
            try:
                sig_res = WindowsSignatureIntelligence.verify_file(args["binary_path"], check_catalog=True)
            except Exception:
                sig_res = None
        if args.get("dmp_path"):
            from windows_intelligence import CrashRootCauseAnalyzer
            rca_res = CrashRootCauseAnalyzer.analyze_crash(dump_target=args["dmp_path"], binary_path=args.get("binary_path"))
        if args.get("ghidra_export_path"):
            from ghidra_pcode_vectorizer import GhidraDeepAnalyzer
            from ghidra_export_store import GhidraExportStore
            from analysis_orchestrator import BinaryTriageOrchestrator
            gp = args["ghidra_export_path"]
            with GhidraExportStore.from_path(gp) as store:
                # Provenance quarantine parity with the triage orchestrator:
                # an export whose hash/name does not match the target binary is
                # NEVER fused into the evidence graph.
                if args.get("binary_path"):
                    from binary_neural_engine import BinaryFormatInspector
                    target_sha = BinaryFormatInspector.compute_sha256(args["binary_path"]).lower()
                    ghidra_provenance, is_crypto, is_heuristic = (
                        BinaryTriageOrchestrator.verify_ghidra_export_provenance(
                            store,
                            target_sha256=target_sha,
                            target_filename=os.path.basename(args["binary_path"]),
                        )
                    )
                    if not (is_crypto or is_heuristic):
                        return {
                            "status": "provenance_mismatch",
                            "epistemic_classification": "MULTI_SIGNAL_EVIDENCE_FUSION",
                            "ghidra_provenance": ghidra_provenance,
                            "warning": ghidra_provenance.get("warning", "Ghidra export provenance verification failed."),
                        }
                else:
                    ghidra_provenance = {
                        "status": "UNVERIFIED_NO_TARGET_FOR_PROVENANCE",
                        "verified": False,
                        "warning": "No binary_path provided; Ghidra export provenance could not be verified.",
                    }
                analyzer = GhidraDeepAnalyzer()
                cg_res = analyzer.build_call_graph_and_xrefs(store, target_function=args.get("function_name"))
                if args.get("function_name"):
                    fn_match = store.get_function(args["function_name"])
                    if fn_match:
                        df_res = analyzer.slice_data_flow(fn_match)
        return fuse_static_dynamic_ghidra(
            pe_forensics=pe_res,
            crash_rca=rca_res,
            ghidra_call_graph=cg_res,
            ghidra_data_flow=df_res,
            signature_intel=sig_res,
            ghidra_provenance=ghidra_provenance,
        )

    def _tool_triage_binary(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_triage_binary"""
        from analysis_orchestrator import BinaryTriageOrchestrator
        return BinaryTriageOrchestrator.triage_binary(
            file_path=args["file_path"],
            dmp_path=args.get("dmp_path"),
            ghidra_export_path=args.get("ghidra_export_path"),
            function_name=args.get("function_name"),
            include_deobfuscation=bool(args.get("include_deobfuscation", True)),
            include_sensory=bool(args.get("include_sensory", True)),
            include_hybrid_scan=bool(args.get("include_hybrid_scan", True)),
            max_exports=int(args.get("max_exports", 32)),
            forensics_limit=int(args.get("forensics_limit", 200)),
        )

    def _tool_inspect_slack_space(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_inspect_slack_space"""
        from windows_intelligence.evidence_engine.binary_slack_inspector import BinarySlackInspector
        return BinarySlackInspector.inspect_file(args["file_path"])

    def _tool_list_capabilities(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_list_capabilities"""
        import platform as _plat
        p_filter = args.get("platform_filter", "all")
        entries = []
        for t in TOOLS_REGISTRY:
            t_name = t["name"]
            sec = self.TOOL_SECURITY_METADATA.get(t_name, ("unknown", "READ", None))
            env = (
                "windows_native"
                if t_name in WINDOWS_NATIVE_TOOLS
                else ("ghidra_required" if t_name in GHIDRA_REQUIRED_TOOLS else "cross_platform")
            )
            if p_filter != "all" and env != p_filter:
                continue
            compact_caps = bool(args.get("compact")) or (os.environ.get("BINTRA_COMPACT_OUTPUT") == "1")
            entry = {
                "name": t_name,
                "environment": env,
                "capability": sec[0],
                "access_mode": sec[1],
            }
            if not compact_caps:
                entry["description"] = t.get("description", "")
            entries.append(entry)
        return {
            "status": "ok",
            "host_os": _plat.system(),
            "total_tools": len(entries),
            "tools": entries,
            "recommended_workflows": {
                "static_pe_deep_audit": WORKFLOW_PLAYBOOKS["static_pe_deep_audit"],
                "ghidra_deep_re": WORKFLOW_PLAYBOOKS["ghidra_deep_re"],
                "crash_root_cause_fusion": WORKFLOW_PLAYBOOKS["crash_root_cause_fusion"],
                "version_diff": ["bintra_binary_diff"]
            }
        }
