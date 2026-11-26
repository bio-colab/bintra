"""Bintra CLI commands: Ghidra P-Code matching, export analysis, headless automation and the live bridge."""
import argparse
import ast
import json
import os
import sys
import time
from typing import Any, Dict


from bintra_cli.commands._common import parse_int_arg, validate_port
from ghidra_pcode_vectorizer import (
    PcodeFunctionMatcher, PcodeDeobfuscator, GhidraAnnotationPlanner
)


def _load_pcode_input(val: str) -> Any:
    """Load P-code operations from a JSON file path or an inline JSON/literal payload."""
    if os.path.exists(val):
        with open(val, "r", encoding="utf-8") as f:
            return json.load(f)
    try:
        return json.loads(val)
    except json.JSONDecodeError as json_err:
        try:
            return ast.literal_eval(val)
        except (ValueError, SyntaxError):
            raise ValueError(f"Invalid P-code payload (expected file path, JSON, or Python literal): {json_err}") from json_err


def cmd_match_pcode(cmd: str) -> None:
    """bintra match-pcode"""
    parser = argparse.ArgumentParser(description="Match two functions using Ghidra P-code")
    parser.add_argument("command")
    parser.add_argument("--func1", required=True, help="JSON file or inline JSON string of function 1 P-code ops")
    parser.add_argument("--func2", required=True, help="JSON file or inline JSON string of function 2 P-code ops")
    args = parser.parse_args()
    p1 = _load_pcode_input(args.func1)
    p2 = _load_pcode_input(args.func2)
    res = PcodeFunctionMatcher.match(p1, p2)
    print(json.dumps(res, indent=2))
    return


def cmd_deobfuscate_pcode(cmd: str) -> None:
    """bintra deobfuscate-pcode"""
    parser = argparse.ArgumentParser(description="Detect and simplify P-code opaque predicates")
    parser.add_argument("command")
    parser.add_argument("--file", default=None, help="JSON file containing P-code ops")
    parser.add_argument("--pcode", default=None, help="Inline JSON string of P-code ops")
    args = parser.parse_args()
    if args.file and os.path.exists(args.file):
        with open(args.file, "r", encoding="utf-8") as f:
            ops = json.load(f)
    elif args.pcode:
        ops = json.loads(args.pcode)
    else:
        print("Must provide --file or --pcode JSON")
        sys.exit(1)
    res = PcodeDeobfuscator.detect_opaque_predicates(ops)
    print(json.dumps(res, indent=2))
    return


def cmd_ghidra_plan(cmd: str) -> None:
    """bintra ghidra-plan"""
    parser = argparse.ArgumentParser(description="Generate Ghidra Program Database annotation plan")
    parser.add_argument("command")
    parser.add_argument("--address", required=True, help="Target function address")
    parser.add_argument("--name", required=True, help="Recovered function name")
    parser.add_argument("--return-type", default="void", help="Return type")
    parser.add_argument("--comment", default=None, help="Optional decompilation comment")
    args = parser.parse_args()
    plan = GhidraAnnotationPlanner.build_function_annotation_plan(
        args.address, args.name, return_type=args.return_type, comment=args.comment
    )
    print(json.dumps(plan, indent=2))
    return


def cmd_ghidra_analyze(cmd: str) -> None:
    """bintra ghidra-analyze"""
    parser = argparse.ArgumentParser(description="Analyze Ghidra exported High P-Code and emit mutation plan, search functions, or profile binary")
    parser.add_argument("command")
    parser.add_argument("--input", "--file", dest="input", required=True, help="Path to exported Ghidra JSON/JSONL/DB file")
    parser.add_argument("--output", default=None, help="Path to write the generated mutation plan JSON")
    parser.add_argument("--to-sqlite", default=None, help="Optional path to convert export to indexed SQLite database")
    parser.add_argument("--workspace", default=None, help="Optional workspace directory override")
    parser.add_argument("--query", default=None, help="Filter functions by name, entry RVA, signature, or decompiled C substring")
    parser.add_argument("--opcode", default=None, help="Filter functions containing specific P-Code opcode (e.g. CALLIND, FLOAT_SQRT, INT_XOR)")
    parser.add_argument("--xref", default=None, help="Filter functions referencing specific symbol, address, or string")
    parser.add_argument("--function", default=None, help="Retrieve full architectural inspection and decompiled C for a single function")
    parser.add_argument("--sensitive-only", action="store_true", help="Filter to functions invoking sensitive Win32 APIs")
    parser.add_argument("--profile", action="store_true", help="Synthesize global computational and architectural profile across binary")
    parser.add_argument("--limit", type=int, default=50, help="Max search results to return (default: 50)")
    args = parser.parse_args()

    from security import SafeFileAccess, ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="ghidra-analyze-input",
        target=args.input,
        capability=Capability.FILE_READ,
        access_mode="READ"
    )
    if args.output:
        ExecutionGuard.request_access(
            component="cli",
            operation="ghidra-analyze-output",
            target=args.output,
            capability=Capability.WORKSPACE_WRITE,
            access_mode="WRITE"
        )
    from ghidra_export_store import GhidraExportStore
    if args.to_sqlite:
        ExecutionGuard.request_access(
            component="cli",
            operation="ghidra-analyze-to-sqlite",
            target=args.to_sqlite,
            capability=Capability.WORKSPACE_WRITE,
            access_mode="WRITE"
        )
        is_jsonl = str(args.input).lower().endswith(".jsonl")
        GhidraExportStore.ingest_to_sqlite(args.input, args.to_sqlite, is_jsonl=is_jsonl)
        print(json.dumps({"status": "ok", "action": "exported_to_sqlite", "sqlite_db": args.to_sqlite}, indent=2))
        return

    with GhidraExportStore.from_path(args.input) as store:
        # 1. Inspect single function
        if args.function:
            res = store.inspect_function(args.function)
            if not res:
                print(json.dumps({"status": "not_found", "function_name": args.function}, indent=2))
            else:
                print(json.dumps(res, indent=2))
            return

        # 2. Search / Query functions
        if args.query or args.opcode or args.xref or args.sensitive_only:
            res = store.search_functions(
                query=args.query,
                opcode=args.opcode,
                xref_target=args.xref,
                sensitive_only=args.sensitive_only,
                limit=args.limit
            )
            print(json.dumps(res, indent=2))
            return

        # 3. Global computational profile
        if args.profile:
            res = store.query_computational_profile()
            print(json.dumps(res, indent=2))
            return

        # 4. Batch annotation plan (default)
        plan = GhidraAnnotationPlanner.analyze_program_export(store)
        if args.output:
            SafeFileAccess.write_workspace_file(args.output, json.dumps(plan, indent=2))
        print(json.dumps(plan, indent=2))
        return


def cmd_ghidra_headless(cmd: str) -> None:
    """bintra ghidra-headless"""
    parser = argparse.ArgumentParser(prog="bintra ghidra-headless", description="Run Ghidra headless analysis with Bintra bridge script")
    parser.add_argument("--binary", "--file", "--input", dest="binary", required=True, help="Path to target executable (PE/ELF)")
    parser.add_argument("--ghidra-path", default=None, help="Ghidra installation directory (default: auto-discover)")
    parser.add_argument("--project-dir", default=None, help="Ghidra project directory (default: temp)")
    parser.add_argument("--project-name", default=None, help="Ghidra project name (default: auto-generated isolated)")
    parser.add_argument("--post-script", default="BintraGhidraBridge.java", help="Bridge script to execute (default: BintraGhidraBridge.java)")
    parser.add_argument("--apply", action="store_true", help="Automatically commit mutations to Ghidra database")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout in seconds for headless analysis (default: 300)")
    parser.add_argument("--max-cpu", type=int, default=None, help="Max CPU cores for Ghidra analysis threads")
    parser.add_argument("--keep-project", action="store_true", help="Do not delete temporary Ghidra project files after run")
    args = parser.parse_args(sys.argv[2:])

    from security import ExecutionGuard, Capability

    ExecutionGuard.request_access(
        component="cli",
        operation="ghidra-headless-exec",
        target=args.binary,
        capability=Capability.GHIDRA_HEADLESS_EXEC,
        access_mode="EXECUTE",
        metadata={"shell": False, "apply": args.apply, "timeout": args.timeout}
    )
    if args.apply:
        ExecutionGuard.request_access(
            component="cli",
            operation="ghidra-headless-mutate",
            target=args.binary,
            capability=Capability.GHIDRA_PROJECT_MUTATE,
            access_mode="WRITE",
            metadata={"target": "ghidra_project_database"}
        )

    from ghidra_headless_runner import GhidraHeadlessRunner

    print("[Bintra] Launching Ghidra Headless Analyzer...")
    print(f"[Bintra] Binary: {args.binary}")
    print(f"[Bintra] Script: {args.post_script}")

    try:
        run_res = GhidraHeadlessRunner.run(
            binary_path=args.binary,
            apply=args.apply,
            timeout_sec=args.timeout,
            delete_project=not args.keep_project,
            ghidra_path=args.ghidra_path,
            post_script=args.post_script,
            project_name=args.project_name,
            project_dir=args.project_dir,
            max_cpu=args.max_cpu,
            guard_component="cli",
        )
    except FileNotFoundError as fnf:
        print(f"Error: {fnf}")
        sys.exit(1)

    if run_res["is_timeout"]:
        sys.stderr.write(f"[Bintra] Ghidra Headless Analyzer timed out after {args.timeout}s.\n")
    if run_res["project_cleaned"]:
        print(f"[Bintra] Transient Ghidra project '{run_res['project_name']}' safely cleaned.")

    print(run_res["stdout"], end="")
    if run_res["stderr"]:
        sys.stderr.write(run_res["stderr"])
    if run_res["is_error"]:
        sys.stderr.write(
            f"[Bintra] Ghidra Headless Analyzer failed (rc={run_res['raw_returncode']}, "
            f"script_error={run_res['script_error_detected']})\n"
        )
        sys.exit(run_res["raw_returncode"] if run_res["raw_returncode"] != 0 else 1)
    sys.exit(0)


def cmd_ghidra_bridge(cmd: str) -> None:
    """bintra ghidra-bridge"""
    parser = argparse.ArgumentParser(prog="bintra ghidra-bridge", description="Bintra Ghidra Live Bidirectional Bridge Daemon")
    parser.add_argument("--start", action="store_true", help="Start the bridge server daemon")
    parser.add_argument("--stop", action="store_true", help="Stop the running bridge server daemon")
    parser.add_argument("--status", action="store_true", help="Check status of the bridge daemon")
    parser.add_argument("--daemon", action="store_true", help="Launch bridge server as a detached background daemon process")
    parser.add_argument("--port", type=int, default=41718, help="Bridge port (default: 41718)")
    parser.add_argument("--token", default=None, help="Optional authentication token")
    parser.add_argument("--annotate-crash", default=None, help="MiniDump (.dmp) file to analyze and inject into Ghidra")
    parser.add_argument("--annotate-vad", type=int, default=None, help="Process ID to inspect VAD layout and inject into Ghidra")
    parser.add_argument("--annotate-struct", default=None, help="PID or JSON report path to dissect structure and inject into Ghidra")
    parser.add_argument("--annotate-pointers", default=None, help="PID or JSON report path to resolve pointer chains and inject into Ghidra")
    parser.add_argument("--addr", default=None, help="Target address in hex (e.g. 0x140001000) for struct or pointer scan")
    parser.add_argument("--size", type=int, default=128, help="Size in bytes for structure dissection (default: 128)")
    parser.add_argument("--depth", type=int, default=2, help="Max pointer scan depth (default: 2)")
    parser.add_argument("--no-temp-marker", action="store_true", help="Keep discovery marker workspace-only without writing to system temp dir")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args(sys.argv[2:])

    validate_port(args.port)
    auth_token = args.token or os.environ.get("BINTRA_BRIDGE_AUTH_TOKEN")

    from ghidra_live_bridge import (
        GhidraLiveBridgeClient,
        get_or_create_bridge, get_active_bridge, stop_active_bridge
    )

    if args.stop:
        res = stop_active_bridge(port=args.port, auth_token=auth_token)
        print(json.dumps(res, indent=2))
        return

    if args.daemon:
        import subprocess
        from security import Capability, ExecutionGuard

        ExecutionGuard.request_access(
            component="cli",
            operation="ghidra-bridge-daemon",
            target=f"127.0.0.1:{args.port}",
            capability=Capability.GHIDRA_PROJECT_MUTATE,
            access_mode="EXECUTE",
            metadata={"port": args.port, "shell": False},
        )
        daemon_cmd = [
            sys.executable,
            os.path.abspath(sys.argv[0]),
            "ghidra-bridge",
            "--start",
            "--port", str(args.port)
        ]
        if args.no_temp_marker:
            daemon_cmd.append("--no-temp-marker")
        popen_kwargs: Dict[str, Any] = {
            "close_fds": True,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if auth_token:
            daemon_env = dict(os.environ)
            daemon_env["BINTRA_BRIDGE_AUTH_TOKEN"] = auth_token
            popen_kwargs["env"] = daemon_env
        if os.name == "nt":
            DETACHED_PROCESS = 0x00000008
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            popen_kwargs["creationflags"] = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True
        proc = subprocess.Popen(daemon_cmd, **popen_kwargs)
        print(f"[+] Launched Bintra Ghidra Bridge background daemon (PID {proc.pid}) on http://127.0.0.1:{args.port}")
        return

    if args.status:
        try:
            client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{args.port}", auth_token=auth_token)
            st = client.call_rpc("get_status")
            print(json.dumps(st, indent=2, ensure_ascii=False))
        except Exception as e:
            print(json.dumps({"is_running": False, "error": str(e)}, indent=2))
        return

    def _bridge_rpc(client, method, payload):
        """Single bridge RPC path: remote client first, active in-process bridge as fallback."""
        try:
            return client.call_rpc(method, payload)
        except Exception as rpc_exc:
            act = get_active_bridge()
            if act and act.is_running:
                fallback_fn = {
                    "bintra.inject_crash_rca": act.inject_crash_rca,
                    "bintra.inject_vad_snapshot": act.inject_vad_snapshot,
                    "bintra.inject_structure_dissection": act.inject_structure_dissection,
                    "bintra.inject_pointer_chains": act.inject_pointer_chains,
                }.get(method)
                if fallback_fn:
                    return fallback_fn(payload.get("rca_report") or payload.get("vad_snapshot")
                                       or payload.get("struct_report") or payload.get("pointer_report"))
            return {"status": "error", "message": f"Bridge communication error: {rpc_exc}"}

    def _dispatch_inject(method: str, key: str, report: Any) -> None:
        client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{args.port}", auth_token=auth_token)
        inj = _bridge_rpc(client, method, {key: report})
        print(json.dumps(inj, indent=2, ensure_ascii=False))

    if args.annotate_crash:
        from windows_intelligence import CrashRootCauseAnalyzer
        _dispatch_inject("bintra.inject_crash_rca", "rca_report", CrashRootCauseAnalyzer.analyze_crash(args.annotate_crash))
        return

    if args.annotate_vad:
        from windows_intelligence import VirtualMemoryInspector
        _dispatch_inject("bintra.inject_vad_snapshot", "vad_snapshot", VirtualMemoryInspector.inspect_process(args.annotate_vad).to_dict())
        return

    if args.annotate_struct:
        if os.path.isfile(args.annotate_struct):
            with open(args.annotate_struct, "r", encoding="utf-8") as f:
                struct_rep = json.load(f)
        else:
            target_pid = parse_int_arg(args.annotate_struct, "--annotate-struct")
            if not args.addr:
                print(json.dumps({"status": "error", "message": "--addr is required when --annotate-struct is a PID"}, indent=2))
                return
            base_addr = parse_int_arg(args.addr, "--addr")
            from windows_intelligence import StructureDissector
            struct_rep = StructureDissector.dissect(target_pid, base_addr, size=args.size)

        _dispatch_inject("bintra.inject_structure_dissection", "struct_report", struct_rep)
        return

    if args.annotate_pointers:
        if os.path.isfile(args.annotate_pointers):
            with open(args.annotate_pointers, "r", encoding="utf-8") as f:
                ptr_rep = json.load(f)
        else:
            target_pid = parse_int_arg(args.annotate_pointers, "--annotate-pointers")
            if not args.addr:
                print(json.dumps({"status": "error", "message": "--addr is required when --annotate-pointers is a PID"}, indent=2))
                return
            target_addr = parse_int_arg(args.addr, "--addr")
            from windows_intelligence import PointerScanner
            ptr_rep = PointerScanner.find_pointer_paths(target_pid, target_addr, max_depth=args.depth)

        _dispatch_inject("bintra.inject_pointer_chains", "pointer_report", ptr_rep)
        return

    # Default / --start: start bridge server in foreground
    server = get_or_create_bridge(
        port=args.port,
        auth_token=auth_token,
        publish_temp_marker=not args.no_temp_marker,
    )
    print(f"[*] Bintra Ghidra Live Bridge running on http://127.0.0.1:{server.port}")
    print(f"[*] Auth Token: {server.auth_token}")
    print(f"[*] Marker File: {getattr(server, '_marker_path', 'None')}")
    print("[*] Press Ctrl+C to shutdown bridge server...")
    try:
        while server.is_running:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[*] Stopping Ghidra Live Bridge...")
        server.stop()
        print("[+] Bridge stopped cleanly.")
    return


def cmd_ghidra_similar(cmd: str) -> None:
    """bintra ghidra-similar"""
    ap = argparse.ArgumentParser(
        prog="bintra ghidra-similar",
        description="Behavioral nearest-routine search: rank all functions in a Ghidra export against a reference (64-D High P-Code cosine similarity)"
    )
    ap.add_argument("--input", required=True, help="Path to Ghidra export (.json, .jsonl, or .db)")
    ap.add_argument("--function", default=None, help="Reference function name or entry address inside the export")
    ap.add_argument("--pcode-file", default=None, help="Path to a JSON file containing an external P-code operation stream (list of ops or {pcode_ops: [...]})")
    ap.add_argument("--threshold", type=float, default=0.75, help="Minimum cosine similarity to report (default 0.75)")
    ap.add_argument("--limit", type=int, default=20, help="Maximum matches to return (default 20)")
    ap.add_argument("--min-pcode-ops", type=int, default=1, help="Minimum P-code ops for indexed functions (default 1; raise to skip thunks)")
    ap.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    ns = ap.parse_args(sys.argv[2:])
    if not ns.function and not ns.pcode_file:
        ap.error("Either --function (in-export reference) or --pcode-file (external P-code stream) is required")
    from ghidra_export_store import GhidraExportStore
    ref_pcode = None
    if ns.pcode_file:
        with open(ns.pcode_file, "r", encoding="utf-8") as pf:
            pcode_payload = json.load(pf)
        if isinstance(pcode_payload, dict):
            ref_pcode = pcode_payload.get("pcode_ops") or pcode_payload.get("pcode")
        elif isinstance(pcode_payload, list):
            ref_pcode = pcode_payload
        if not isinstance(ref_pcode, list) or not ref_pcode:
            print(json.dumps({"status": "error", "message": "P-code reference file must contain a non-empty list of operations."}, indent=2))
            sys.exit(1)
    with GhidraExportStore.from_path(ns.input) as store:
        sim_res = store.search_similar_functions(
            reference_function=ns.function,
            reference_pcode=ref_pcode,
            threshold=ns.threshold,
            limit=ns.limit,
            min_pcode_ops=ns.min_pcode_ops,
        )
    if ns.format == "md":
        md_lines = ["# Bintra P-Code Similar Function Search", ""]
        md_lines.append(f"- **Export:** `{ns.input}`")
        md_lines.append(f"- **Reference:** `{ns.function or 'external P-code stream'}`")
        md_lines.append(f"- **Indexed functions:** {sim_res.get('indexed_functions', 0)} (skipped: {sim_res.get('skipped_functions', 0)})")
        md_lines.append(f"- **Threshold:** {sim_res.get('threshold', ns.threshold)}")
        md_lines.append("")
        if sim_res.get("matches"):
            md_lines.append("| Rank | Similarity | Match | Confidence | Function | Entry | P-Code Ops |")
            md_lines.append("| :---: | :---: | :---: | :---: | :--- | :--- | :---: |")
            for rank_i, m in enumerate(sim_res["matches"], 1):
                md_lines.append(
                    f"| {rank_i} | {m['pcode_cosine_similarity']:.4f} | {'YES' if m['is_semantic_match'] else 'no'} "
                    f"| {m['confidence']} | `{m['function_name']}` | `{m.get('entry_point', 'N/A')}` | {m.get('pcode_op_count', 'N/A')} |"
                )
        else:
            md_lines.append("_No functions met the similarity threshold._")
        print("\n".join(md_lines))
    else:
        print(json.dumps(sim_res, indent=2))


def cmd_ghidra_callgraph(cmd: str) -> None:
    """bintra ghidra-callgraph"""
    ap = argparse.ArgumentParser(prog="bintra ghidra-callgraph")
    ap.add_argument("--input", required=True, help="Path to Ghidra export (.json, .jsonl, or .db)")
    ap.add_argument("--function", default=None)
    ap.add_argument("--max-depth", type=int, default=4)
    ns = ap.parse_args(sys.argv[2:])
    from ghidra_pcode_vectorizer import GhidraDeepAnalyzer
    from ghidra_export_store import GhidraExportStore
    with GhidraExportStore.from_path(ns.input) as store:
        print(json.dumps(GhidraDeepAnalyzer().build_call_graph_and_xrefs(store, target_function=ns.function, max_depth=ns.max_depth), indent=2))


def cmd_ghidra_dataflow(cmd: str) -> None:
    """bintra ghidra-dataflow"""
    ap = argparse.ArgumentParser(prog="bintra ghidra-dataflow")
    ap.add_argument("--input", required=True, help="Path to Ghidra export (.json, .jsonl, or .db)")
    ap.add_argument("--function", required=True)
    ap.add_argument("--var", default=None)
    ns = ap.parse_args(sys.argv[2:])
    from ghidra_pcode_vectorizer import GhidraDeepAnalyzer
    from ghidra_export_store import GhidraExportStore
    with GhidraExportStore.from_path(ns.input) as store:
        fn_obj = store.get_function(ns.function)
        if not fn_obj:
            print(json.dumps({"status": "not_found", "function": ns.function}, indent=2))
            sys.exit(1)
        print(json.dumps(GhidraDeepAnalyzer().slice_data_flow(fn_obj, target_var=ns.var), indent=2))

