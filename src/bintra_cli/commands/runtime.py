"""Bintra CLI commands: Runtime telemetry: MiniDumps, crash RCA, VAD, memory/pointer scans, ETW."""
import argparse
import json
import os
import sys
import time


from windows_intelligence import (
    MiniDumpParser, EtwController, VirtualMemoryInspector, CrashRootCauseAnalyzer,
    EtwLiveCaptureSession, EtwTimelineCorrelator,
    ProcessMemoryScanner, PointerScanner, StructureDissector
)


def cmd_dmp_inspect(cmd: str) -> None:
    """bintra dmp-inspect"""
    parser = argparse.ArgumentParser(description="Multi-stream MiniDump crash inspection and root cause analysis")
    parser.add_argument("command")
    parser.add_argument("--file", "--dmp", dest="file", default=None, help="Path to .dmp file (if omitted, scans standard dump paths)")
    parser.add_argument("--scan", action="store_true", help="Scan system for recent crash dumps")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args()

    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="dmp-inspect",
        target=args.file or "AllCrashDumps",
        capability=Capability.MINIDUMP_READ,
        access_mode="QUERY"
    )

    if args.file:
        report = MiniDumpParser.parse_minidump(args.file)
    else:
        report = MiniDumpParser.audit_dumps()

    if args.format == "md":
        if "crash_reports" in report:
            lines = [
                "# System Crash Dump Audit Summary",
                f"- **Total Dumps Discovered:** {report.get('total_dumps_discovered', 0)}",
                f"- **Dumps Analyzed:** {report.get('dumps_analyzed', 0)}",
                ""
            ]
            for cr in report.get("crash_reports", []):
                lines.append(f"### Dump: `{cr.get('file_path')}`")
                exc = cr.get("exception_info") or {}
                lines.append(f"- **Exception:** `{exc.get('exception_code')}` ({exc.get('exception_name')})")
                lines.append(f"- **Faulting Module:** `{exc.get('fault_module')}` (Offset: `{exc.get('fault_offset')}`)")
                if "access_violation_details" in exc:
                    av = exc["access_violation_details"]
                    lines.append(f"- **Access Violation:** `{av.get('operation')}` at `{av.get('target_virtual_address')}`")
                    lines.append(f"- **Cause:** {av.get('probable_cause')}")
                lines.append("")
            print("\n".join(lines))
        else:
            exc = report.get("exception_info") or {}
            sys_info = report.get("system_info") or {}
            lines = [
                f"# MiniDump Crash Inspection: `{os.path.basename(report.get('file_path', 'dump.dmp'))}`",
                f"- **Status:** {report.get('status')}",
                f"- **OS Version:** {sys_info.get('os_version', 'Unknown')} ({sys_info.get('processor_architecture', 'Unknown')})",
                f"- **Stream Count:** {report.get('stream_count', 0)}",
                f"- **Loaded Modules:** {report.get('module_count', 0)}",
                f"- **Active Threads:** {report.get('thread_count', 0)}",
                "",
                "## Exception Telemetry:",
                f"- **Exception Code:** `{exc.get('exception_code')}` ({exc.get('exception_name')})",
                f"- **Fault Address:** `{exc.get('exception_address')}`",
                f"- **Fault Module:** `{exc.get('fault_module')}` (Offset: `{exc.get('fault_offset')}`)"
            ]
            if "access_violation_details" in exc:
                av = exc["access_violation_details"]
                lines.append("\n## Access Violation Diagnostic:")
                lines.append(f"- **Operation:** `{av.get('operation')}`")
                lines.append(f"- **Target Address:** `{av.get('target_virtual_address')}`")
                lines.append(f"- **NULL Pointer Dereference:** `{av.get('is_null_pointer_dereference')}`")
                lines.append(f"- **Diagnostic Explanation:** {av.get('probable_cause')}")
            print("\n".join(lines))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return


def cmd_vad_inspect(cmd: str) -> None:
    """bintra vad-inspect"""
    parser = argparse.ArgumentParser(prog="bintra vad-inspect", description="Inspect passive virtual memory map (VAD) and classify addresses")
    parser.add_argument("--pid", type=int, required=True, help="Target process PID to inspect")
    parser.add_argument("--address", default=None, help="Optional virtual memory address to classify (e.g. '0x7fff12340000')")
    parser.add_argument("--regions", action="store_true", help="Include full listing of contiguous memory regions")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args(sys.argv[2:])

    snapshot = VirtualMemoryInspector.inspect_process(args.pid)
    if args.address is not None:
        parsed_addr = int(args.address, 0)
        res = snapshot.classify_address(parsed_addr)
    else:
        res = snapshot.to_dict(include_regions=args.regions)

    if args.format == "md":
        if args.address is not None:
            lines = [
                f"# Address Classification: `{res['address']}`",
                f"- **Category:** `{res.get('category')}`",
                f"- **Status:** `{res.get('status')}`",
                f"- **Protection:** `{res.get('protect')}`",
            ]
            if res.get("module_name"):
                lines.append(f"- **Module:** `{res.get('module_name')}` (RVA: `{res.get('rva')}`)")
            if res.get("description"):
                lines.append(f"- **Description:** {res.get('description')}")
            print("\n".join(lines))
        else:
            sum_data = res["summary"]
            lines = [
                f"# Virtual Memory (VAD) Map for PID {args.pid} (`{res['process_name']}`)",
                f"- **Committed Memory:** {sum_data['commit_mb']} MB ({sum_data['commit_bytes']} bytes)",
                f"- **Image Sections (DLL/EXE):** {sum_data['image_mb']} MB",
                f"- **Private Heap:** {sum_data['heap_mb']} MB",
                f"- **Thread Stacks:** {sum_data['stack_kb']} KB",
                f"- **W^X Violations (Writable+Executable):** {sum_data['wx_regions_count']}",
                f"- **Total Contiguous Regions:** {sum_data['total_regions']}",
            ]
            print("\n".join(lines))
    else:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    return


def cmd_mem_scan(cmd: str) -> None:
    """bintra mem-scan"""
    parser = argparse.ArgumentParser(prog="bintra mem-scan", description="Non-intrusive read-only memory value search (First/Next scan)")
    parser.add_argument("--pid", type=int, required=True, help="Target process PID to scan")
    parser.add_argument("--type", default="int32", choices=["int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64", "float", "double", "bytes", "string"], help="Data type to scan")
    parser.add_argument("--mode", default="exact", choices=["exact", "between", "unknown", "increased", "decreased", "changed", "unchanged"], help="Scan mode")
    parser.add_argument("--value", default=None, help="Target value (or hex string for bytes)")
    parser.add_argument("--high-value", default=None, help="High value for 'between' scan mode")
    parser.add_argument("--session-file", default=None, help="Path to state file to enable iterative First Scan -> Next Scan filtering")
    parser.add_argument("--max-results", type=int, default=100, help="Maximum number of matches to display")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args(sys.argv[2:])

    from security import ExecutionGuard, Capability, SafeFileAccess, SecurityViolationError
    ExecutionGuard.request_access(
        component="cli",
        operation="mem-scan",
        target=f"PID_{args.pid}",
        capability=Capability.PROCESS_QUERY,
        access_mode="READ"
    )
    if args.session_file:
        ExecutionGuard.request_access(
            component="cli",
            operation="mem-scan-session-write",
            target=args.session_file,
            capability=Capability.WORKSPACE_WRITE,
            access_mode="WRITE"
        )

    val = args.value
    high_val = args.high_value
    if val is not None:
        if args.type in ("int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64"):
            val = int(val, 0)
        elif args.type in ("float", "double"):
            val = float(val)
        elif args.type == "bytes":
            val = bytes.fromhex(val.replace(" ", "").replace("0x", ""))
    if high_val is not None:
        if args.type in ("int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64"):
            high_val = int(high_val, 0)
        elif args.type in ("float", "double"):
            high_val = float(high_val)

    mode_map = {
        "exact": "EXACT_VALUE",
        "between": "VALUE_BETWEEN",
        "unknown": "UNKNOWN_INITIAL_VALUE",
        "increased": "INCREASED_VALUE",
        "decreased": "DECREASED_VALUE",
        "changed": "CHANGED_VALUE",
        "unchanged": "UNCHANGED_VALUE",
    }
    scan_mode = mode_map.get(args.mode, "EXACT_VALUE")

    sid = None
    if args.session_file and os.path.exists(args.session_file):
        try:
            raw_session = SafeFileAccess.read_text(args.session_file)
            session_data = json.loads(raw_session)
            state = session_data.get("session_state") if isinstance(session_data, dict) else None
            if state:
                # Full state persisted by a previous CLI process: restore it here.
                sid = ProcessMemoryScanner.import_session(state)
            else:
                sid = session_data.get("session_id")
        except SecurityViolationError:
            raise
        except Exception:
            pass

    if sid:
        res = ProcessMemoryScanner.next_scan(
            session_id=sid,
            scan_type=scan_mode,
            value=val,
            min_val=val,
            max_val=high_val
        )
    else:
        res = ProcessMemoryScanner.first_scan(
            pid=args.pid,
            data_type=args.type,
            scan_type=scan_mode,
            value=val,
            min_val=val,
            max_val=high_val
        )

    if args.session_file and res.get("session_id"):
        persisted = dict(res)
        persisted["session_state"] = ProcessMemoryScanner.export_session(res["session_id"])
        SafeFileAccess.write_workspace_file(args.session_file, json.dumps(persisted))

    if args.format == "md":
        is_next = "surviving_count" in res
        total = res.get("surviving_count") if is_next else res.get("total_candidates", 0)
        sample = res.get("surviving_sample") if is_next else res.get("candidates_sample", [])
        lines = [
            f"# Memory Scan Report (PID: {args.pid})",
            f"- **Scan Pass:** `{'Next Scan' if is_next else 'First Scan'}` (Session ID: `{res.get('session_id')}`)",
            f"- **Type / Mode:** `{args.type}` / `{scan_mode}`",
            f"- **Total Candidates Found:** {total}",
            "",
            "| Address | Value | Category |",
            "| :--- | :--- | :--- |"
        ]
        for m in sample[:args.max_results]:
            addr_hex = m.get("address", "")
            cur_val = m.get("value", "")
            cat = m.get("category", "")
            lines.append(f"| `{addr_hex}` | `{cur_val}` | `{cat}` |")
        print("\n".join(lines))
    else:
        print(json.dumps(res, indent=2, ensure_ascii=False, default=str))
    return


def cmd_pointer_scan(cmd: str) -> None:
    """bintra pointer-scan"""
    parser = argparse.ArgumentParser(prog="bintra pointer-scan", description="Multi-level static module base pointer path resolver")
    parser.add_argument("--pid", type=int, required=True, help="Target process PID")
    parser.add_argument("--target", required=True, help="Target dynamic address (e.g. '0x7fff12340000')")
    parser.add_argument("--max-depth", type=int, default=2, choices=[1, 2, 3], help="Maximum pointer indirection depth")
    parser.add_argument("--max-offset", type=int, default=4096, help="Maximum struct offset (default: 4096)")
    parser.add_argument("--max-results", type=int, default=20, help="Maximum number of resolved pointer paths")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args(sys.argv[2:])

    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="pointer-scan",
        target=f"PID_{args.pid}",
        capability=Capability.PROCESS_QUERY,
        access_mode="READ"
    )

    target_addr = int(args.target, 0)
    res = PointerScanner.find_pointer_paths(
        pid=args.pid,
        target_address=target_addr,
        max_depth=args.max_depth,
        max_offset=args.max_offset,
        max_results=args.max_results
    )

    if args.format == "md":
        paths = res.get("paths", [])
        lines = [
            f"# Pointer Chain Discovery for `0x{target_addr:016X}` (PID: {args.pid})",
            f"- **Max Depth:** {args.max_depth} | **Paths Found:** {len(paths)}",
            "",
            "| Index | Base Module | Expression | Offsets |",
            "| :--- | :--- | :--- | :--- |"
        ]
        for idx, p in enumerate(paths, 1):
            mod_name = p.get("base_module") or "Unknown"
            expr = p.get("expression", "")
            offsets_str = " -> ".join(p.get("offsets", []))
            lines.append(f"| {idx} | `{mod_name}` | `{expr}` | `{offsets_str}` |")
        print("\n".join(lines))
    else:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    return


def cmd_dissect_struct(cmd: str) -> None:
    """bintra dissect-struct"""
    parser = argparse.ArgumentParser(prog="bintra dissect-struct", description="Runtime object field analysis and C struct generation")
    parser.add_argument("--pid", type=int, required=True, help="Target process PID")
    parser.add_argument("--address", required=True, help="Target object base address (e.g. '0x7fff12340000')")
    parser.add_argument("--size", type=int, default=64, help="Size of object memory to dissect in bytes (default: 64)")
    parser.add_argument("--name", default="ObjectLayout", help="Name for emitted C struct")
    parser.add_argument("--format", choices=["json", "c", "md"], default="json", help="Output format")
    args = parser.parse_args(sys.argv[2:])

    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="dissect-struct",
        target=f"PID_{args.pid}",
        capability=Capability.PROCESS_QUERY,
        access_mode="READ"
    )

    addr = int(args.address, 0)
    res = StructureDissector.dissect(pid=args.pid, base_address=addr, size=args.size)

    if args.format == "c":
        print(res.get("c_struct_definition", "// No structure definition generated"))
    elif args.format == "md":
        c_code = res.get("c_struct_definition", "")
        fields = res.get("fields", [])
        lines = [
            f"# Structure Dissection at `0x{addr:016X}` (PID: {args.pid})",
            f"- **Analyzed Size:** {args.size} bytes | **Fields Reconstructed:** {len(fields)}",
            "",
            "```c",
            c_code,
            "```",
            "",
            "| Offset | Type | Description |",
            "| :--- | :--- | :--- |"
        ]
        for f in fields:
            off_hex = f"+0x{f.get('offset', 0):04X}"
            f_type = f.get('inferred_type', 'unknown')
            desc = f.get('description', '')
            lines.append(f"| `{off_hex}` | `{f_type}` | {desc} |")
        print("\n".join(lines))
    else:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    return


def cmd_crash_rca(cmd: str) -> None:
    """bintra crash-rca"""
    parser = argparse.ArgumentParser(prog="bintra crash-rca", description="Automated Crash Root Cause Analysis (MiniDump + Disassembly)")
    parser.add_argument("--dmp", "--file", dest="dmp_path", required=True, help="Path to Windows MiniDump (.dmp) file")
    parser.add_argument("--binary", default=None, help="Optional path to target executable for machine code disassembly")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args(sys.argv[2:])

    report = CrashRootCauseAnalyzer.analyze_crash(dump_target=args.dmp_path, binary_path=args.binary)
    if args.format == "md":
        print(CrashRootCauseAnalyzer.format_markdown(report))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return


def cmd_etw_capture(cmd: str) -> None:
    """bintra etw-capture"""
    parser = argparse.ArgumentParser(prog="bintra etw-capture", description="Start real-time ETW capture session and inspect timeline")
    parser.add_argument("--session-name", default="Bintra_Diagnostic_Trace", help="Name for real-time ETW trace session")
    parser.add_argument("--pid", type=int, default=None, help="Optional target PID to filter events")
    parser.add_argument("--duration", type=float, default=2.0, help="Duration in seconds to capture live trace (default: 2.0s, max: 300s)")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args(sys.argv[2:])

    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="etw-capture",
        target=args.session_name,
        capability=Capability.EVENT_LOG_READ,
        access_mode="READ",
    )
    bounded_duration = min(max(float(args.duration), 0.1), 300.0)

    session = EtwLiveCaptureSession(session_name=args.session_name, target_pid=args.pid)
    start_res = session.start_session()
    try:
        time.sleep(bounded_duration)
    finally:
        stop_res = session.stop_session()

    timeline = session.get_timeline(pid=args.pid)
    correlation = EtwTimelineCorrelator.correlate_crash_timeline(timeline)
    correlation["session_info"] = start_res
    correlation["stop_info"] = stop_res

    if args.format == "md":
        print(EtwTimelineCorrelator.format_markdown(correlation))
    else:
        print(json.dumps(correlation, indent=2, ensure_ascii=False))
    return


def cmd_etw_audit(cmd: str) -> None:
    """bintra etw-audit"""
    parser = argparse.ArgumentParser(description="Audit ETW trace sessions and diagnostic providers")
    parser.add_argument("command")
    parser.add_argument("--session", default=None, help="Query specific session name")
    parser.add_argument("--providers", action="store_true", help="Dynamically enumerate registered system ETW providers via TDH")
    parser.add_argument("--query", default=None, help="Filter keyword for provider enumeration")
    parser.add_argument("--provider-info", default=None, help="Query live kernel instances and hosting PIDs for a provider GUID")
    parser.add_argument("--active-kernel", action="store_true", help="List active providers registered with the Windows kernel")
    parser.add_argument("--limit", type=int, default=50, help="Maximum results to return")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args()

    if args.session:
        report = EtwController.query_trace_session(args.session)
    elif args.provider_info:
        report = EtwController.query_provider_instances(args.provider_info)
    elif args.active_kernel:
        report = EtwController.audit_active_kernel_providers(limit=args.limit)
    elif args.providers or args.query:
        report = EtwController.enumerate_registered_providers(query=args.query, limit=args.limit)
    else:
        report = EtwController.audit_telemetry_system()

    if args.format == "md":
        if "providers" in report and isinstance(report["providers"], list):
            lines = [
                "# ETW Registered Providers Enumeration",
                f"- **Total System Providers:** {report.get('total_system_providers')}",
                f"- **Matched Providers:** {report.get('matched_count')}",
                "",
                "| Provider Name | GUID | Schema |",
                "|---|---|---|"
            ]
            for p in report.get("providers", []):
                lines.append(f"| `{p.get('name')}` | `{p.get('guid')}` | {p.get('schema_source')} |")
            print("\n".join(lines))
        elif "active_kernel_providers_count" in report and "sessions" not in report:
            lines = [
                "# Active Windows Kernel ETW Providers",
                f"- **Total Kernel Registered Providers:** {report.get('active_kernel_providers_count')}",
                "",
                "### Sample Registered GUIDs:"
            ]
            for g in report.get("sample_guids", []):
                lines.append(f"- `{g}`")
            print("\n".join(lines))
        elif "instance_count" in report:
            lines = [
                f"# ETW Provider Instance Info: `{report.get('guid')}`",
                f"- **Status:** `{report.get('status')}`",
                f"- **Active Instances in Kernel:** {report.get('instance_count')}",
                "",
                "| PID | Enable Count | Is Enabled |",
                "|---|---|---|"
            ]
            for inst in report.get("instances", []):
                lines.append(f"| `{inst.get('pid')}` | {inst.get('enable_count')} | {inst.get('is_enabled')} |")
            print("\n".join(lines))
        elif "sessions" in report:
            lines = [
                "# ETW Telemetry Infrastructure Audit",
                f"- **Probed Sessions:** {report.get('standard_sessions_probed', 0)}",
                f"- **Active Sessions:** {report.get('active_sessions_count', 0)} ({', '.join(report.get('active_sessions', []))})",
                f"- **System Registered Providers (TDH):** {report.get('system_total_registered_providers', 0)}",
                f"- **Active Kernel Providers:** {report.get('active_kernel_providers_count', 0)}",
                "",
                "## High-Value Diagnostic Providers:"
            ]
            for pname, pdata in report.get("providers", {}).items():
                lines.append(f"- **`{pname}`** ({pdata.get('category')}): `{pdata.get('guid')}`")
                lines.append(f"  *{pdata.get('diagnostic_value')}*")
            print("\n".join(lines))
        else:
            lines = [
                f"# ETW Session Query: `{report.get('session_name')}`",
                f"- **Active:** {report.get('is_active')}",
                f"- **Status Code:** {report.get('status_code')}",
                f"- **Description:** {report.get('status_description')}"
            ]
            print("\n".join(lines))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return

