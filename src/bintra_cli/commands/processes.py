"""Bintra CLI commands: Live process inventory, mitigations, module hosting, file locks and leak profiling."""
import argparse
import json
import sys


from windows_intelligence import (
    ProcessMitigationInspector
)


def cmd_process_mitigations(cmd: str) -> None:
    """bintra process-mitigations"""
    parser = argparse.ArgumentParser(description="Inspect Windows process exploit mitigations (DEP, ASLR, CFG)")
    parser.add_argument("command")
    parser.add_argument("--pid", type=int, required=True, help="Target process ID")
    args = parser.parse_args()

    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="process-mitigations",
        target=f"pid:{args.pid}",
        capability=Capability.PROCESS_QUERY,
        access_mode="QUERY",
    )
    res = ProcessMitigationInspector.inspect_process(pid=args.pid)
    print(json.dumps(res, indent=2, default=str))
    return


def cmd_file_locks(cmd: str) -> None:
    """bintra file-locks"""
    parser = argparse.ArgumentParser(prog="bintra file-locks", description="Detect processes locking a target file")
    parser.add_argument("--file", required=True, help="Path to file to inspect")
    args = parser.parse_args(sys.argv[2:])
    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="file-locks",
        target=args.file,
        capability=Capability.PROCESS_QUERY,
        access_mode="QUERY"
    )
    from windows_intelligence.process_intelligence import FileUsageInspector
    res = FileUsageInspector.inspect_file_locks(args.file)
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return


def cmd_proc_modules(cmd: str) -> None:
    """bintra proc-modules"""
    parser = argparse.ArgumentParser(prog="bintra proc-modules", description="Find processes hosting a loaded DLL")
    parser.add_argument("--module", required=True, help="Module/DLL name or keyword")
    args = parser.parse_args(sys.argv[2:])
    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="proc-modules",
        target=args.module,
        capability=Capability.PROCESS_QUERY,
        access_mode="QUERY"
    )
    from windows_intelligence.process_intelligence import ModuleInventory
    res = ModuleInventory.find_processes_hosting_module(args.module)
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return


def cmd_proc_list(cmd: str) -> None:
    """bintra proc-list"""
    parser = argparse.ArgumentParser(prog="bintra proc-list", description="List running processes with Task Manager telemetry")
    parser.add_argument("--limit", type=int, default=50, help="Maximum processes to display (default: 50)")
    parser.add_argument("--sort", choices=["memory", "commit", "threads", "handles", "pid", "name"], default="memory", help="Sort column")
    parser.add_argument("--query", default=None, help="Filter by name, PID, or image path")
    parser.add_argument("--resolve-users", action="store_true", help="Resolve Windows user accounts")
    parser.add_argument("--format", choices=["json", "md"], default="md", help="Output format")
    args = parser.parse_args(sys.argv[2:])
    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="proc-list",
        target="ProcessTable",
        capability=Capability.PROCESS_QUERY,
        access_mode="QUERY"
    )
    from windows_intelligence.process_intelligence import TaskManagerInspector
    res = TaskManagerInspector.list_processes(limit=args.limit, sort_by=args.sort, query=args.query, resolve_users=args.resolve_users)
    if args.format == "md":
        lines = [
            f"# Windows Task Manager - Active Processes ({res.get('matched_processes', len(res.get('processes', [])))} matches)",
            f"- **Total System Processes:** {res.get('total_processes', 0)}",
            f"- **Sorted By:** `{res.get('sort_by', 'memory')}`",
            "",
            "| PID | Name | RAM (MB) | Commit (MB) | Threads | Handles | Session | Arch | User |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for p in res.get("processes", []):
            lines.append(
                f"| {p.get('process_id')} | `{p.get('executable_name')}` | {p.get('working_set_mb', 0.0):.2f} | "
                f"{p.get('commit_mb', 0.0):.2f} | {p.get('thread_count', 0)} | {p.get('handle_count', 0)} | "
                f"{p.get('session_id', 0)} | {p.get('architecture', 'Unknown')} | {p.get('user', 'Unknown')} |"
            )
        print("\n".join(lines))
    else:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    return


def cmd_proc_search(cmd: str) -> None:
    """bintra proc-search"""
    parser = argparse.ArgumentParser(prog="bintra proc-search", description="Search processes by keyword, PID, or name")
    parser.add_argument("--query", required=True, help="Search query (substring in name, PID, user, or image path)")
    parser.add_argument("--limit", type=int, default=25, help="Maximum results (default: 25)")
    parser.add_argument("--format", choices=["json", "md"], default="md", help="Output format")
    args = parser.parse_args(sys.argv[2:])
    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="proc-search",
        target=args.query,
        capability=Capability.PROCESS_QUERY,
        access_mode="QUERY"
    )
    from windows_intelligence.process_intelligence import TaskManagerInspector
    res = TaskManagerInspector.search_processes(query=args.query, max_results=args.limit)
    if args.format == "md":
        lines = [
            f"# Process Search Results for `{args.query}` ({res.get('matched_processes', 0)} matches)",
            "",
            "| PID | Name | RAM (MB) | Commit (MB) | Threads | Handles | Session | Arch | Image Path |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for p in res.get("processes", []):
            img = p.get("image_path") or "N/A"
            lines.append(
                f"| {p.get('process_id')} | `{p.get('executable_name')}` | {p.get('working_set_mb', 0.0):.2f} | "
                f"{p.get('commit_mb', 0.0):.2f} | {p.get('thread_count', 0)} | {p.get('handle_count', 0)} | "
                f"{p.get('session_id', 0)} | {p.get('architecture', 'Unknown')} | `{img}` |"
            )
        print("\n".join(lines))
    else:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    return


def cmd_proc_info(cmd: str) -> None:
    """bintra proc-info"""
    parser = argparse.ArgumentParser(prog="bintra proc-info", description="Deep Task Manager forensic telemetry for a process")
    parser.add_argument("--pid", type=int, required=True, help="Target process ID (PID)")
    parser.add_argument("--format", choices=["json", "md"], default="md", help="Output format")
    args = parser.parse_args(sys.argv[2:])
    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="proc-info",
        target=str(args.pid),
        capability=Capability.PROCESS_QUERY,
        access_mode="QUERY"
    )
    from windows_intelligence.process_intelligence import TaskManagerInspector
    res = TaskManagerInspector.get_process_details(args.pid)
    if args.format == "md":
        mem = res.get("memory", {})
        cpu = res.get("cpu_and_timing", {})
        ioc = res.get("io_counters", {})
        sec = res.get("security", {})
        mit = res.get("mitigations", {})
        lines = [
            f"# Process Telemetry Dossier: PID {res.get('process_id')} (`{res.get('executable_name')}`)",
            f"- **Status:** `{res.get('status')}`",
            f"- **Parent PID:** `{res.get('parent_process_id')}`",
            f"- **Image Path:** `{res.get('image_path')}`",
            f"- **Command Line:** `{res.get('command_line')}`",
            f"- **Architecture:** `{res.get('architecture')}` | **Session ID:** `{res.get('session_id')}`",
            f"- **User:** `{sec.get('user')}` | **Elevated:** `{sec.get('is_elevated')}` | **Integrity:** `{sec.get('integrity_level')}`",
            f"- **Threads:** {res.get('thread_count')} | **Handles:** {res.get('handle_count')}",
            "",
            "## Memory Telemetry (PSAPI)",
            f"- **Working Set (RAM):** {mem.get('working_set_mb', 0.0):.2f} MB (Peak: {mem.get('peak_working_set_mb', 0.0):.2f} MB)",
            f"- **Commit Charge:** {mem.get('commit_mb', 0.0):.2f} MB (Peak: {mem.get('peak_commit_mb', 0.0):.2f} MB)",
            f"- **Paged / Non-Paged Pool:** {mem.get('paged_pool_mb', 0.0):.2f} MB / {mem.get('non_paged_pool_mb', 0.0):.2f} MB",
            f"- **Page Faults:** {mem.get('page_fault_count', 0):,}",
            "",
            "## CPU & Lifetime Telemetry",
            f"- **Creation Time (UTC):** `{cpu.get('creation_time_utc')}`",
            f"- **Uptime:** {cpu.get('uptime_hours', 0.0)} hours ({cpu.get('uptime_seconds', 0.0):.1f} s)",
            f"- **CPU Total:** {cpu.get('total_cpu_time_seconds', 0.0):.2f} s (User: {cpu.get('user_cpu_time_seconds', 0.0):.2f} s, Kernel: {cpu.get('kernel_cpu_time_seconds', 0.0):.2f} s)",
            "",
            "## I/O Counters",
            f"- **Read Data:** {ioc.get('read_transfer_mb', 0.0):.2f} MB ({ioc.get('read_operation_count', 0):,} ops)",
            f"- **Write Data:** {ioc.get('write_transfer_mb', 0.0):.2f} MB ({ioc.get('write_operation_count', 0):,} ops)",
            "",
            "## Exploit Mitigations",
            f"- **DEP:** `{mit.get('dep', {}).get('enabled')}` (Permanent: `{mit.get('dep', {}).get('permanent')}`)",
            f"- **ASLR:** `{mit.get('aslr', {}).get('bottom_up_randomization')}` (High Entropy: `{mit.get('aslr', {}).get('high_entropy')}`)",
            f"- **CFG:** `{mit.get('cfg', {}).get('enabled')}`",
            "",
            "## Network & Services",
            f"- **Active TCP Sockets:** {len(res.get('active_tcp_connections', []))}",
            f"- **Hosted Services:** {len(res.get('hosted_services', []))}",
            f"- **Loaded Modules Sample:** {res.get('loaded_modules_count', 0)} total"
        ]
        print("\n".join(lines))
    else:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    return


def cmd_sys_perf(cmd: str) -> None:
    """bintra sys-perf"""
    parser = argparse.ArgumentParser(prog="bintra sys-perf", description="Windows Task Manager Performance Tab overview")
    parser.add_argument("--format", choices=["json", "md"], default="md", help="Output format")
    args = parser.parse_args(sys.argv[2:])
    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="sys-perf",
        target="SystemPerformance",
        capability=Capability.DEVICE_QUERY,
        access_mode="QUERY"
    )
    from windows_intelligence.process_intelligence import TaskManagerInspector
    res = TaskManagerInspector.get_system_performance()
    if args.format == "md":
        mem = res.get("memory", {})
        upt = res.get("uptime", {})
        top = res.get("topology", {})
        lines = [
            "# Windows Task Manager - System Performance Overview",
            f"- **Status:** `{res.get('status')}`",
            f"- **Instant CPU Utilization:** **{res.get('cpu_utilization_percent', 0.0)}%**",
            "",
            "## Physical Memory (RAM)",
            f"- **Total Installed:** {mem.get('total_physical_gb', 0.0)} GB",
            f"- **In Use:** {mem.get('used_physical_gb', 0.0)} GB ({mem.get('memory_load_percent', 0)}%)",
            f"- **Available:** {mem.get('available_physical_gb', 0.0)} GB",
            "",
            "## Commit Limits (Pagefile)",
            f"- **Committed:** {mem.get('committed_gb', 0.0)} GB / {mem.get('commit_limit_gb', 0.0)} GB ({mem.get('commit_percent', 0.0)}%)",
            "",
            "## System Uptime & Topology",
            f"- **System Uptime:** {upt.get('uptime_days', 0.0)} days ({upt.get('uptime_hours', 0.0)} hours)",
            f"- **Boot Time (UTC):** `{upt.get('boot_time_utc')}`",
            f"- **Total Active Processes:** {top.get('total_processes', 0):,}",
            f"- **Total Active Threads:** {top.get('total_threads', 0):,}",
        ]
        print("\n".join(lines))
    else:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    return


def cmd_proc_profile(cmd: str) -> None:
    """bintra proc-profile, process-profile, leak-audit"""
    parser = argparse.ArgumentParser(prog=f"bintra {cmd}", description="Process longitudinal resource profiler and leak diagnosis engine (Private Bytes, Working Set, Handles, GDI/USER)")
    parser.add_argument("command", help="Command name or positional argument")
    parser.add_argument("pos_pid", nargs="?", type=int, default=None, help="Target process ID (PID)")
    parser.add_argument("--pid", "-p", dest="flag_pid", type=int, default=None, help="Target process ID (PID)")
    parser.add_argument("--samples", "-n", type=int, default=10, help="Number of consecutive samples to record (default: 10)")
    parser.add_argument("--interval", "-i", type=float, default=0.2, help="Sampling interval in seconds (default: 0.2)")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format (json or md)")
    args = parser.parse_args(sys.argv[1:])
    target_pid = args.flag_pid or args.pos_pid
    if target_pid is None:
        parser.error("Target process PID is required (positional or via -p / --pid)")

    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation=cmd,
        target=f"pid:{target_pid}",
        capability=Capability.PROCESS_QUERY,
        # QUERY (not READ): READ triggers filesystem path canonicalization,
        # which rejects "pid:N" on Windows as an Alternate Data Stream.
        access_mode="QUERY",
        metadata={"command": cmd, "pid": target_pid}
    )

    from windows_intelligence.process_intelligence import ProcessLongitudinalProfiler
    report = ProcessLongitudinalProfiler.profile_pid_longitudinal(
        pid=target_pid,
        samples_count=args.samples,
        interval_seconds=args.interval
    )
    if args.format == "md":
        m = report.get("metrics_summary", {})
        lines = [
            f"# Process Longitudinal Profiling Report: PID `{target_pid}`",
            f"- **Classification:** `{report.get('behavior_classification')}`",
            f"- **Diagnosis:** {report.get('diagnostic_explanation')}",
            f"- **Total Samples:** {report.get('total_samples')}",
            f"- **Private Bytes (MB):** Initial={m.get('initial_private_bytes_mb')} -> Final={m.get('final_private_bytes_mb')} (Delta={m.get('delta_private_bytes_mb')}, Slope={m.get('slope_private_bytes_mb_per_sample')} MB/sample)",
            f"- **Working Set (MB):** Initial={m.get('initial_working_set_mb')} -> Final={m.get('final_working_set_mb')} (Delta={m.get('delta_working_set_mb')})",
            f"- **Kernel Handles:** Initial={m.get('initial_kernel_handles')} -> Final={m.get('final_kernel_handles')} (Delta={m.get('delta_kernel_handles')})",
            f"- **GDI Handles:** Initial={m.get('initial_gdi_handles')} -> Final={m.get('final_gdi_handles')} (Delta={m.get('delta_gdi_handles')})",
            f"- **Saturation Plateau:** {m.get('is_saturation_plateau', False)}"
        ]
        print("\n".join(lines))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return

