"""Bintra CLI commands: Windows host profiling, dependency resolution, crash correlation and registry intelligence."""
import argparse
import json
import os
import sys


from windows_intelligence import (
    WindowsOSProfiler, WindowsDependencyResolver, WindowsDeviceInspector,
    WindowsSecurityInspector, WindowsCrashAnalyzer, DiagnosticEvidenceCorrelator,
    CommandCatalog, CommandExecutor, WindowsRegistryAnalyzer
)


def cmd_win_audit(cmd: str) -> None:
    """bintra win-audit"""
    parser = argparse.ArgumentParser(description="Profile host Windows OS, devices, and security context")
    parser.add_argument("command")
    parser.add_argument("--binary", "--file", dest="binary", default=None, help="Optional executable to inspect for compatibility shims")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args()

    report = {
        "os": WindowsOSProfiler.profile(args.binary),
        "devices": WindowsDeviceInspector.audit(),
        "security": WindowsSecurityInspector.audit(args.binary)
    }
    if args.format == "md":
        os_rep = report.get("os", {})
        sec_rep = report.get("security", {})
        dev_rep = report.get("devices", {})
        if os_rep.get("status") == "not_applicable" or "kernel" not in os_rep:
            lines = [
                "# Windows System Intelligence Profile",
                f"- **Status:** `{os_rep.get('status', 'unavailable')}`",
                f"- **Note:** {os_rep.get('message', 'Windows OS profiling is only available on Windows NT hosts.')}",
            ]
        else:
            kernel = os_rep.get("kernel", {})
            arch = os_rep.get("architecture", {})
            lines = [
                "# Windows System Intelligence Profile",
                f"- **OS:** {kernel.get('friendly_name', 'Unknown')} (Build {kernel.get('build_number', 'Unknown')})",
                f"- **Native Architecture:** {arch.get('native_architecture', 'Unknown')}",
                f"- **Elevation:** Admin={sec_rep.get('is_elevated_admin')}",
                f"- **Token Integrity:** {sec_rep.get('token_integrity', {}).get('integrity_level')}",
                f"- **Active Graphics Adapters:** {len(dev_rep.get('graphics_adapters', []))}",
            ]
        print("\n".join(lines))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return


def cmd_registry_read(cmd: str) -> None:
    """bintra registry-read, reg-read"""
    parser = argparse.ArgumentParser(prog=f"bintra {cmd}", description="Read-only Windows Registry key and value inspection")
    parser.add_argument("pos_key", nargs="?", default="", help="Registry subkey path")
    parser.add_argument("--key", dest="named_key", default=None, help="Registry subkey path flag")
    parser.add_argument("--hive", default="HKLM", help="Registry hive (HKLM, HKCU, HKCR, HKU, HKCC)")
    parser.add_argument("--view", choices=["dual", "64", "32", "native"], default="dual", help="Architecture view perspective")
    parser.add_argument("--format", choices=["json", "md"], default="md", help="Output format")
    args = parser.parse_args(sys.argv[2:])
    target_key = args.named_key or args.pos_key
    if not target_key:
        print("Error: Subkey path is required. Example: bintra reg-read --key \"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\"")
        return

    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="registry-read",
        target=f"{args.hive}\\{target_key}",
        capability=Capability.REGISTRY_READ,
        access_mode="READ",
    )
    from windows_intelligence.registry_intelligence import WindowsRegistryReader
    res = WindowsRegistryReader.read_key(hive=args.hive, subkey=target_key, view=args.view)
    if args.format == "md":
        if res.get("status") == "not_applicable":
            print(f"# Windows Registry - {args.hive}\\{target_key}\n- **Status:** `not_applicable` (Requires Windows NT)")
            return
        if res.get("status") == "error":
            print(f"# Windows Registry - Error\n- **Error:** {res.get('error')}")
            return

        # If dual view, show 64-bit primarily and report any discrepancies
        view_obj = res.get("view_64") if "view_64" in res else res.get("result", {})
        if not view_obj.get("exists"):
            print(f"# Windows Registry - Key Not Found\n- **Target:** `{args.hive}\\{target_key}`")
            return

        vals = view_obj.get("values", {})
        last_mod = view_obj.get("last_modified_utc") or "N/A"
        subkeys = view_obj.get("subkeys", [])

        lines = [
            f"# Windows Registry Key - `{args.hive}\\{target_key}`",
            f"- **View Mode:** `{res.get('view', 'dual')}`",
            f"- **Last Modified (UTC):** `{last_mod}`",
            f"- **Total Values:** {len(vals)}",
            f"- **Total Subkeys:** {view_obj.get('total_subkeys', len(subkeys))}",
        ]
        if res.get("has_discrepancy"):
            lines.append(f"- **⚠️ WOW64 Divergence Detected:** {res.get('discrepancy_count', 0)} discrepancies between 64-bit and 32-bit views")
        lines.extend([
            "",
            "| Value Name | Type | Data |",
            "| :--- | :--- | :--- |",
        ])
        for vn, vinfo in sorted(vals.items(), key=lambda x: x[0]):
            v_type = vinfo.get("type", "REG_SZ")
            v_val = str(vinfo.get("value", ""))
            if len(v_val) > 80:
                v_val = v_val[:77] + "..."
            lines.append(f"| `{vn}` | `{v_type}` | {v_val} |")

        if subkeys:
            lines.extend([
                "",
                f"### Child Subkeys ({min(len(subkeys), 20)} of {view_obj.get('total_subkeys', len(subkeys))})",
            ])
            for sk in subkeys[:20]:
                lines.append(f"- `{sk}`")

        print("\n".join(lines))
    else:
        print(json.dumps(res, indent=2, default=str))
    return


def cmd_reg_search(cmd: str) -> None:
    """bintra reg-search"""
    parser = argparse.ArgumentParser(prog="bintra reg-search", description="Search registry keys, value names, and value data")
    parser.add_argument("query", nargs="?", default="", help="Search query string")
    parser.add_argument("--query", dest="named_query", default=None, help="Search query string flag")
    parser.add_argument("--hive", default="HKLM", help="Target hive (HKLM, HKCU, HKCR, HKU, HKCC)")
    parser.add_argument("--root-key", default="", help="Subkey path to begin search from")
    parser.add_argument("--max-depth", type=int, default=3, help="Maximum traversal depth (default: 3)")
    parser.add_argument("--limit", type=int, default=50, help="Maximum matches to return (default: 50)")
    parser.add_argument("--match-case", action="store_true", help="Case-sensitive search")
    parser.add_argument("--match-whole", action="store_true", help="Match entire string only")
    parser.add_argument("--view", choices=["64", "32"], default="64", help="Architecture view")
    parser.add_argument("--format", choices=["json", "md"], default="md", help="Output format")
    args = parser.parse_args(sys.argv[2:])
    q_val = args.named_query or args.query
    if not q_val:
        print("Error: Search query is required. Example: bintra reg-search --query \"Python\"")
        return

    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="reg-search",
        target=f"{args.hive}\\{args.root_key or 'SearchRoot'}",
        capability=Capability.REGISTRY_READ,
        access_mode="READ",
    )
    from windows_intelligence.registry_intelligence import WindowsRegistryEditor
    res = WindowsRegistryEditor.search(
        query=q_val,
        hive=args.hive,
        root_key=args.root_key,
        max_depth=args.max_depth,
        limit=args.limit,
        match_case=args.match_case,
        match_whole_string=args.match_whole,
        view=args.view
    )
    if args.format == "md":
        lines = [
            f"# Windows Registry Search - '{q_val}' ({res.get('matched_count', len(res.get('matches', [])))} matches)",
            f"- **Hive:** `{res.get('hive')}` | **Root Key:** `{res.get('root_key')}`",
            f"- **Scanned Keys:** {res.get('keys_scanned', 0):,} | **Scanned Values:** {res.get('values_scanned', 0):,}",
            f"- **Elapsed Time:** {res.get('elapsed_seconds', 0.0)}s",
            "",
            "| Match Type | Canonical Path | Value Name | Type | Match Preview |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
        for m in res.get("matches", []):
            m_type = m.get("match_type")
            p = m.get("canonical_path", "")
            vn = m.get("value_name") or "-"
            vt = m.get("value_type") or "-"
            prev = m.get("preview", "")
            if len(prev) > 80:
                prev = prev[:77] + "..."
            lines.append(f"| `{m_type}` | `{p}` | `{vn}` | `{vt}` | {prev} |")
        print("\n".join(lines))
    else:
        print(json.dumps(res, indent=2, default=str))
    return


def cmd_reg_export(cmd: str) -> None:
    """bintra reg-export"""
    parser = argparse.ArgumentParser(prog="bintra reg-export", description="Export live registry key to Windows Registry Editor Version 5.00 format")
    parser.add_argument("key", nargs="?", default="", help="Registry subkey path")
    parser.add_argument("--key", dest="named_key", default=None, help="Registry subkey path flag")
    parser.add_argument("--hive", default="HKLM", help="Registry hive (HKLM, HKCU, HKCR, HKU, HKCC)")
    parser.add_argument("--output", default=None, help="Output .reg file path (prints to stdout if omitted)")
    parser.add_argument("--recursive", action="store_true", help="Recursively export child subkeys")
    parser.add_argument("--max-depth", type=int, default=1, help="Maximum recursion depth (default: 1)")
    parser.add_argument("--view", choices=["64", "32"], default="64", help="Architecture view")
    args = parser.parse_args(sys.argv[2:])
    target_key = args.named_key or args.key
    if not target_key:
        print("Error: Subkey path is required. Example: bintra reg-export --key \"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\"")
        return

    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="reg-export",
        target=f"{args.hive}\\{target_key}",
        capability=Capability.REGISTRY_READ,
        access_mode="READ",
    )
    from windows_intelligence.registry_intelligence import WindowsRegistryEditor
    res = WindowsRegistryEditor.export_key(
        hive=args.hive,
        subkey=target_key,
        output_path=args.output,
        recursive=args.recursive,
        max_depth=args.max_depth,
        view=args.view
    )
    if args.output:
        print(f"Export successful. Wrote {res.get('keys_exported', 0)} keys and {res.get('values_exported', 0)} values to '{res.get('output_path')}'.")
    else:
        print(res.get("reg_content", ""))
    return


def cmd_reg_import(cmd: str) -> None:
    """bintra reg-import"""
    parser = argparse.ArgumentParser(prog="bintra reg-import", description="Parse and audit .reg files with live registry drift detection")
    parser.add_argument("file", nargs="?", default="", help="Path to .reg file")
    parser.add_argument("--file", dest="named_file", default=None, help="Path to .reg file flag")
    parser.add_argument("--diff", action="store_true", help="Audit live drift against Windows registry")
    parser.add_argument("--view", choices=["64", "32"], default="64", help="Architecture view for live diff")
    parser.add_argument("--format", choices=["json", "md"], default="md", help="Output format")
    args = parser.parse_args(sys.argv[2:])
    target_file = args.named_file or args.file
    if not target_file:
        print("Error: Path to .reg file is required. Example: bintra reg-import export.reg --diff")
        return

    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="reg-import",
        target=target_file,
        capability=Capability.REGISTRY_READ,
        access_mode="READ",
    )
    from windows_intelligence.registry_intelligence import WindowsRegistryEditor
    if args.diff:
        res = WindowsRegistryEditor.diff_reg_file(reg_content_or_path=target_file, view=args.view)
        if args.format == "md":
            lines = [
                f"# Registry Drift Audit - '{target_file}'",
                f"- **Format:** `{res.get('format_version')}`",
                f"- **Total Checked Values:** {res.get('total_items_checked', 0)}",
                f"- **Compliance:** **{res.get('compliance_percentage', 0.0)}%**",
                f"- **Matched:** {res.get('matched_count', 0)} | **Drifted:** {res.get('drifted_count', 0)} | **Missing:** {res.get('missing_count', 0)}",
                "",
                "| Target Key / Value | Audit Status | Expected Value | Live System Value |",
                "| :--- | :--- | :--- | :--- |",
            ]
            for item in res.get("diff_items", []):
                st = item.get("status")
                st_badge = "✅ Matched" if st == "matched" else ("⚠️ Drifted" if st == "drifted" else f"❌ {st}")
                k_lbl = f"{item.get('full_key')}\\{item.get('value_name', '')}"
                exp_v = str(item.get("expected_value", item.get("value", "")))
                act_v = str(item.get("actual_value", "-"))
                if len(exp_v) > 40: exp_v = exp_v[:37] + "..."
                if len(act_v) > 40: act_v = act_v[:37] + "..."
                lines.append(f"| `{k_lbl}` | {st_badge} | `{exp_v}` | `{act_v}` |")
            print("\n".join(lines))
        else:
            print(json.dumps(res, indent=2, default=str))
    else:
        res = WindowsRegistryEditor.parse_reg_file(target_file)
        if args.format == "md":
            lines = [
                f"# Parsed Registry File - '{target_file}'",
                f"- **Format:** `{res.get('format_version')}`",
                f"- **Total Keys:** {res.get('keys_count', 0)}",
                f"- **Total Values:** {res.get('values_count', 0)}",
                "",
            ]
            for k_path, k_data in res.get("keys", {}).items():
                del_str = " (DELETION)" if k_data.get("is_deletion") else ""
                lines.append(f"### `[{k_path}]{del_str}`")
                vals = k_data.get("values", {})
                if vals:
                    lines.extend([
                        "| Value Name | Type | Value Literal |",
                        "| :--- | :--- | :--- |",
                    ])
                    for vn, vinfo in vals.items():
                        lines.append(f"| `{vn}` | `{vinfo.get('type')}` | `{vinfo.get('value')}` |")
                lines.append("")
            print("\n".join(lines))
        else:
            print(json.dumps(res, indent=2, default=str))
    return


def cmd_resolve_deps(cmd: str) -> None:
    """bintra resolve-deps"""
    parser = argparse.ArgumentParser(prog="bintra resolve-deps", description="Audit Windows dynamic link library dependencies")
    parser.add_argument("command")
    parser.add_argument("pos_binary", nargs="?", default=None, help="Target PE binary")
    parser.add_argument("--binary", "--file", "-b", "-f", "--target", "-t", dest="flag_binary", default=None, help="Target PE binary")
    parser.add_argument("--app-dir", default=None, help="Host application directory to search first for DLL dependencies")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args(sys.argv[1:])

    target_binary = args.flag_binary or args.pos_binary
    if not target_binary:
        parser.error("Target binary path is required (positional or via --binary / --file)")

    report = WindowsDependencyResolver.audit_dependencies(target_binary, app_dir=args.app_dir)
    if args.format == "md":
        lines = [
            f"# Dependency Audit for `{os.path.basename(target_binary)}`",
            f"- **Verdict:** `{report.get('verdict')}`",
            f"- **Loader Mode:** `{report.get('loader_mode')}` ({report.get('binary_architecture')})",
            f"- **Resolved DLLs:** {report.get('resolved_dlls_count')}/{report.get('total_imported_dlls')}",
            f"- **Missing DLLs:** {report.get('missing_dlls_count')}",
            f"- **Architecture Mismatches:** {report.get('architecture_mismatches_count')}",
            f"- **Missing Exports:** {report.get('missing_exports_count')}"
        ]
        if report.get("missing_dlls"):
            lines.append("\n### Missing DLLs:")
            for m in report["missing_dlls"]:
                lines.append(f"- `{m['imported_name']}` (Required functions: {m['functions_count']})")
        print("\n".join(lines))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return


def cmd_wer_inspect(cmd: str) -> None:
    """bintra wer-inspect"""
    parser = argparse.ArgumentParser(description="Scan Windows Error Reporting and Event Log for application crash dossiers")
    parser.add_argument("command")
    parser.add_argument("--binary", "--file", dest="binary", default=None, help="Optional executable name filter")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args()

    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="wer-inspect",
        target=args.binary or "SystemEventLog",
        capability=Capability.EVENT_LOG_READ,
        access_mode="QUERY"
    )

    report = WindowsCrashAnalyzer.collect_crash_evidence(args.binary)
    if args.format == "md":
        lines = [
            "# Windows Crash Telemetry Report",
            f"- **Target Filter:** `{args.binary or 'ALL'}`",
            f"- **WER Reports Found:** {report.get('wer_reports_found')}",
            f"- **Event Log Errors Found:** {report.get('event_log_errors_found')}"
        ]
        for r in report.get("wer_reports", [])[:5]:
            lines.append(f"- [WER] {r.get('app_name')} | Exception: {r.get('exception_code')} ({r.get('exception_name')}) at {r.get('fault_offset')}")
        for e in report.get("event_log_errors", [])[:5]:
            lines.append(f"- [Event 1000] {e.get('app_name')} | Module: {e.get('fault_module')} at {e.get('fault_offset')}")
        print("\n".join(lines))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return


def cmd_diagnose(cmd: str) -> None:
    """bintra diagnose"""
    parser = argparse.ArgumentParser(description="Correlate Windows OS environment, crash records, and PE structure into Failure Evidence Dossier")
    parser.add_argument("command")
    parser.add_argument("--binary", "--file", dest="binary", required=True, help="Target executable")
    parser.add_argument("--crash-json", default=None, help="Optional path to custom crash record JSON")
    parser.add_argument("--ghidra-json", default=None, help="Optional path to exported Ghidra High P-Code JSON")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format (json or md)")
    args = parser.parse_args()

    crash_rec = None
    if args.crash_json and os.path.exists(args.crash_json):
        with open(args.crash_json, "r", encoding="utf-8") as f:
            crash_rec = json.load(f)

    ghidra_data = None
    if args.ghidra_json and os.path.exists(args.ghidra_json):
        with open(args.ghidra_json, "r", encoding="utf-8") as f:
            ghidra_data = json.load(f)

    dossier = DiagnosticEvidenceCorrelator.correlate(
        args.binary, crash_record=crash_rec, ghidra_export=ghidra_data
    )
    if args.format == "md":
        print(DiagnosticEvidenceCorrelator.format_markdown(dossier))
    else:
        print(json.dumps(dossier, indent=2, ensure_ascii=False))
    return


def cmd_win_cmd(cmd: str) -> None:
    """bintra win-cmd"""
    parser = argparse.ArgumentParser(description="Safely execute pre-registered read-only Windows catalog commands")
    parser.add_argument("command")
    parser.add_argument("cmd_id", nargs="?", default="list", help="Command ID to execute (or 'list')")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args()

    if args.cmd_id == "list":
        catalog_list = CommandCatalog.list_available_commands()
        if args.format == "md":
            lines = [
                "# Available Safe Windows Catalog Commands",
                "",
                "| Command ID | Binary | Min Build | Admin Req | Output Schema |",
                "|:---|:---|:---|:---|:---|"
            ]
            for c in catalog_list:
                lines.append(f"| `{c['command_id']}` | `{c['binary']}` | {c['min_build']} | {c['requires_admin']} | `{c['output_schema']}` |")
            print("\n".join(lines))
        else:
            print(json.dumps(catalog_list, indent=2, ensure_ascii=False))
        return

    res = CommandExecutor.execute(args.cmd_id)
    if args.format == "md":
        lines = [
            f"# Execution: `{args.cmd_id}` ({res.get('status')})",
            f"- **Schema:** `{res.get('schema')}`",
            f"- **Duration:** {res.get('duration_ms')} ms",
            f"- **Exit Code:** {res.get('exit_code')}",
            ""
        ]
        print("\n".join(lines))
        print(json.dumps(res.get("data"), indent=2, ensure_ascii=False))
    else:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    return


def cmd_reg_audit(cmd: str) -> None:
    """bintra reg-audit"""
    parser = argparse.ArgumentParser(description="Dual-view (32/64-bit) 11-domain Windows Registry intelligence audit")
    parser.add_argument("command")
    parser.add_argument("--domain", default=None, help="Specific domain to audit (e.g. OPERATING_SYSTEM, SECURITY_POLICIES)")
    parser.add_argument("--binary", default=None, help="Optional binary path to check for AppCompatFlags shims")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args()

    if args.domain:
        report = WindowsRegistryAnalyzer.audit_domain(args.domain)
    else:
        report = WindowsRegistryAnalyzer.audit_all(target_binary_path=args.binary)

    if args.format == "md":
        lines = [
            "# Windows Registry Intelligence Audit",
            f"- **Domains Inspected:** {report.get('total_domains_audited', 1)}",
            f"- **Keys Inspected:** {report.get('total_keys_inspected', report.get('keys_inspected', 0))}",
            f"- **Architecture Discrepancies:** {report.get('total_discrepancies_detected', report.get('discrepancies_count', 0))}"
        ]
        if "critical_policies" in report:
            lines.append("\n## Critical Security & Loader Policies:")
            for f in report["critical_policies"].get("findings", []):
                lines.append(f"- {f}")
        print("\n".join(lines))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return

