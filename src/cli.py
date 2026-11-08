#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
REA-Neural Unified Command-Line Interface.
Dispatches to Binary Engine (inspect, deobfuscate, match, patch-binary, scan-hybrid),
Weight-Space Engine (subspace, decompile, patch-weights, diff-weights, probe-trace, verify-behavior),
or Metaphorical Sensory Cortex (sense / sensory-audit).
"""

import sys
import os
import json
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import binary_neural_engine
import rea_neural_engine
from binary_neural_engine import SensoryCortex


def _ensure_utf8_stdio() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


BINARY_COMMANDS = {"inspect", "deobfuscate", "match", "match-functions", "patch-binary", "scan-hybrid", "dump"}
WEIGHT_COMMANDS = {
    "subspace", "decompile", "decompile-circuit", "patch-weights",
    "diff", "diff-weights", "probe-trace", "verify-behavior",
    "wsp-audit"
}
ARCHIVED_SCOPE_COMMANDS = {"synthesize-weights"}
SENSORY_COMMANDS = {"sense", "sensory-audit"}
GHIDRA_COMMANDS = {"match-pcode", "deobfuscate-pcode", "ghidra-plan", "ghidra-analyze", "ghidra-headless"}
WIN_INTEL_COMMANDS = {"win-audit", "resolve-deps", "wer-inspect", "diagnose", "win-cmd", "reg-audit", "hw-audit", "driver-audit", "service-audit", "dmp-inspect", "etw-audit"}


def print_help():
    print("""
REA-Neural Unified CLI v7.4.0 (Windows-Native & 10-Sense Edition)
Autonomous Continuous Semantic Reverse Engineering & Binary Analysis

Usage:
  python src/cli.py <command> [options]

Binary / Windows Executable Commands:
  inspect           Inspect PE32/PE32+/ELF headers, mitigations (ASLR/DEP/CFG), and sections
  deobfuscate       Detect and prune REX-aware opaque predicates & CFF dispatcher loops
  match             Semantically match functions across compilers / architectures (x86-64 / ARM64)
  patch-binary      Surgically patch a binary file on disk with stack proprioception & PE checksum
  scan-hybrid       Scan an executable for embedded neural logic (DirectML, WinML, ONNX, GGUF, TFLite)

Weight-Space / Neural Commands:
  subspace          Extract SVD modes, sparse extremes, or coordinate slices from weight tensors
  decompile         Decompile attention heads, MLP projections, or LayerNorm drift into pseudocode
  patch-weights     Surgically patch a safetensors weight tensor without gradients
  diff-weights      Compare baseline and patched models with Frobenius diff
  probe-trace       Probe temporal activation traces across token steps (Temporal Hearing)
  verify-behavior      Verify neural equilibrium and Lipschitz bounds (Vestibular Balance)
  wsp-audit            Run MIT CSAIL WSP audit (Effective Rank, Cross-Layer Induction, Amenability, Backdoors)

Metaphorical Sensory Cortex Commands:
  sense             Run all 10 Metaphorical Senses on a binary (--file), model (--file), or code (--hex)

Ghidra P-Code & Symbolic Integration Commands:
  match-pcode       Match functions using Ghidra High P-code IR (Architecture-Invariant)
  deobfuscate-pcode Detect and prune P-code algebraic opaque predicates and dispatcher loops
  ghidra-plan       Generate type-safe Ghidra database mutation and annotation plans
  ghidra-analyze    Batch-analyze exported Ghidra P-Code JSON and generate database mutation plan
  ghidra-headless   Launch Ghidra analyzeHeadless with REA-Neural bridge script to auto-deobfuscate

Windows System Intelligence & Failure Diagnostic Commands:
  win-audit         Profile host Windows OS build, WOW64 mode, and AppCompatFlags layers
  resolve-deps      Audit DLL search order, API-Sets, and verify required exported symbols
  wer-inspect       Scan Windows Error Reporting (WER) archives and Application Event Log
  diagnose          Correlate host OS environment, crash records, and PE structure into Evidence Dossier
  win-cmd           Safely execute pre-registered read-only Windows catalog commands (or 'list')
  reg-audit         Dual-view (32/64-bit) audit across 11 Windows Registry functional domains
  hw-audit          Inspect live PnP devices and problem codes (CM_PROB_*) via SetupAPI & CfgMgr32
  driver-audit      Enumerate loaded kernel drivers and execution image bases via PSAPI
  service-audit     Inspect Windows Service Control Manager (SCM) service states via Advapi32
  dmp-inspect       Multi-stream MiniDump (.dmp) inspection and access violation root-cause analysis
  etw-audit         Inspect active ETW trace sessions and diagnostic providers (Process, D3D11, DXGI)

Agent-Native MCP (Model Context Protocol):
  mcp               Launch native JSON-RPC 2.0 stdio MCP server for AI models (Claude, Antigravity, Cursor)
""")


def main():
    _ensure_utf8_stdio()
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print_help()
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd == "patch":
        if "--patch-hex" in sys.argv or "--offset" in sys.argv:
            cmd = "patch-binary"
        elif "--alpha" in sys.argv or "--mode-index" in sys.argv or "--tensor" in sys.argv or "--operation" in sys.argv:
            cmd = "patch-weights"
        else:
            print("Ambiguous command 'patch'. Please specify 'patch-binary' for PE files or 'patch-weights' for model tensors.")
            sys.exit(1)

    if cmd in WIN_INTEL_COMMANDS:
        from windows_intelligence import (
            WindowsOSProfiler, WindowsDependencyResolver, WindowsDeviceInspector,
            WindowsSecurityInspector, WindowsCrashAnalyzer, DiagnosticEvidenceCorrelator,
            CommandCatalog, CommandExecutor, PowerShellExecutor,
            RegistryCatalog, WindowsRegistryReader, WindowsRegistryAnalyzer,
            NativeDeviceInspector, KernelDriverInspector, ServiceManagerInspector, ProcessMitigationInspector,
            MiniDumpParser, EventLogCollector, EtwController
        )
        if cmd == "win-audit":
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
                lines = [
                    "# Windows System Intelligence Profile",
                    f"- **OS:** {report['os']['kernel'].get('friendly_name')} (Build {report['os']['kernel'].get('build_number')})",
                    f"- **Native Architecture:** {report['os']['architecture'].get('native_architecture')}",
                    f"- **Elevation:** Admin={report['security'].get('is_elevated_admin')}",
                    f"- **Token Integrity:** {report['security'].get('token_integrity', {}).get('integrity_level')}",
                    f"- **Active Graphics Adapters:** {len(report['devices'].get('graphics_adapters', []))}"
                ]
                print("\n".join(lines))
            else:
                print(json.dumps(report, indent=2, ensure_ascii=False))
            return

        elif cmd == "resolve-deps":
            parser = argparse.ArgumentParser(description="Audit Windows dynamic link library dependencies")
            parser.add_argument("command")
            parser.add_argument("--binary", "--file", dest="binary", required=True, help="Target PE binary")
            parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
            args = parser.parse_args()

            report = WindowsDependencyResolver.audit_dependencies(args.binary)
            if args.format == "md":
                lines = [
                    f"# Dependency Audit for `{os.path.basename(args.binary)}`",
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

        elif cmd == "wer-inspect":
            parser = argparse.ArgumentParser(description="Scan Windows Error Reporting and Event Log for application crash dossiers")
            parser.add_argument("command")
            parser.add_argument("--binary", "--file", dest="binary", default=None, help="Optional executable name filter")
            parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
            args = parser.parse_args()

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

        elif cmd == "diagnose":
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

        elif cmd == "win-cmd":
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

        elif cmd == "reg-audit":
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

        elif cmd == "hw-audit":
            parser = argparse.ArgumentParser(description="Live hardware and PnP device audit via SetupAPI and CfgMgr32")
            parser.add_argument("command")
            parser.add_argument("--problems-only", action="store_true", help="Filter for devices with non-zero problem codes")
            parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
            args = parser.parse_args()

            report = NativeDeviceInspector.audit_hardware_health()
            if args.format == "md":
                lines = [
                    "# Native Hardware Subsystem Audit (SetupAPI / CfgMgr32)",
                    f"- **Hardware Status:** {'HEALTHY' if report['is_hardware_healthy'] else 'DEGRADED_OR_PROBLEMS'}",
                    f"- **Live PnP Devices:** {report['total_pnp_devices_enumerated']}",
                    f"- **Display Adapters:** {report['display_adapters_count']}",
                    f"- **Audio Devices:** {report['audio_devices_count']}",
                    f"- **Problem Devices:** {report['problem_devices_count']}"
                ]
                if report['problem_devices']:
                    lines.append("\n## Faulting Devices (CM_PROB_*):")
                    for p in report['problem_devices']:
                        lines.append(f"- **{p['name']}**: `{p['problem_name']}` (Service: `{p.get('service')}`)")
                print("\n".join(lines))
            else:
                print(json.dumps(report, indent=2, ensure_ascii=False))
            return

        elif cmd == "driver-audit":
            parser = argparse.ArgumentParser(description="Kernel driver introspection via PSAPI")
            parser.add_argument("command")
            parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
            args = parser.parse_args()

            report = KernelDriverInspector.audit_drivers()
            if args.format == "md":
                lines = [
                    "# Kernel Drivers Introspection (PSAPI)",
                    f"- **Total Drivers Loaded:** {report['total_drivers_loaded']}",
                    f"- **Graphics Drivers:** {len(report['graphics_drivers'])}",
                    f"- **Audio Drivers:** {len(report['audio_drivers'])}",
                    "",
                    "## Critical Graphics & Display Driver Bases:"
                ]
                for g in report['graphics_drivers']:
                    lines.append(f"- **`{g['driver_name']}`**: Base `{g['kernel_image_base']}` (Path: `{g['file_path']}`)")
                print("\n".join(lines))
            else:
                print(json.dumps(report, indent=2, ensure_ascii=False))
            return

        elif cmd == "service-audit":
            parser = argparse.ArgumentParser(description="Windows Service Control Manager audit via Advapi32")
            parser.add_argument("command")
            parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
            args = parser.parse_args()

            report = ServiceManagerInspector.audit_services()
            if args.format == "md":
                lines = [
                    "# Service Control Manager Audit (Advapi32)",
                    f"- **Total Services Enumerated:** {report['total_services_enumerated']}",
                    f"- **Running Services:** {report['running_services_count']}",
                    f"- **Stopped Services:** {report['stopped_services_count']}"
                ]
                print("\n".join(lines))
            else:
                print(json.dumps(report, indent=2, ensure_ascii=False))
            return

        elif cmd == "dmp-inspect":
            parser = argparse.ArgumentParser(description="Multi-stream MiniDump crash inspection and root cause analysis")
            parser.add_argument("command")
            parser.add_argument("--file", "--dmp", dest="file", default=None, help="Path to .dmp file (if omitted, scans standard dump paths)")
            parser.add_argument("--scan", action="store_true", help="Scan system for recent crash dumps")
            parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
            args = parser.parse_args()

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

        elif cmd == "etw-audit":
            parser = argparse.ArgumentParser(description="Audit ETW trace sessions and diagnostic providers")
            parser.add_argument("command")
            parser.add_argument("--session", default=None, help="Query specific session name")
            parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
            args = parser.parse_args()

            if args.session:
                report = EtwController.query_trace_session(args.session)
            else:
                report = EtwController.audit_telemetry_system()

            if args.format == "md":
                if "providers" in report:
                    lines = [
                        "# ETW Telemetry Infrastructure Audit",
                        f"- **Probed Sessions:** {report.get('standard_sessions_probed', 0)}",
                        f"- **Active Sessions:** {report.get('active_sessions_count', 0)} ({', '.join(report.get('active_sessions', []))})",
                        f"- **Registered Diagnostic Providers:** {report.get('registered_providers_count', 0)}",
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

    if cmd in SENSORY_COMMANDS:
        parser = argparse.ArgumentParser(description="REA-Neural 10-Sense Diagnostic Audit")
        parser.add_argument("command", help="sense or sensory-audit")
        parser.add_argument("--file", "--binary", "--input", dest="file", default=None, help="Optional path to PE executable or .safetensors model")
        parser.add_argument("--hex", default=None, help="Optional hex string of machine code")
        args = parser.parse_args()
        report = SensoryCortex.evaluate_all_senses(file_path=args.file, code_hex=args.hex)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return

    if cmd in GHIDRA_COMMANDS:
        from ghidra_pcode_vectorizer import (
            PcodeVectorizer, PcodeFunctionMatcher, PcodeDeobfuscator, GhidraAnnotationPlanner
        )
        if cmd == "match-pcode":
            parser = argparse.ArgumentParser(description="Match two functions using Ghidra P-code")
            parser.add_argument("command")
            parser.add_argument("--func1", required=True, help="JSON file or inline JSON string of function 1 P-code ops")
            parser.add_argument("--func2", required=True, help="JSON file or inline JSON string of function 2 P-code ops")
            args = parser.parse_args()
            def _load_pcode(val):
                if os.path.exists(val):
                    with open(val, "r", encoding="utf-8") as f:
                        return json.load(f)
                try:
                    return json.loads(val)
                except Exception:
                    import ast
                    return ast.literal_eval(val)
            p1 = _load_pcode(args.func1)
            p2 = _load_pcode(args.func2)
            res = PcodeFunctionMatcher.match(p1, p2)
            print(json.dumps(res, indent=2))
            return
        elif cmd == "deobfuscate-pcode":
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
        elif cmd == "ghidra-plan":
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
        elif cmd == "ghidra-analyze":
            parser = argparse.ArgumentParser(description="Analyze Ghidra exported High P-Code and emit mutation plan")
            parser.add_argument("command")
            parser.add_argument("--input", "--file", dest="input", required=True, help="Path to exported Ghidra JSON file")
            parser.add_argument("--output", default=None, help="Path to write the generated mutation plan JSON")
            args = parser.parse_args()

            with open(args.input, "r", encoding="utf-8") as f:
                payload = json.load(f)

            plan = GhidraAnnotationPlanner.analyze_program_export(payload)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    json.dump(plan, f, indent=2)
            print(json.dumps(plan, indent=2))
            return
        elif cmd == "ghidra-headless":
            parser = argparse.ArgumentParser(description="Run Ghidra headless analysis with REA-Neural bridge script")
            parser.add_argument("command")
            parser.add_argument("--binary", "--file", "--input", dest="binary", required=True, help="Path to target executable (PE/ELF)")
            parser.add_argument("--ghidra-path", default=os.environ.get("GHIDRA_INSTALL_DIR", r"C:\Users\Eylias\tools\ghidra"), help="Ghidra installation directory")
            parser.add_argument("--project-dir", default=None, help="Ghidra project directory (default: temp)")
            parser.add_argument("--project-name", default="REANeuralHeadless", help="Ghidra project name")
            parser.add_argument("--apply", action="store_true", help="Automatically commit mutations to Ghidra database")
            args = parser.parse_args()

            import subprocess, tempfile
            from pathlib import Path as P
            ghidra_dir = P(args.ghidra_path)
            headless_bat = ghidra_dir / "support" / "analyzeHeadless.bat"
            if not headless_bat.exists():
                print(f"Error: analyzeHeadless.bat not found at: {headless_bat}")
                sys.exit(1)

            repo_root = P(__file__).resolve().parent.parent
            script_dir = repo_root / "ghidra_scripts"
            proj_dir = args.project_dir or tempfile.gettempdir()
            script_args = ["apply"] if args.apply else []

            cmd_args = [
                str(headless_bat),
                proj_dir,
                args.project_name,
                "-import", args.binary,
                "-overwrite",
                "-scriptPath", str(script_dir),
                "-postScript", "ReaNeuralGhidraBridge.java"
            ] + script_args

            print(f"[REA-Neural] Launching Ghidra Headless Analyzer...")
            print(f"[REA-Neural] Binary: {args.binary}")
            print(f"[REA-Neural] Script: {script_dir / 'ReaNeuralGhidraBridge.java'}")
            res = subprocess.run(cmd_args)
            sys.exit(res.returncode)

    # MCP Server Command
    if cmd in ("mcp", "mcp-server"):
        from mcp_server import main as mcp_main
        mcp_main()
        return

    # Agent-Native Flag Normalization (Permissive Aliases for AI Agents)
    if cmd in BINARY_COMMANDS:
        if cmd == "patch-binary":
            sys.argv[1] = "patch"
            # Normalize --file / --binary / --input to --source
            for alt in ("--file", "--binary", "--input"):
                if alt in sys.argv and "--source" not in sys.argv:
                    idx = sys.argv.index(alt)
                    sys.argv[idx] = "--source"
            # If no --output, default to in-place patch
            if "--source" in sys.argv and "--output" not in sys.argv:
                s_idx = sys.argv.index("--source")
                if s_idx + 1 < len(sys.argv):
                    sys.argv.extend(["--output", sys.argv[s_idx + 1]])
            # Normalize --patch to --patch-hex
            if "--patch" in sys.argv and "--patch-hex" not in sys.argv:
                p_idx = sys.argv.index("--patch")
                sys.argv[p_idx] = "--patch-hex"
        elif cmd == "match-functions":
            sys.argv[1] = "match"
        else:
            # Normalize --binary or --input to --file for inspect, scan-hybrid, etc.
            for alt in ("--binary", "--input"):
                if alt in sys.argv and "--file" not in sys.argv:
                    idx = sys.argv.index(alt)
                    sys.argv[idx] = "--file"

        binary_neural_engine.main()

    elif cmd in ARCHIVED_SCOPE_COMMANDS:
        scope_msg = {
            "status": "decoupled_from_active_scope",
            "command": cmd,
            "message": (
                "Command 'synthesize-weights' has been decoupled from REA-Neural's active reverse-engineering interface. "
                "Per SCOPE.md, REA-Neural focuses on continuous semantic reverse engineering, decompilation, "
                "and embedded neural tensor auditing. Standalone neural model synthesis is preserved only as historical lineage."
            ),
            "reference": "SCOPE.md"
        }
        if "--archived-lineage" in sys.argv:
            print(f"[SCOPE WARNING] Running {cmd} under historical research lineage (--archived-lineage).")
            rea_neural_engine.main()
            return
        else:
            scope_msg["hint"] = "To invoke for paper reproduction, provide flag: --archived-lineage"
            print(json.dumps(scope_msg, indent=2))
            sys.exit(0)

    elif cmd in WEIGHT_COMMANDS:
        if cmd == "patch-weights":
            sys.argv[1] = "patch"
        elif cmd == "decompile-circuit":
            sys.argv[1] = "decompile"
        elif cmd == "diff-weights":
            sys.argv[1] = "diff"

        # Normalize --file or --input or --binary to --model
        for alt in ("--file", "--input", "--binary"):
            if alt in sys.argv and "--model" not in sys.argv:
                idx = sys.argv.index(alt)
                sys.argv[idx] = "--model"

        rea_neural_engine.main()

    else:
        print(f"Unknown command '{cmd}'. Run 'cli.py help' for usage.")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, ValueError, KeyError) as e:
        print(json.dumps({
            "status": "error",
            "error_type": type(e).__name__,
            "message": str(e)
        }, indent=2))
        sys.exit(1)
