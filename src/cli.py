#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bintra Unified Command-Line Interface.
Dispatches to Binary Engine (inspect, deobfuscate, match, patch-binary, scan-hybrid),
Weight-Space Engine (subspace, decompile, patch-weights, diff-weights, probe-trace, verify-behavior),
or Metaphorical Sensory Cortex (sense / sensory-audit).
"""

import sys
import os
import time
import json
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import binary_neural_engine
import bintra_engine
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
GHIDRA_COMMANDS = {"match-pcode", "deobfuscate-pcode", "ghidra-plan", "ghidra-analyze", "ghidra-headless", "ghidra-bridge"}
WIN_INTEL_COMMANDS = {"win-audit", "resolve-deps", "wer-inspect", "diagnose", "win-cmd", "reg-audit", "hw-audit", "driver-audit", "service-audit", "dmp-inspect", "etw-audit", "file-locks", "proc-modules", "dev-match", "vad-inspect", "crash-rca", "etw-capture", "mem-scan", "pointer-scan", "dissect-struct"}


def print_help():
    print(r"""
  ____  _       _             
 | __ )(_)_ __ | |_ _ __ __ _ 
 |  _ \| | '_ \| __| '__/ _` |
 | |_) | | | | | |_| | | (_| |
 |____/|_|_| |_|\__|_|  \__,_|

 Bintra Unified CLI v1.0.0 (Windows-Native & 10-Sense Edition)
 Autonomous Continuous Semantic Reverse Engineering & Binary Analysis

Usage:
  bintra <command> [options]  (or: python src/cli.py <command> [options])

Binary / Windows Executable Commands:
  inspect           Inspect PE32/PE32+/ELF headers, mitigations (ASLR/DEP/CFG), and sections
  deobfuscate       Detect and prune REX-aware opaque predicates & CFF dispatcher loops
  match             Semantically match functions via raw hex bytes (--func1 / --func2 hex) across architectures (x86-64 / ARM64)
  patch-binary      Surgically patch a binary file on disk with stack proprioception & PE checksum
  scan-hybrid       Scan an executable for embedded neural logic (DirectML, WinML, ONNX, GGUF, TFLite)

Weight-Space / Neural Commands:
  subspace          Extract SVD modes, sparse extremes, or coordinate slices from weight tensors
  decompile         Decompile attention heads, MLP projections, or LayerNorm drift into pseudocode
  patch-weights     Surgically patch a safetensors weight tensor without gradients
  diff-weights      Compare baseline and patched models with Frobenius diff
  probe-trace       Run seeded spectral SVD operator trace simulation across weight layers (Temporal Hearing)
  verify-behavior      Verify neural equilibrium and Lipschitz bounds (Vestibular Balance)
  wsp-audit            Run MIT CSAIL WSP audit (Effective Rank, Cross-Layer Induction, Amenability, Backdoors)

Metaphorical Sensory Cortex Commands:
  sense             Run all 10 Metaphorical Senses on a binary (--file), model (--file), or code (--hex)

Ghidra P-Code & Symbolic Integration Commands:
  match-pcode       Match functions using Ghidra High P-code IR (Architecture-Invariant)
  deobfuscate-pcode Detect and prune P-code algebraic opaque predicates and dispatcher loops
  ghidra-plan       Generate type-safe Ghidra database mutation and annotation plans
  ghidra-analyze    Batch-analyze exported Ghidra P-Code JSON and generate database mutation plan
  ghidra-headless   Launch Ghidra analyzeHeadless with Bintra bridge script to auto-deobfuscate
  ghidra-bridge     Run localhost JSON-RPC 2.0 live bridge daemon connecting to Ghidra

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
  file-locks        Detect processes and services holding active locks on a file via Restart Manager
  proc-modules      Locate running processes that have loaded a specific module or DLL
  dev-match         Match Plug and Play (PnP) hardware IDs against driver INF store and problem codes
  vad-inspect       Inspect passive virtual memory map (VAD) and classify addresses (Heap/Stack/Image)
  mem-scan          Non-intrusive read-only memory value search (First/Next scan: exact, changed, between)
  pointer-scan      Multi-level backward pointer path resolver finding static module roots
  dissect-struct    Runtime object structure field analysis (vftables, pointers, floats, ints, C struct)
  crash-rca         Automated Crash Root Cause Analysis (MiniDump + Disassembly + Culprit Register)
  etw-capture       Establish real-time ETW capture session and stream diagnostic timeline events

Agent-Native MCP (Model Context Protocol):
  mcp               Launch native JSON-RPC 2.0 stdio MCP server for AI models (Claude, Antigravity, Cursor)

Maintenance & Update Commands:
  update            Check and automatically update Bintra to latest commit from GitHub (or 'self-update')
""")


def main():
    _ensure_utf8_stdio()
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print_help()
        sys.exit(0)
    if sys.argv[1] in ("-v", "-V", "--version", "version"):
        print("Bintra v1.0.0")
        sys.exit(0)

    cmd_lower = sys.argv[1].lower()
    mutation_cmds = {"patch", "patch-binary", "patch-weights"}
    is_update_write = cmd_lower in ("update", "self-update") and any(f in sys.argv for f in ("--yes", "--confirm"))
    strict_audit = cmd_lower in mutation_cmds or is_update_write

    from security import AuditLogger, AuditPersistenceError
    prev_strict = AuditLogger.get_strict_persistence()
    AuditLogger.set_strict_persistence(strict_audit)
    try:
        try:
            init_res = AuditLogger.ensure_chain_continuity(rotate_on_corrupt=not strict_audit)
            if isinstance(init_res, dict) and init_res.get("audit_degraded") and strict_audit:
                raise AuditPersistenceError(init_res.get("audit_degraded_reason") or "Audit persistence degraded")
        except Exception as audit_err:
            if strict_audit:
                print(json.dumps({
                    "status": "error",
                    "command": cmd_lower,
                    "error_type": type(audit_err).__name__,
                    "error": f"AUDIT_INIT_FAILED: {audit_err}",
                    "message": f"Fail-closed refusal for mutation command '{cmd_lower}': audit log initialization/persistence failed ({audit_err}).",
                    "audit_degraded": True,
                    "audit_degraded_reason": str(audit_err),
                }, indent=2, ensure_ascii=False))
                sys.exit(1)
            AuditLogger.mark_degraded(str(audit_err))
            sys.stderr.write(f"[AUDIT DEGRADATION WARNING] Audit log degraded for '{cmd_lower}': {audit_err}\n")

        # Establish isolated target scope and authorized workspace for CLI execution
        target_arg = None
        workspace_arg = None
        for flag in ("--file", "--binary", "--source", "--input", "--model", "--target", "--dmp"):
            if flag in sys.argv:
                idx = sys.argv.index(flag)
                if idx + 1 < len(sys.argv):
                    target_arg = sys.argv[idx + 1]
                    break

        for flag in ("--workspace", "--workspace-dir"):
            while flag in sys.argv:
                idx = sys.argv.index(flag)
                if idx + 1 < len(sys.argv):
                    workspace_arg = sys.argv[idx + 1]
                    del sys.argv[idx:idx + 2]
                else:
                    del sys.argv[idx]

        streaming_cmds = {"mcp", "mcp-server", "ghidra-bridge", "ghidra-headless", "etw-capture", "update", "self-update"}
        should_buffer = cmd_lower not in streaming_cmds
        try:
            from security import ExecutionGuard
            with ExecutionGuard.scoped_session(target_binary_path=target_arg, workspace_dir=workspace_arg):
                if should_buffer:
                    import io, contextlib
                    cap_buf = io.StringIO()
                    try:
                        with contextlib.redirect_stdout(cap_buf):
                            _dispatch_cli()
                    finally:
                        raw_out = cap_buf.getvalue()
                        if AuditLogger.is_audit_degraded() and raw_out.strip():
                            injected = False
                            try:
                                parsed = json.loads(raw_out)
                                if isinstance(parsed, dict):
                                    parsed["audit_degraded"] = True
                                    parsed["audit_degraded_reason"] = AuditLogger.get_degraded_reason()
                                    sys.stdout.write(json.dumps(parsed, indent=2, ensure_ascii=False) + "\n")
                                    injected = True
                            except Exception:
                                pass
                            if not injected:
                                sys.stdout.write(raw_out)
                                sys.stderr.write(
                                    f"[AUDIT DEGRADED] Persistent audit logging unavailable: {AuditLogger.get_degraded_reason()}\n"
                                )
                        else:
                            sys.stdout.write(raw_out)
                else:
                    _dispatch_cli()
        except SystemExit:
            raise
        except Exception as e:
            err_payload = {
                "status": "error",
                "command": sys.argv[1] if len(sys.argv) > 1 else None,
                "error_type": type(e).__name__,
                "error": str(e),
                "message": str(e)
            }
            if AuditLogger.is_audit_degraded() or isinstance(e, AuditPersistenceError):
                err_payload["audit_degraded"] = True
                err_payload["audit_degraded_reason"] = AuditLogger.get_degraded_reason() or str(e)
            if os.environ.get("BINTRA_DEBUG") == "1":
                import traceback
                err_payload["traceback"] = traceback.format_exc()
            print(json.dumps(err_payload, indent=2, ensure_ascii=False))
            sys.exit(1)
    finally:
        AuditLogger.set_strict_persistence(prev_strict)


def _dispatch_cli():

    cmd = sys.argv[1]

    if cmd == "patch":
        if "--patch-hex" in sys.argv or "--offset" in sys.argv:
            cmd = "patch-binary"
        elif "--alpha" in sys.argv or "--mode-index" in sys.argv or "--tensor" in sys.argv or "--operation" in sys.argv:
            cmd = "patch-weights"
        elif "-h" in sys.argv or "--help" in sys.argv or "help" in sys.argv:
            print("Bintra Patch Commands:")
            print("  Binary patching:  bintra patch-binary --binary <path> --offset <offset> --patch-hex <hex>")
            print("  Weight patching:  bintra patch-weights --model <path> --tensor <name> --operation <op>")
            sys.exit(0)
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
            MiniDumpParser, EventLogCollector, EtwController, VirtualMemoryInspector, CrashRootCauseAnalyzer,
            EtwLiveCaptureSession, EtwTimelineCorrelator,
            ProcessMemoryScanner, PointerScanner, StructureDissector
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

        elif cmd == "resolve-deps":
            parser = argparse.ArgumentParser(description="Audit Windows dynamic link library dependencies")
            parser.add_argument("command")
            parser.add_argument("--binary", "--file", dest="binary", required=True, help="Target PE binary")
            parser.add_argument("--app-dir", default=None, help="Host application directory to search first for DLL dependencies")
            parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
            args = parser.parse_args()

            report = WindowsDependencyResolver.audit_dependencies(args.binary, app_dir=args.app_dir)
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
                if report.get("status") == "not_applicable" or "is_hardware_healthy" not in report:
                    lines = [
                        "# Native Hardware Subsystem Audit (SetupAPI / CfgMgr32)",
                        f"- **Status:** `{report.get('status', 'unavailable')}`",
                        f"- **Note:** {report.get('message', 'Hardware audit requires a Windows NT host.')}",
                    ]
                else:
                    lines = [
                        "# Native Hardware Subsystem Audit (SetupAPI / CfgMgr32)",
                        f"- **Hardware Status:** {'HEALTHY' if report.get('is_hardware_healthy') else 'DEGRADED_OR_PROBLEMS'}",
                        f"- **Live PnP Devices:** {report.get('total_pnp_devices_enumerated', 0)}",
                        f"- **Display Adapters:** {report.get('display_adapters_count', 0)}",
                        f"- **Audio Devices:** {report.get('audio_devices_count', 0)}",
                        f"- **Problem Devices:** {report.get('problem_devices_count', 0)}"
                    ]
                    if report.get("problem_devices"):
                        lines.append("\n## Faulting Devices (CM_PROB_*):")
                        for p in report["problem_devices"]:
                            lines.append(f"- **{p.get('name', 'Unknown')}**: `{p.get('problem_name', 'Unknown')}` (Service: `{p.get('service')}`)")
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
                if report.get("status") == "not_applicable" or "total_drivers_loaded" not in report:
                    lines = [
                        "# Kernel Drivers Introspection (PSAPI)",
                        f"- **Status:** `{report.get('status', 'unavailable')}`",
                        f"- **Note:** {report.get('message', 'Kernel driver audit requires a Windows NT host.')}",
                    ]
                else:
                    lines = [
                        "# Kernel Drivers Introspection (PSAPI)",
                        f"- **Total Drivers Loaded:** {report.get('total_drivers_loaded', 0)}",
                        f"- **Graphics Drivers:** {len(report.get('graphics_drivers', []))}",
                        f"- **Audio Drivers:** {len(report.get('audio_drivers', []))}",
                        "",
                        "## Critical Graphics & Display Driver Bases:"
                    ]
                    for g in report.get("graphics_drivers", []):
                        lines.append(f"- **`{g.get('driver_name')}`**: Base `{g.get('kernel_image_base')}` (Path: `{g.get('file_path')}`)")
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
                if report.get("status") == "not_applicable" or "total_services_enumerated" not in report:
                    lines = [
                        "# Service Control Manager Audit (Advapi32)",
                        f"- **Status:** `{report.get('status', 'unavailable')}`",
                        f"- **Note:** {report.get('message', 'Service control manager audit requires a Windows NT host.')}",
                    ]
                else:
                    lines = [
                        "# Service Control Manager Audit (Advapi32)",
                        f"- **Total Services Enumerated:** {report.get('total_services_enumerated', 0)}",
                        f"- **Running Services:** {report.get('running_services_count', 0)}",
                        f"- **Stopped Services:** {report.get('stopped_services_count', 0)}"
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


        elif cmd == "file-locks":
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

        elif cmd == "proc-modules":
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

        elif cmd == "dev-match":
            parser = argparse.ArgumentParser(prog="bintra dev-match", description="Match PnP devices against Driver Store packages")
            parser.add_argument("--query", default=None, help="Device query name, instance ID, or hardware ID")
            parser.add_argument("--class-filter", default=None, help="Filter by device class")
            parser.add_argument("--problems-only", action="store_true", help="Filter to devices with active problem codes")
            args = parser.parse_args(sys.argv[2:])
            from security import ExecutionGuard, Capability
            ExecutionGuard.request_access(
                component="cli",
                operation="dev-match",
                target=args.query or "AllDevices",
                capability=Capability.DEVICE_QUERY,
                access_mode="QUERY"
            )
            from windows_intelligence.device_intelligence import DriverMatcher
            res = DriverMatcher.audit_device_driver_bindings(
                device_query=args.query,
                class_filter=args.class_filter,
                problems_only=args.problems_only
            )
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return

        elif cmd == "vad-inspect":
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

        elif cmd == "mem-scan":
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

            from security import SafeFileAccess, SecurityViolationError
            sid = None
            if args.session_file and os.path.exists(args.session_file):
                try:
                    raw_session = SafeFileAccess.read_text(args.session_file)
                    session_data = json.loads(raw_session)
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
                SafeFileAccess.write_workspace_file(args.session_file, json.dumps(res, indent=2))

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

        elif cmd == "pointer-scan":
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

        elif cmd == "dissect-struct":
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

        elif cmd == "crash-rca":
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

        elif cmd == "etw-capture":
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

        elif cmd == "etw-audit":
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
                        f"# ETW Registered Providers Enumeration",
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

    if cmd in SENSORY_COMMANDS:
        parser = argparse.ArgumentParser(description="Bintra 10-Sense Diagnostic Audit")
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

            from security import SafeFileAccess, ExecutionGuard, Capability
            if args.output:
                ExecutionGuard.request_access(
                    component="cli",
                    operation="ghidra-analyze-output",
                    target=args.output,
                    capability=Capability.WORKSPACE_WRITE,
                    access_mode="WRITE"
                )
            raw_input = SafeFileAccess.read_text(args.input)
            payload = json.loads(raw_input)

            plan = GhidraAnnotationPlanner.analyze_program_export(payload)
            if args.output:
                SafeFileAccess.write_workspace_file(args.output, json.dumps(plan, indent=2))
            print(json.dumps(plan, indent=2))
            return
        elif cmd == "ghidra-headless":
            parser = argparse.ArgumentParser(description="Run Ghidra headless analysis with Bintra bridge script")
            parser.add_argument("command")
            parser.add_argument("--binary", "--file", "--input", dest="binary", required=True, help="Path to target executable (PE/ELF)")
            parser.add_argument("--ghidra-path", default=None, help="Ghidra installation directory (default: auto-discover)")
            parser.add_argument("--project-dir", default=None, help="Ghidra project directory (default: temp)")
            parser.add_argument("--project-name", default="BintraHeadless", help="Ghidra project name")
            parser.add_argument("--apply", action="store_true", help="Automatically commit mutations to Ghidra database")
            args = parser.parse_args()

            import subprocess, tempfile
            from pathlib import Path as P
            ghidra_path_val = args.ghidra_path or os.environ.get("GHIDRA_INSTALL_DIR") or os.environ.get("GHIDRA_HOME")
            headless_name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
            alt_name = "analyzeHeadless" if os.name == "nt" else "analyzeHeadless.bat"

            headless_cmd = None
            if ghidra_path_val:
                p = P(ghidra_path_val)
                cand = p / "support" / headless_name
                if cand.exists():
                    headless_cmd = cand
                elif (p / "support" / alt_name).exists():
                    headless_cmd = p / "support" / alt_name

            if not headless_cmd:
                candidates = [
                    P.home() / "tools" / "ghidra",
                    P.home() / "ghidra",
                    P(r"C:\ghidra") if os.name == "nt" else P("/opt/ghidra"),
                    P(r"C:\tools\ghidra"),
                    P(r"D:\ghidra"),
                ]
                for cand_dir in candidates:
                    cand = cand_dir / "support" / headless_name
                    if cand.exists():
                        headless_cmd = cand
                        break
                    alt = cand_dir / "support" / alt_name
                    if alt.exists():
                        headless_cmd = alt
                        break

            if not headless_cmd:
                print(f"Error: {headless_name} not found. Please set GHIDRA_INSTALL_DIR or pass --ghidra-path.")
                sys.exit(1)

            repo_root = P(__file__).resolve().parent.parent
            script_dir = repo_root / "ghidra_scripts"
            proj_dir = args.project_dir or tempfile.gettempdir()
            script_args = ["apply"] if args.apply else []

            cmd_args = [
                str(headless_cmd),
                proj_dir,
                args.project_name,
                "-import", args.binary,
                "-overwrite",
                "-scriptPath", str(script_dir),
                "-postScript", "BintraGhidraBridge.java"
            ] + script_args

            print(f"[Bintra] Launching Ghidra Headless Analyzer...")
            print(f"[Bintra] Binary: {args.binary}")
            print(f"[Bintra] Script: {script_dir / 'BintraGhidraBridge.java'}")
            res = subprocess.run(cmd_args)
            if res.returncode != 0:
                sys.stderr.write(f"[Bintra] Ghidra Headless Analyzer failed with return code {res.returncode}\n")
            sys.exit(res.returncode)

        elif cmd == "ghidra-bridge":
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

            from ghidra_live_bridge import (
                GhidraLiveBridgeServer, GhidraLiveBridgeClient,
                get_or_create_bridge, get_active_bridge, stop_active_bridge
            )

            if args.stop:
                res = stop_active_bridge(port=args.port, auth_token=args.token)
                print(json.dumps(res, indent=2))
                return

            if args.daemon:
                import subprocess
                daemon_cmd = [
                    sys.executable,
                    os.path.abspath(sys.argv[0]),
                    "ghidra-bridge",
                    "--start",
                    "--port", str(args.port)
                ]
                if args.token:
                    daemon_cmd.extend(["--token", args.token])
                if args.no_temp_marker:
                    daemon_cmd.append("--no-temp-marker")
                popen_kwargs: Dict[str, Any] = {
                    "close_fds": True,
                    "stdout": subprocess.DEVNULL,
                    "stderr": subprocess.DEVNULL,
                }
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
                    client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{args.port}", auth_token=args.token)
                    st = client.call_rpc("get_status")
                    print(json.dumps(st, indent=2, ensure_ascii=False))
                except Exception as e:
                    print(json.dumps({"is_running": False, "error": str(e)}, indent=2))
                return

            if args.annotate_crash:
                from windows_intelligence import CrashRootCauseAnalyzer
                rca = CrashRootCauseAnalyzer.analyze_crash(args.annotate_crash)
                client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{args.port}", auth_token=args.token)
                try:
                    inj = client.call_rpc("bintra.inject_crash_rca", {"rca_report": rca})
                    print(json.dumps(inj, indent=2, ensure_ascii=False))
                except Exception as e:
                    act = get_active_bridge()
                    if act and act.is_running:
                        inj = act.inject_crash_rca(rca)
                        print(json.dumps(inj, indent=2, ensure_ascii=False))
                    else:
                        print(json.dumps({"status": "error", "message": f"Bridge communication error: {e}"}, indent=2))
                return

            if args.annotate_vad:
                from windows_intelligence import VirtualMemoryInspector
                snap = VirtualMemoryInspector.inspect_process(args.annotate_vad)
                client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{args.port}", auth_token=args.token)
                try:
                    inj = client.call_rpc("bintra.inject_vad_snapshot", {"vad_snapshot": snap.to_dict()})
                    print(json.dumps(inj, indent=2, ensure_ascii=False))
                except Exception as e:
                    act = get_active_bridge()
                    if act and act.is_running:
                        inj = act.inject_vad_snapshot(snap.to_dict())
                        print(json.dumps(inj, indent=2, ensure_ascii=False))
                    else:
                        print(json.dumps({"status": "error", "message": f"Bridge communication error: {e}"}, indent=2))
                return

            if args.annotate_struct:
                if os.path.isfile(args.annotate_struct):
                    with open(args.annotate_struct, "r", encoding="utf-8") as f:
                        struct_rep = json.load(f)
                else:
                    target_pid = int(args.annotate_struct)
                    if not args.addr:
                        print(json.dumps({"status": "error", "message": "--addr is required when --annotate-struct is a PID"}, indent=2))
                        return
                    base_addr = int(args.addr, 16) if args.addr.lower().startswith("0x") else int(args.addr)
                    from windows_intelligence import StructureDissector
                    struct_rep = StructureDissector.dissect(target_pid, base_addr, size=args.size)

                client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{args.port}", auth_token=args.token)
                try:
                    inj = client.call_rpc("bintra.inject_structure_dissection", {"struct_report": struct_rep})
                    print(json.dumps(inj, indent=2, ensure_ascii=False))
                except Exception as e:
                    act = get_active_bridge()
                    if act and act.is_running:
                        inj = act.inject_structure_dissection(struct_rep)
                        print(json.dumps(inj, indent=2, ensure_ascii=False))
                    else:
                        print(json.dumps({"status": "error", "message": f"Bridge communication error: {e}"}, indent=2))
                return

            if args.annotate_pointers:
                if os.path.isfile(args.annotate_pointers):
                    with open(args.annotate_pointers, "r", encoding="utf-8") as f:
                        ptr_rep = json.load(f)
                else:
                    target_pid = int(args.annotate_pointers)
                    if not args.addr:
                        print(json.dumps({"status": "error", "message": "--addr is required when --annotate-pointers is a PID"}, indent=2))
                        return
                    target_addr = int(args.addr, 16) if args.addr.lower().startswith("0x") else int(args.addr)
                    from windows_intelligence import PointerScanner
                    ptr_rep = PointerScanner.find_pointer_paths(target_pid, target_addr, max_depth=args.depth)

                client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{args.port}", auth_token=args.token)
                try:
                    inj = client.call_rpc("bintra.inject_pointer_chains", {"pointer_report": ptr_rep})
                    print(json.dumps(inj, indent=2, ensure_ascii=False))
                except Exception as e:
                    act = get_active_bridge()
                    if act and act.is_running:
                        inj = act.inject_pointer_chains(ptr_rep)
                        print(json.dumps(inj, indent=2, ensure_ascii=False))
                    else:
                        print(json.dumps({"status": "error", "message": f"Bridge communication error: {e}"}, indent=2))
                return

            # Default / --start: start bridge server in foreground
            server = get_or_create_bridge(
                port=args.port,
                auth_token=args.token,
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
            # Guard: in-place source modification is strictly forbidden
            if "--source" in sys.argv and "--output" not in sys.argv:
                s_idx = sys.argv.index("--source")
                if s_idx + 1 < len(sys.argv):
                    src_file = sys.argv[s_idx + 1]
                    from security import ExecutionGuard
                    scope = ExecutionGuard.get_current_scope()
                    safe_out = os.path.join(scope.workspace_dir, "patched_" + os.path.basename(src_file))
                    sys.argv.extend(["--output", safe_out])
            elif "--source" in sys.argv and "--output" in sys.argv:
                s_idx = sys.argv.index("--source")
                o_idx = sys.argv.index("--output")
                if s_idx + 1 < len(sys.argv) and o_idx + 1 < len(sys.argv):
                    from security import PathIdentity, ExecutionGuard, TargetMutationError, OutOfScopeError, Capability
                    src_f = sys.argv[s_idx + 1]
                    out_f = sys.argv[o_idx + 1]
                    if PathIdentity.is_same_file(src_f, out_f):
                        raise TargetMutationError(
                            "TARGET_WRITE_FORBIDDEN: Direct in-place modification of target binaries is strictly forbidden by Bintra Safety Policy. Specify a distinct --output file in the workspace."
                        )
                    scope = ExecutionGuard.get_current_scope()
                    if scope and scope.is_target_directory(out_f):
                        raise TargetMutationError(
                            f"TARGET_DIRECTORY_WRITE_FORBIDDEN: Output patch cannot be placed in the target's original directory '{os.path.dirname(os.path.abspath(out_f))}'."
                        )
                    if not scope.is_inside_workspace(out_f):
                        raise OutOfScopeError(
                            f"WRITE_OUTSIDE_WORKSPACE: Output path '{out_f}' is outside authorized workspace '{scope.workspace_dir}'."
                        )
                    ExecutionGuard.request_access(
                        component="cli",
                        operation="patch-binary",
                        target=out_f,
                        capability=Capability.WORKSPACE_WRITE,
                        access_mode="WRITE"
                    )
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
                "Command 'synthesize-weights' has been decoupled from Bintra's active reverse-engineering interface. "
                "Per SCOPE.md, Bintra focuses on continuous semantic reverse engineering, decompilation, "
                "and embedded neural tensor auditing. Standalone neural model synthesis is preserved only as historical lineage."
            ),
            "reference": "SCOPE.md"
        }
        if "--archived-lineage" in sys.argv:
            print(f"[SCOPE WARNING] Running {cmd} under historical research lineage (--archived-lineage).")
            bintra_engine.main()
            return
        else:
            scope_msg["hint"] = "To invoke for paper reproduction, provide flag: --archived-lineage"
            print(json.dumps(scope_msg, indent=2))
            sys.exit(0)

    elif cmd in WEIGHT_COMMANDS:
        if cmd == "patch-weights":
            sys.argv[1] = "patch"
            if "--source" in sys.argv and "--output" in sys.argv:
                s_idx = sys.argv.index("--source")
                o_idx = sys.argv.index("--output")
                if s_idx + 1 < len(sys.argv) and o_idx + 1 < len(sys.argv):
                    from security import PathIdentity, ExecutionGuard, TargetMutationError, OutOfScopeError, Capability
                    src_f = sys.argv[s_idx + 1]
                    out_f = sys.argv[o_idx + 1]
                    if PathIdentity.is_same_file(src_f, out_f):
                        raise TargetMutationError(
                            "TARGET_WRITE_FORBIDDEN: Direct in-place modification of model weights is strictly forbidden by Bintra Safety Policy. Specify a distinct --output file in the workspace."
                        )
                    scope = ExecutionGuard.get_current_scope()
                    if scope and scope.is_target_directory(out_f):
                        raise TargetMutationError(
                            f"TARGET_DIRECTORY_WRITE_FORBIDDEN: Output patch cannot be placed in the target's original directory '{os.path.dirname(os.path.abspath(out_f))}'."
                        )
                    if not scope.is_inside_workspace(out_f):
                        raise OutOfScopeError(
                            f"WRITE_OUTSIDE_WORKSPACE: Output path '{out_f}' is outside authorized workspace '{scope.workspace_dir}'."
                        )
                    ExecutionGuard.request_access(
                        component="cli",
                        operation="patch-weights",
                        target=out_f,
                        capability=Capability.WORKSPACE_WRITE,
                        access_mode="WRITE"
                    )
        elif cmd == "decompile-circuit":
            sys.argv[1] = "decompile"
        elif cmd == "diff-weights":
            sys.argv[1] = "diff"

        # Normalize --file or --input or --binary to --model
        for alt in ("--file", "--input", "--binary"):
            if alt in sys.argv and "--model" not in sys.argv:
                idx = sys.argv.index(alt)
                sys.argv[idx] = "--model"

        bintra_engine.main()

    elif cmd in ("update", "self-update"):
        _handle_update()

    else:
        print(f"Unknown command '{cmd}'. Run 'cli.py help' for usage.")
        sys.exit(1)


def _handle_update() -> None:
    parser = argparse.ArgumentParser(
        prog="bintra update",
        description="Check and safely update Bintra from GitHub (requires --yes/--confirm to modify installation)"
    )
    parser.add_argument("--check", action="store_true", help="Check for available updates without applying them")
    parser.add_argument("--branch", default="main", help="Target git branch (default: main)")
    parser.add_argument("--ref", default=None, help="Optional pinned tag or commit SHA to verify/checkout on update")
    parser.add_argument("--yes", "--confirm", dest="confirm", action="store_true", help="Explicit confirmation required to apply updates")
    args = parser.parse_args(sys.argv[2:])

    import re
    ref_pat = r"^[a-zA-Z0-9_\./]+[a-zA-Z0-9_\-\./]*$"
    if not re.match(ref_pat, args.branch) or args.branch.startswith("-"):
        print(f"[-] Invalid branch refname: '{args.branch}'")
        sys.exit(1)
    if args.ref and (not re.match(ref_pat, args.ref) or args.ref.startswith("-")):
        print(f"[-] Invalid target ref: '{args.ref}'")
        sys.exit(1)

    import subprocess
    repo_dir = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
    git_dir = os.path.join(repo_dir, ".git")

    if os.path.isdir(git_dir):
        try:
            print(f"[*] Checking remote repository for updates (branch: '{args.branch}')...")
            fetch_res = subprocess.run(
                ["git", "fetch", "--tags", "origin", "--", args.branch],
                cwd=repo_dir,
                capture_output=True,
                text=True
            )
            if fetch_res.returncode != 0:
                print(f"[-] Git fetch error: {fetch_res.stderr.strip()}")
                sys.exit(1)

            target_rev = args.ref or f"origin/{args.branch}"
            local_hash = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_dir, text=True).strip()
            remote_hash = subprocess.check_output(["git", "rev-parse", "--verify", target_rev], cwd=repo_dir, text=True).strip()

            if local_hash == remote_hash:
                commit_title = subprocess.check_output(["git", "log", "-1", "--format=%s"], cwd=repo_dir, text=True).strip()
                print(f"[+] Bintra is already at the latest commit: {local_hash[:7]} (\"{commit_title}\")")
                return

            incoming_commits = subprocess.check_output(
                ["git", "log", f"HEAD..{remote_hash}", "--oneline"],
                cwd=repo_dir,
                text=True
            ).strip()
            print(f"[!] New updates available ({local_hash[:7]} -> {remote_hash[:7]}):\n")
            for c_line in incoming_commits.splitlines():
                print(f"    • {c_line}")
            print()

            if args.check:
                print("[*] Update check completed. Run 'bintra update --yes' to apply.")
                return

            if not args.confirm:
                print("[!] Refusing unconfirmed remote code update. Re-run with '--yes' (or '--confirm') to apply.")
                sys.exit(2)

            if args.ref:
                print(f"[*] Fast-forwarding to verified ref '{args.ref}' ({remote_hash[:12]})...")
                subprocess.run(["git", "merge", "--ff-only", remote_hash], cwd=repo_dir, check=True)
            else:
                print(f"[*] Fast-forwarding latest commits from origin/{args.branch}...")
                subprocess.run(["git", "pull", "--ff-only", "origin", "--", args.branch], cwd=repo_dir, check=True)

            print("[*] Refreshing package entry points and dependencies...")
            subprocess.run([sys.executable, "-m", "pip", "install", "--no-deps", "-e", "."], cwd=repo_dir, check=True)

            new_hash = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_dir, text=True).strip()
            new_title = subprocess.check_output(["git", "log", "-1", "--format=%s"], cwd=repo_dir, text=True).strip()
            print(f"[+] Successfully updated Bintra to latest commit: {new_hash[:7]} (\"{new_title}\")")
        except Exception as e:
            print(f"[-] Automatic update failed: {e}")
            sys.exit(1)
    else:
        if args.check:
            print("[*] Package is installed without a local git working tree.")
            print("[*] Run 'bintra update --yes --ref <tag-or-sha>' to reinstall/upgrade directly from GitHub.")
            return

        if not args.confirm:
            print("[!] Refusing unconfirmed remote pip installation. Re-run with '--yes' (optionally '--ref <tag-or-sha>') to apply.")
            sys.exit(2)

        pkg_spec = "git+https://github.com/bio-colab/bintra.git"
        if args.ref:
            pkg_spec = f"{pkg_spec}@{args.ref}"
        print(f"[*] Updating Bintra via pip from {pkg_spec}...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "--upgrade", pkg_spec],
                check=True
            )
            print("[+] Successfully updated Bintra via pip!")
        except Exception as e:
            print(f"[-] Pip update failed: {e}")
            sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        err_payload = {
            "status": "error",
            "error_type": type(e).__name__,
            "message": str(e)
        }
        if os.environ.get("BINTRA_DEBUG") == "1":
            import traceback
            err_payload["traceback"] = traceback.format_exc()
        print(json.dumps(err_payload, indent=2))
        sys.exit(1)
