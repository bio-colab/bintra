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
import json

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from bintra_cli import registry
from bintra_cli.registry import (  # noqa: F401  (public re-exports)
    ARCHIVED_SCOPE_COMMANDS, BINARY_COMMANDS, GHIDRA_COMMANDS, SENSORY_COMMANDS,
    WEIGHT_COMMANDS, WIN_INTEL_COMMANDS,
)


def _ensure_utf8_stdio() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass




def print_help():
    print(r"""
  ____  _       _             
 | __ )(_)_ __ | |_ _ __ __ _ 
 |  _ \| | '_ \| __| '__/ _` |
 | |_) | | | | | |_| | | (_| |
 |____/|_|_| |_|\__|_|  \__,_|

 Bintra Unified CLI v1.1.0 (Windows-Native & 10-Sense Edition)
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
  ghidra-similar    Behavioral nearest-routine search inside a Ghidra export (64-D P-Code cosine)

Windows System Intelligence & Failure Diagnostic Commands:
  win-audit         Profile host Windows OS build, WOW64 mode, and AppCompatFlags layers
  resolve-deps      Audit DLL search order, API-Sets, and verify required exported symbols
  wer-inspect       Scan Windows Error Reporting (WER) archives and Application Event Log
  diagnose          Correlate host OS environment, crash records, and PE structure into Evidence Dossier
  win-cmd           Safely execute pre-registered read-only Windows catalog commands (or 'list')
  reg-audit         Dual-view (32/64-bit) audit across 11 Windows Registry functional domains
  reg-read          Read registry keys, values, and subkeys across 64/32/dual views
  reg-search        Deep multi-mode search across registry keys, value names, and data (Ctrl+F)
  reg-export        Export live registry keys to official .reg format (Version 5.00)
  reg-import        Parse, validate, and audit .reg files with live registry drift detection
  hw-audit          Inspect live PnP devices, problem codes (CM_PROB_*), and physical storage drives
  port-audit        Audit active COM and LPT ports with USB bridge matching and modem line status
  hw-tree           Render authoritative PnP bus hierarchy tree (ASCII tree, Mermaid, or JSON)
  hw-net            Audit live network adapters, physical MAC layer, and NDIS link characteristics
  hw-dissect        Multi-layer hardware-to-ring0 kernel driver reverse engineering dossier (DevNode to KASLR)
  driver-audit      Enumerate loaded kernel drivers and execution image bases via PSAPI
  service-audit     Inspect Windows Service Control Manager (SCM) service states via Advapi32
  dmp-inspect       Multi-stream MiniDump (.dmp) inspection and access violation root-cause analysis
  etw-audit         Inspect active ETW trace sessions and diagnostic providers (Process, D3D11, DXGI)
  file-locks        Detect processes and services holding active locks on a file via Restart Manager
  proc-modules      Locate running processes that have loaded a specific module or DLL
  dev-match         Match Plug and Play (PnP) hardware IDs against driver INF store and problem codes
  dev-classes       Device Manager class hierarchy with friendly categories and error tallies
  dev-list          Enumerate active PnP devices enriched with driver store metadata and locations
  dev-search        Instant multi-field search across device names, hardware IDs, and vendors
  dev-info          Complete Device Manager Properties dossier (General, Driver, IDs, Topology)
  vad-inspect       Inspect passive virtual memory map (VAD) and classify addresses (Heap/Stack/Image)
  mem-scan          Non-intrusive read-only memory value search (First/Next scan: exact, changed, between)
  pointer-scan      Multi-level backward pointer path resolver finding static module roots
  dissect-struct    Runtime object structure field analysis (vftables, pointers, floats, ints, C struct)
  crash-rca         Automated Crash Root Cause Analysis (MiniDump + Disassembly + Culprit Register)
  etw-capture       Establish real-time ETW capture session and stream diagnostic timeline events
  sig-verify        Verify Authenticode and Security Catalog (.cat) signatures with full certificate chain
  sig-audit         Audit executable and driver signatures across directories with WHQL/OEM classification
  proc-profile      Longitudinal resource profiler & leak diagnosis (Private Bytes, Handles, GDI/USER, Plateau)
  slack-audit       Audit binary slack space, PE overlays, and document EOF padding (MFC NUL, installer overlays)
  triage            Multi-stage unified binary triage with deterministic markdown report generation (--format md)

Python Ecosystem & Runtime Forensics Commands:
  py-bytecode       Disassemble and inspect Python bytecode (.pyc / .py) with opcode and constant analysis
  py-mem-inspect    Passive runtime CPython object inspection via PROCESS_VM_READ (PyObject, PyDict, PyASCIIObject)

Agent-Native MCP (Model Context Protocol):
  mcp               Launch native JSON-RPC 2.0 stdio MCP server for AI models (Claude, Antigravity, Cursor)

Maintenance & Update Commands:
  update            Check and automatically update Bintra to latest commit from GitHub (or 'self-update')
""")


def _payload_signals_failure(raw_out: str) -> bool:
    """True when a single JSON object payload reports an error or a missing target."""
    text = (raw_out or "").strip()
    if not text.startswith("{"):
        return False
    try:
        parsed = json.loads(text)
    except Exception:
        return False
    if not isinstance(parsed, dict):
        return False
    return str(parsed.get("status", "")).lower() == "error" or parsed.get("format") == "FILE_NOT_FOUND"


def main():
    _ensure_utf8_stdio()
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print_help()
        sys.exit(0)
    if sys.argv[1] in ("-v", "-V", "--version", "version"):
        print("Bintra v1.1.0")
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
            is_tamper_err = isinstance(audit_err, __import__("security").AuditIntegrityError) and AuditLogger.is_tamper_detected()
            if strict_audit:
                print(json.dumps({
                    "status": "error",
                    "command": cmd_lower,
                    "error_type": type(audit_err).__name__,
                    "error": f"{'AUDIT_TAMPER_DETECTED' if is_tamper_err else 'AUDIT_INIT_FAILED'}: {audit_err}",
                    "message": f"Fail-closed refusal for mutation command '{cmd_lower}': audit log integrity/persistence failed ({audit_err}).",
                    "audit_degraded": True,
                    "audit_tamper_detected": bool(is_tamper_err),
                    "audit_degraded_reason": str(audit_err),
                }, indent=2, ensure_ascii=False))
                sys.exit(1)
            if is_tamper_err:
                AuditLogger.mark_tampered(str(audit_err))
            else:
                AuditLogger.mark_degraded(str(audit_err))
            sys.stderr.write(f"[AUDIT DEGRADATION WARNING] Audit log degraded for '{cmd_lower}': {audit_err}\n")

        # Establish isolated target scope and authorized workspace for CLI execution
        target_arg = None
        workspace_arg = None
        if cmd_lower != "ghidra-analyze":
            for flag in ("--file", "-f", "--binary", "-b", "--source", "--input", "--model", "--target", "--dmp"):
                if flag in sys.argv:
                    idx = sys.argv.index(flag)
                    if idx + 1 < len(sys.argv):
                        target_arg = sys.argv[idx + 1]
                        break
            if not target_arg and len(sys.argv) >= 3 and not sys.argv[2].startswith("-"):
                if cmd_lower in ("slack-audit", "overlay-inspect", "inspect-slack", "inspect", "triage", "deobfuscate", "dump"):
                    target_arg = sys.argv[2]

        for flag in ("--workspace", "--workspace-dir"):
            while flag in sys.argv:
                idx = sys.argv.index(flag)
                if idx + 1 < len(sys.argv):
                    workspace_arg = sys.argv[idx + 1]
                    del sys.argv[idx:idx + 2]
                else:
                    del sys.argv[idx]

        compact_mode = (os.environ.get("BINTRA_COMPACT_OUTPUT") == "1")
        while "--compact" in sys.argv:
            compact_mode = True
            sys.argv.remove("--compact")

        token_report_mode = (os.environ.get("BINTRA_TOKEN_TELEMETRY") == "1")
        while "--token-report" in sys.argv:
            token_report_mode = True
            sys.argv.remove("--token-report")

        model_pricing = os.environ.get("BINTRA_MODEL_PRICING", "claude-3.5-sonnet")
        while "--model-pricing" in sys.argv:
            idx = sys.argv.index("--model-pricing")
            if idx + 1 < len(sys.argv):
                model_pricing = sys.argv[idx + 1]
                del sys.argv[idx:idx + 2]
            else:
                del sys.argv[idx]

        # CLI only (never MCP): an explicit write destination designates the workspace when
        # --workspace is absent, so documented flows such as
        # `patch-binary --output .\workspace\x.exe` work out of the box. TargetScope still
        # refuses unsafe roots (filesystem/home/system dirs) and relocates away from any
        # target directory, so writes next to a target remain blocked fail-closed.
        if not workspace_arg:
            for out_flag in ("--output", "--session-file", "--to-sqlite"):
                if out_flag in sys.argv:
                    out_idx = sys.argv.index(out_flag)
                    if out_idx + 1 < len(sys.argv) and not sys.argv[out_idx + 1].startswith("-"):
                        workspace_arg = os.path.dirname(os.path.abspath(sys.argv[out_idx + 1]))
                        break

        streaming_cmds = {"mcp", "mcp-server", "ghidra-bridge", "ghidra-headless", "etw-capture", "update", "self-update"}
        should_buffer = cmd_lower not in streaming_cmds
        try:
            from security import ExecutionGuard
            with ExecutionGuard.scoped_session(target_binary_path=target_arg, workspace_dir=workspace_arg):
                if should_buffer:
                    import io, contextlib
                    cap_buf = io.StringIO()
                    dispatch_completed = False
                    try:
                        with contextlib.redirect_stdout(cap_buf):
                            _dispatch_cli()
                        dispatch_completed = True
                    finally:
                        raw_out = cap_buf.getvalue()
                        final_out = raw_out
                        if AuditLogger.is_audit_degraded() and raw_out.strip():
                            injected = False
                            try:
                                parsed = json.loads(raw_out)
                                if isinstance(parsed, dict):
                                    parsed["audit_degraded"] = True
                                    if AuditLogger.is_tamper_detected():
                                        parsed["audit_tamper_detected"] = True
                                    parsed["audit_degraded_reason"] = AuditLogger.get_degraded_reason()
                                    if compact_mode:
                                        final_out = json.dumps(parsed, separators=(",", ":"), ensure_ascii=False) + "\n"
                                    else:
                                        final_out = json.dumps(parsed, indent=2, ensure_ascii=False) + "\n"
                                    injected = True
                            except Exception:
                                pass
                            if not injected:
                                sys.stderr.write(
                                    f"[AUDIT DEGRADED] Persistent audit logging unavailable: {AuditLogger.get_degraded_reason()}\n"
                                )
                        elif compact_mode and raw_out.strip():
                            try:
                                parsed = json.loads(raw_out)
                                final_out = json.dumps(parsed, separators=(",", ":"), ensure_ascii=False) + "\n"
                            except Exception:
                                pass
                        sys.stdout.write(final_out)
                        sys.stdout.flush()
                        if token_report_mode and final_out.strip():
                            from token_telemetry import estimate_tokens, estimate_cost_usd
                            base_tok = estimate_tokens(raw_out)
                            act_tok = estimate_tokens(final_out)
                            saved_tok = max(0, base_tok - act_tok)
                            cost_usd = estimate_cost_usd(act_tok, model=model_pricing, direction="input")
                            sys.stderr.write(
                                f"[TOKEN TELEMETRY] model={model_pricing} tokens={act_tok} "
                                f"(baseline={base_tok}, saved={saved_tok}) est_cost_usd=${cost_usd:.6f}\n"
                            )
                            sys.stderr.flush()
                    # Exit-code contract: a command that returned normally but reported a
                    # failure payload (status=error / missing target) must not exit 0.
                    if dispatch_completed and _payload_signals_failure(raw_out):
                        sys.exit(1)
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
                if AuditLogger.is_tamper_detected():
                    err_payload["audit_tamper_detected"] = True
                err_payload["audit_degraded_reason"] = AuditLogger.get_degraded_reason() or str(e)
            if os.environ.get("BINTRA_DEBUG") == "1":
                import traceback
                err_payload["traceback"] = traceback.format_exc()
            print(json.dumps(err_payload, indent=2, ensure_ascii=False))
            sys.exit(1)
    finally:
        AuditLogger.set_strict_persistence(prev_strict)


def _dispatch_cli():
    """Resolves the command (and the ambiguous `patch` alias) and runs its registered handler."""
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

    handler = registry.resolve(cmd)
    if handler is None:
        print(f"Unknown command '{cmd}'. Run 'cli.py help' for usage.")
        sys.exit(1)
    handler(cmd)




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
