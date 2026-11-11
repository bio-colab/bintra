---
name: reverse-engineer-anything
description: Master agent skill for REA-Neural v7.4.0. Autonomous, continuous semantic reverse engineering, deobfuscation, cross-architecture matching (x86-64 vs ARM64), safe surgical binary patching, Windows system forensics (crashes, file locks, driver conflicts), and weight-space neural program analysis for compiled Windows software (.exe, .dll, PE32/PE32+) and embedded AI models (Safetensors, ONNX, DirectML).
metadata:
  framework: rea-neural
  version: "7.4.0"
  tool_count: 34
  subskills:
    - rea-binary-dissection
    - rea-safe-binary-patching
    - rea-windows-troubleshooter
    - rea-neural-weight-security
    - rea-live-runtime-analysis
    - rea-etw-telemetry
    - rea-ghidra-integration
---

# Reverse Engineer Anything (REA-Neural Master Skill)

`REA-Neural` is an agent-native, next-generation reverse engineering and Windows system forensics framework. It combines deterministic PE disassembly, continuous semantic representations (MIT CSAIL Weight-Space Programming), read-only process telemetry, and fail-closed Reference Monitoring via the **Safety Kernel**.

---

## 1. The 7 Specialized Sub-Skills

Depending on what the user asks for in natural language, navigate to the specialized sub-skill:

| User Task / Intent | Dedicated Sub-Skill | Primary Capabilities |
|:---|:---|:---|
| **Binary Dissection & Deobfuscation** | [`rea-binary-dissection`](../rea-binary-dissection/SKILL.md) | PE header inspection, ASLR/DEP/CFG mitigations, REX-aware opaque predicates pruning, CFF loop recovery, cross-arch function matching (x86 vs ARM64), 10 Metaphorical Senses. |
| **Surgical Binary Patching** | [`rea-safe-binary-patching`](../rea-safe-binary-patching/SKILL.md) | Safe byte patching, stack frame balance proprioception ($\Delta RSP/RBP$ guard), automated PE checksum recalculation, strict workspace isolation. |
| **Windows System Forensics** | [`rea-windows-troubleshooter`](../rea-windows-troubleshooter/SKILL.md) | File locks diagnosis via Windows Restart Manager, 0xc0000005 crash & MiniDump (.dmp) inspection, missing DLL/API-Set resolution, PnP driver problem codes (`CM_PROB_*`). |
| **Weight-Space & Safetensors Security** | [`rea-neural-weight-security`](../rea-neural-weight-security/SKILL.md) | Zero-execution Safetensors auditing, backdoor/trojan outlier neurons ($>4.5\sigma$), spectral effective rank, selective column direction subtraction without training. |
| **Live Runtime Memory & Crash RCA** | [`rea-live-runtime-analysis`](../rea-live-runtime-analysis/SKILL.md) | Passive VAD mapping, read-only `PROCESS_VM_READ` First/Next scans, depth 1-3 pointer resolution, 4-byte-granularity struct dissection, Crash RCA. |
| **ETW Telemetry & Causality** | [`rea-etw-telemetry`](../rea-etw-telemetry/SKILL.md) | Native Advapi32 `OpenTraceW`/`ProcessTrace` ETW consumption (elevated), `WEVTAPI` Event Log polling + Toolhelp32 module-delta fallback, temporal crash correlation. |
| **Ghidra P-Code & Live Bridge** | [`rea-ghidra-integration`](../rea-ghidra-integration/SKILL.md) | 64-D High P-Code vector matching, headless analyzer automation, authenticated localhost JSON-RPC queue+poll bridge (`cap.tempdir.marker.write`, explicit `rva`/`va`). |

**Architecture & Theoretical Reference Guides:**
- [`weight-space-programming.md`](references/weight-space-programming.md)
- [`neural-binary-patching.md`](references/neural-binary-patching.md)
- [`neural-circuit-decompilation.md`](references/neural-circuit-decompilation.md)
- [`ghidra-bridge-status.md`](references/ghidra-bridge-status.md)

---

## 2. Global Safety Kernel Guardrails (Complete Mediation)

All 34 MCP tools and CLI commands are strictly governed by the **Safety Kernel & ExecutionGuard**:

1. **Target Immutability:** Never modify source binaries in-place. Passing identical source and destination paths raises `TargetMutationError(TARGET_WRITE_FORBIDDEN)`.
2. **Workspace Confinement:** All outputs must be written inside a designated workspace directory (e.g. `./workspace/...`). Writing into the target's original directory raises `TARGET_DIRECTORY_WRITE_FORBIDDEN`.
3. **Fail-Closed Mediation:** Unauthorized commands or unregistered tools are aborted before execution with `SecurityViolationError`.
4. **Nociceptive Reflex:** Destructive patches that unbalance the stack frame raise `RuntimeError` unless `force: true` is explicitly asserted.

---

## 3. Tool Matrix: The 34 Native MCP Tools

REA-Neural exposes 34 type-safe tools over JSON-RPC 2.0 stdio (`rea-mcp`):

### Tier 1: Core Binary & Disassembly (13 Tools)
- `rea_inspect_binary`: PE32/PE32+ headers, ASLR/DEP/CFG mitigations, sections, entropy.
- `rea_deobfuscate_binary`: Detect and prune opaque predicates and CFF dispatcher loops.
- `rea_dump_bytes`: Read raw bytes and hex/ASCII preview at offset.
- `rea_match_functions`: Cross-architecture behavioral vector matching.
- `rea_patch_binary`: Surgical byte patch with stack balance and PE checksum update.
- `rea_scan_hybrid`: Scan binary for embedded AI runtimes (DirectML, ONNX, GGUF).
- `rea_sensory_audit`: Holistic 10-Sense cybernetic audit.
- `rea_match_pcode`: Architecture-invariant Ghidra High P-Code IR matching.
- `rea_deobfuscate_pcode`: Ghidra P-Code dead branch pruning.
- `rea_ghidra_analyze`: Batch-analyze Ghidra P-Code export and generate mutation plans.
- `rea_ghidra_headless`: Launch Ghidra headless deobfuscation bridge.
- `rea_wsp_audit`: Zero-evaluation Safetensors weight-space audit.
- `rea_patch_weights`: Selective column direction subtraction for loop attractor cure.

### Tier 2: Windows System & Diagnostic Intelligence (14 Tools)
- `rea_windows_env_audit`: Host OS build, WOW64 mode, security mitigations.
- `rea_resolve_dependencies`: Safe DLL search order and API-Set schema resolution.
- `rea_inspect_crash_reports`: Windows Error Reporting (WER) and Event 1000 logs.
- `rea_correlate_failure_evidence`: Correlate OS, crash dump, and PE into an Evidence Dossier.
- `rea_win_catalog_cmd`: Execute pre-registered read-only Windows catalog commands.
- `rea_registry_audit`: Dual-view (32/64-bit) 11-domain Windows registry inspection.
- `rea_hardware_audit`: PnP device health and problem codes (`CM_PROB_*`).
- `rea_driver_audit`: Kernel drivers and execution image bases via PSAPI.
- `rea_service_audit`: Windows Service Control Manager (SCM) service states.
- `rea_dmp_inspect`: Multi-stream MiniDump (.dmp) inspection and Access Violation root-cause analysis.
- `rea_etw_audit`: Event Tracing for Windows (ETW) active sessions and providers.
- `rea_evidence_graph`: Formal directed Evidence Graph connecting binary, OS, and crash telemetry.
- `rea_device_driver_intelligence`: Driver Store package matching and estimated driver rank.
- `rea_process_resource_audit`: Restart Manager file locks, module holders, and process tree.

### Tier 3: Runtime Telemetry, Crash RCA & Live Ghidra Bridge (7 Tools)
- `rea_vad_inspect`: Passive virtual memory map (VAD) layout and address classification.
- `rea_memory_scan`: Read-only First/Next Scan across process memory with `PROCESS_VM_READ`.
- `rea_pointer_scan`: Multi-level backward pointer chain resolver to static module roots.
- `rea_struct_dissect`: Runtime data structure field dissection and C struct reconstruction.
- `rea_crash_rca`: Automated Crash Root Cause Analysis (MiniDump + Capstone + Register blame).
- `rea_etw_capture`: Live ETW trace session capture and causal timeline correlation.
- `rea_ghidra_live_bridge`: Localhost JSON-RPC bridge for bidirectional Ghidra annotation & P-Code analysis.

---

## 4. Unified CLI Quick Reference

```powershell
# Unified CLI binary (available system-wide)
rea-neural --help

# Specific workflows
rea-neural inspect --file <path>
rea-neural deobfuscate --hex <hex>
rea-neural match --func1 <hex1> --func2 <hex2>
rea-neural patch-binary --file <src> --output <dst> --offset <off> --patch-hex <hex>
rea-neural file-locks --file <path>
rea-neural proc-modules --module <name>
rea-neural dev-match --query <query> --problems-only
rea-neural dmp-inspect --file <path>
rea-neural wsp-audit --model <model.safetensors>
rea-neural patch-weights --source <in> --output <out> --tensor <name> --num-columns 64
rea-neural sense --hex "55 48 89 e5 90 5d c3"
rea-neural diagnose --binary <path> [--crash-json <crash.json>] [--ghidra-json <pcode.json>]
rea-neural vad-inspect --pid <pid> [--address 0x...]
rea-neural mem-scan --pid <pid> --type float --mode exact --value 100.0 --session-file .\workspace\scan.json
rea-neural pointer-scan --pid <pid> --target 0x... --max-depth 2
rea-neural dissect-struct --pid <pid> --address 0x... --size 64
rea-neural crash-rca --dmp <crash.dmp> [--binary <path>]
rea-neural etw-capture --session-name REA_Diagnostic_Trace --pid <pid> --duration 2.0
rea-neural ghidra-bridge --start --port 41718 --no-temp-marker
```
