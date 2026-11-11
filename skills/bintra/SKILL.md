---
name: bintra
description: Master agent skill for Bintra v1.0.0. Autonomous, continuous semantic reverse engineering, deobfuscation, cross-architecture matching (x86-64 vs ARM64), safe surgical binary patching, Windows system forensics (crashes, file locks, driver conflicts), and weight-space neural program analysis for compiled Windows software (.exe, .dll, PE32/PE32+) and embedded AI models (Safetensors, ONNX, DirectML).
metadata:
  framework: bintra
  version: "1.0.0"
  tool_count: 34
  subskills:
    - bintra-binary-dissection
    - bintra-safe-binary-patching
    - bintra-windows-troubleshooter
    - bintra-neural-weight-security
    - bintra-live-runtime-analysis
    - bintra-etw-telemetry
    - bintra-ghidra-integration
---

# Bintra (Autonomous Binary Analysis Master Skill)

`Bintra` is an agent-native, next-generation reverse engineering and Windows system forensics framework. It combines deterministic PE disassembly, continuous semantic representations (MIT CSAIL Weight-Space Programming), read-only process telemetry, and fail-closed Reference Monitoring via the **Safety Kernel**.

---

## 1. The 7 Specialized Sub-Skills

Depending on what the user asks for in natural language, navigate to the specialized sub-skill:

| User Task / Intent | Dedicated Sub-Skill | Primary Capabilities |
|:---|:---|:---|
| **Binary Dissection & Deobfuscation** | [`bintra-binary-dissection`](../bintra-binary-dissection/SKILL.md) | PE header inspection, ASLR/DEP/CFG mitigations, REX-aware opaque predicates pruning, CFF loop recovery, cross-arch function matching (x86 vs ARM64), 10 Metaphorical Senses. |
| **Surgical Binary Patching** | [`bintra-safe-binary-patching`](../bintra-safe-binary-patching/SKILL.md) | Safe byte patching, stack frame balance proprioception ($\Delta RSP/RBP$ guard), automated PE checksum recalculation, strict workspace isolation. |
| **Windows System Forensics** | [`bintra-windows-troubleshooter`](../bintra-windows-troubleshooter/SKILL.md) | File locks diagnosis via Windows Restart Manager, 0xc0000005 crash & MiniDump (.dmp) inspection, missing DLL/API-Set resolution, PnP driver problem codes (`CM_PROB_*`). |
| **Weight-Space & Safetensors Security** | [`bintra-neural-weight-security`](../bintra-neural-weight-security/SKILL.md) | Zero-execution Safetensors auditing, backdoor/trojan outlier neurons ($>4.5\sigma$), spectral effective rank, selective column direction subtraction without training. |
| **Live Runtime Memory & Crash RCA** | [`bintra-live-runtime-analysis`](../bintra-live-runtime-analysis/SKILL.md) | Passive VAD mapping, read-only `PROCESS_VM_READ` First/Next scans, depth 1-3 pointer resolution, 4-byte-granularity struct dissection, Crash RCA. |
| **ETW Telemetry & Causality** | [`bintra-etw-telemetry`](../bintra-etw-telemetry/SKILL.md) | Native Advapi32 `OpenTraceW`/`ProcessTrace` ETW consumption (elevated), `WEVTAPI` Event Log polling + Toolhelp32 module-delta fallback, temporal crash correlation. |
| **Ghidra P-Code & Live Bridge** | [`bintra-ghidra-integration`](../bintra-ghidra-integration/SKILL.md) | 64-D High P-Code vector matching, headless analyzer automation, authenticated localhost JSON-RPC queue+poll bridge (`cap.tempdir.marker.write`, explicit `rva`/`va`). |

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

Bintra exposes 34 type-safe tools over JSON-RPC 2.0 stdio (`bintra-mcp`):

### Tier 1: Core Binary & Disassembly (13 Tools)
- `bintra_inspect_binary`: PE32/PE32+ headers, ASLR/DEP/CFG mitigations, sections, entropy.
- `bintra_deobfuscate_binary`: Detect and prune opaque predicates and CFF dispatcher loops.
- `bintra_dump_bytes`: Read raw bytes and hex/ASCII preview at offset.
- `bintra_match_functions`: Cross-architecture behavioral vector matching.
- `bintra_patch_binary`: Surgical byte patch with stack balance and PE checksum update.
- `bintra_scan_hybrid`: Scan binary for embedded AI runtimes (DirectML, ONNX, GGUF).
- `bintra_sensory_audit`: Holistic 10-Sense cybernetic audit.
- `bintra_match_pcode`: Architecture-invariant Ghidra High P-Code IR matching.
- `bintra_deobfuscate_pcode`: Ghidra P-Code dead branch pruning.
- `bintra_ghidra_analyze`: Batch-analyze Ghidra P-Code export and generate mutation plans.
- `bintra_ghidra_headless`: Launch Ghidra headless deobfuscation bridge.
- `bintra_wsp_audit`: Zero-evaluation Safetensors weight-space audit.
- `bintra_patch_weights`: Selective column direction subtraction for loop attractor cure.

### Tier 2: Windows System & Diagnostic Intelligence (14 Tools)
- `bintra_windows_env_audit`: Host OS build, WOW64 mode, security mitigations.
- `bintra_resolve_dependencies`: Safe DLL search order and API-Set schema resolution.
- `bintra_inspect_crash_reports`: Windows Error Reporting (WER) and Event 1000 logs.
- `bintra_correlate_failure_evidence`: Correlate OS, crash dump, and PE into an Evidence Dossier.
- `bintra_win_catalog_cmd`: Execute pre-registered read-only Windows catalog commands.
- `bintra_registry_audit`: Dual-view (32/64-bit) 11-domain Windows registry inspection.
- `bintra_hardware_audit`: PnP device health and problem codes (`CM_PROB_*`).
- `bintra_driver_audit`: Kernel drivers and execution image bases via PSAPI.
- `bintra_service_audit`: Windows Service Control Manager (SCM) service states.
- `bintra_dmp_inspect`: Multi-stream MiniDump (.dmp) inspection and Access Violation root-cause analysis.
- `bintra_etw_audit`: Event Tracing for Windows (ETW) active sessions and providers.
- `bintra_evidence_graph`: Formal directed Evidence Graph connecting binary, OS, and crash telemetry.
- `bintra_device_driver_intelligence`: Driver Store package matching and estimated driver rank.
- `bintra_process_resource_audit`: Restart Manager file locks, module holders, and process tree.

### Tier 3: Runtime Telemetry, Crash RCA & Live Ghidra Bridge (7 Tools)
- `bintra_vad_inspect`: Passive virtual memory map (VAD) layout and address classification.
- `bintra_memory_scan`: Read-only First/Next Scan across process memory with `PROCESS_VM_READ`.
- `bintra_pointer_scan`: Multi-level backward pointer chain resolver to static module roots.
- `bintra_struct_dissect`: Runtime data structure field dissection and C struct reconstruction.
- `bintra_crash_rca`: Automated Crash Root Cause Analysis (MiniDump + Capstone + Register blame).
- `bintra_etw_capture`: Live ETW trace session capture and causal timeline correlation.
- `bintra_ghidra_live_bridge`: Localhost JSON-RPC bridge for bidirectional Ghidra annotation & P-Code analysis.

---

## 4. Unified CLI Quick Reference

```powershell
# Unified CLI binary (available system-wide)
bintra --help

# Specific workflows
bintra inspect --file <path>
bintra deobfuscate --hex <hex>
bintra match --func1 <hex1> --func2 <hex2>
bintra patch-binary --file <src> --output <dst> --offset <off> --patch-hex <hex>
bintra file-locks --file <path>
bintra proc-modules --module <name>
bintra dev-match --query <query> --problems-only
bintra dmp-inspect --file <path>
bintra wsp-audit --model <model.safetensors>
bintra patch-weights --source <in> --output <out> --tensor <name> --num-columns 64
bintra sense --hex "55 48 89 e5 90 5d c3"
bintra diagnose --binary <path> [--crash-json <crash.json>] [--ghidra-json <pcode.json>]
bintra vad-inspect --pid <pid> [--address 0x...]
bintra mem-scan --pid <pid> --type float --mode exact --value 100.0 --session-file .\workspace\scan.json
bintra pointer-scan --pid <pid> --target 0x... --max-depth 2
bintra dissect-struct --pid <pid> --address 0x... --size 64
bintra crash-rca --dmp <crash.dmp> [--binary <path>]
bintra etw-capture --session-name Bintra_Diagnostic_Trace --pid <pid> --duration 2.0
bintra ghidra-bridge --start --port 41718 --no-temp-marker
```
