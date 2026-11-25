---
name: bintra
description: Master agent skill for Bintra v1.1.0. Autonomous, continuous semantic reverse engineering, deobfuscation, cross-architecture matching (x86-64 vs ARM64), safe surgical binary patching, Windows system forensics (crashes, file locks, driver conflicts), and weight-space neural program analysis for compiled Windows software (.exe, .dll, PE32/PE32+) and embedded AI models (Safetensors, ONNX, DirectML).
metadata:
  framework: bintra
  version: "1.1.0"
  tool_count: 51
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
| **Binary Dissection, Triage & Diffing** | [`bintra-binary-dissection`](../bintra-binary-dissection/SKILL.md) | PE32/PE32+/ELF headers, ASLR/DEP/CFG mitigations, REX-aware opaque predicates, CFF recovery, x86/ARM64 matching, `.pdata`/RTTI/PDB forensics, slack/overlay inspection (`slack-audit`), Python `.pyc` bytecode (`py-bytecode`), unified `triage`, 10 Metaphorical Senses. |
| **Surgical Binary Patching** | [`bintra-safe-binary-patching`](../bintra-safe-binary-patching/SKILL.md) | Safe byte patching, stack frame balance proprioception ($\Delta RSP/RBP$ guard), automated PE checksum recalculation, strict workspace isolation, fail-closed audit logging. |
| **Windows System Forensics** | [`bintra-windows-troubleshooter`](../bintra-windows-troubleshooter/SKILL.md) | Restart Manager file locks, 0xc0000005 MiniDump (.dmp) & WER inspection, DLL/API-Set/SxS dependencies, PnP/COM/network topology & hardware-to-ring0 dissection, dual-view registry, Authenticode Trust, evidence fusion. |
| **Weight-Space & Safetensors Security** | [`bintra-neural-weight-security`](../bintra-neural-weight-security/SKILL.md) | Zero-execution Safetensors auditing, dual-axis row/column trojan outliers ($>4.5\sigma$), spectral effective rank, selective column direction subtraction without training, `audit_neural_weights` prompt. |
| **Live Runtime Memory & Profiling** | [`bintra-live-runtime-analysis`](../bintra-live-runtime-analysis/SKILL.md) | Passive VAD mapping, read-only `PROCESS_VM_READ` First/Next scans, depth 1-3 pointer resolution, 4-byte-granularity struct dissection, longitudinal `proc-profile` leak diagnosis, CPython memory forensics (`py-mem-inspect`), Crash RCA. |
| **ETW Telemetry & Causality** | [`bintra-etw-telemetry`](../bintra-etw-telemetry/SKILL.md) | Native Advapi32 `OpenTraceW`/`ProcessTrace` ETW consumption (elevated), `WEVTAPI` Event Log polling + Toolhelp32 module-delta fallback, temporal crash correlation. |
| **Ghidra P-Code & Live Bridge** | [`bintra-ghidra-integration`](../bintra-ghidra-integration/SKILL.md) | 64-D High P-Code vector matching, headless analyzer automation, authenticated localhost JSON-RPC queue+poll bridge (`cap.tempdir.marker.write`, explicit `rva`/`va`). |

**Architecture & Theoretical Reference Guides:**
- [`weight-space-programming.md`](references/weight-space-programming.md)
- [`neural-binary-patching.md`](references/neural-binary-patching.md)
- [`neural-circuit-decompilation.md`](references/neural-circuit-decompilation.md)
- [`ghidra-bridge-status.md`](references/ghidra-bridge-status.md)

---

## 2. Global Safety Kernel Guardrails (Complete Mediation)

All 51 MCP tools and CLI commands are strictly governed by the **Safety Kernel & ExecutionGuard**:

1. **Target Immutability:** Never modify source binaries in-place. Passing identical source and destination paths raises `TargetMutationError(TARGET_WRITE_FORBIDDEN)`.
2. **Workspace Confinement:** All outputs must be written inside a designated workspace directory (e.g. `./workspace/...`). Writing into the target's original directory raises `TARGET_DIRECTORY_WRITE_FORBIDDEN`.
3. **Fail-Closed Mediation & Audit Logging:** Unauthorized commands or unregistered tools are aborted before execution with `SecurityViolationError`. Mutating CLI/engine operations initialize `AuditLogger` fail-closed (`AUDIT_INIT_FAILED` aborts execution).
4. **Nociceptive Reflex:** Destructive patches that unbalance the stack frame raise `RuntimeError` unless `force: true` (`--force` / `--no-enforce-nociception`) is explicitly asserted.

---

## 3. Tool Matrix: The 51 Native MCP Tools

Bintra exposes 51 type-safe tools over JSON-RPC 2.0 stdio (`bintra-mcp`):

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

### Tier 2: Windows System & Diagnostic Intelligence (21 Tools)
- `bintra_windows_env_audit`: Host OS build, WOW64 mode, security mitigations.
- `bintra_resolve_dependencies`: Safe DLL search order and API-Set schema resolution.
- `bintra_inspect_crash_reports`: Windows Error Reporting (WER) and Event 1000 logs.
- `bintra_correlate_failure_evidence`: Correlate OS, crash dump, and PE into an Evidence Dossier.
- `bintra_win_catalog_cmd`: Execute pre-registered read-only Windows catalog commands.
- `bintra_registry_audit`: Dual-view (32/64-bit) 11-domain Windows registry inspection.
- `bintra_hardware_audit`: PnP device health, problem codes (`CM_PROB_*`), and physical storage drives.
- `bintra_port_audit`: Read-only audit of COM/LPT ports, USB bridge matching (FTDI, CH340, CP210x, PL2303), and modem control signals.
- `bintra_hardware_topology`: Authoritative PnP bus hierarchy tree and directed hardware graph (Tree, JSON, or Mermaid graph TD).
- `bintra_network_audit`: Live network adapters, physical MAC addresses, link speeds, and IPv4/IPv6 telemetry via `iphlpapi`.
- `bintra_network_hardware_dissect`: Multi-layer hardware-to-ring0 kernel driver reverse engineering (DevNode to KASLR).
- `bintra_network_connections`: Live TCP/UDP connection table with owning process resolution.
- `bintra_driver_audit`: Kernel drivers and execution image bases via PSAPI.
- `bintra_service_audit`: Windows Service Control Manager (SCM) service states.
- `bintra_dmp_inspect`: Multi-stream MiniDump (.dmp) inspection and Access Violation root-cause analysis.
- `bintra_etw_audit`: Event Tracing for Windows (ETW) active sessions and providers.
- `bintra_evidence_graph`: Formal directed Evidence Graph connecting binary, OS, and crash telemetry.
- `bintra_device_driver_intelligence`: Driver Store package matching and estimated driver rank.
- `bintra_process_resource_audit`: Restart Manager file locks, module holders, and process tree.
- `bintra_profile_process`: Passive longitudinal resource profiler & leak diagnoser.
- `bintra_inspect_slack_space`: Audits binary slack space, PE overlays, and document EOF padding.

### Tier 3: Runtime Telemetry, Crash RCA & Live Ghidra Bridge (7 Tools)
- `bintra_vad_inspect`: Passive virtual memory map (VAD) layout and address classification.
- `bintra_memory_scan`: Read-only First/Next Scan across process memory with `PROCESS_VM_READ`.
- `bintra_pointer_scan`: Multi-level backward pointer chain resolver to static module roots.
- `bintra_struct_dissect`: Runtime data structure field dissection and C struct reconstruction.
- `bintra_crash_rca`: Automated Crash Root Cause Analysis (MiniDump + Capstone + Register blame).
- `bintra_etw_capture`: Live ETW trace session capture and causal timeline correlation.
- `bintra_ghidra_live_bridge`: Localhost JSON-RPC bridge for bidirectional Ghidra annotation & P-Code analysis.

### Tier 4: Deep Forensics, Difference & Triaged Evidence Fusion (10 Tools)
- `bintra_python_bytecode`: Python `.pyc` bytecode dissection and frozen-binary (PyInstaller) forensics.
- `bintra_cpython_memory_forensics`: CPython interpreter memory introspection for live processes.
- `bintra_pe_deep_forensics`: x64 `.pdata` `RUNTIME_FUNCTION` recovery, MSVC RTTI vftables, and offline PDB/RSDS verification.
- `bintra_binary_diff`: Semantic diff across two PE binaries or Ghidra exports (WL-CFG hash + 64-D P-Code cosine + API anchors).
- `bintra_ghidra_call_graph`: Caller/callee topology, indirect calls, XREFs, and sensitive Win32 API reachability.
- `bintra_ghidra_data_flow`: Intra-procedural High P-Code SSA def-use slicing with decompiler C correlation.
- `bintra_ghidra_similar_functions`: Behavioral nearest-routine search over a Ghidra export (64-D P-Code cosine vs. an in-export function or external P-code stream).
- `bintra_fuse_evidence`: Multi-signal causal fusion (PE forensics + Crash RCA + Ghidra) with provenance quarantine into `EvidenceGraph`.
- `bintra_triage_binary`: End-to-end unified triage: PE inspection, deep forensics, signature trust, obfuscation, 10-sense sensory perception, embedded-AI scan, slack space, optional crash/Ghidra fusion.
- `bintra_list_capabilities`: Self-describing manifest of all tools with host compatibility and workflows.

---

## 4. Unified CLI Quick Reference

```powershell
# Unified CLI discovery & MCP transport
bintra --help
bintra capabilities [--platform all|cross_platform|windows_native|ghidra_required]
bintra mcp   # alias: mcp-server (or standalone: bintra-mcp)

# Binary dissection, deep forensics, slack/bytecode & unified triage
bintra inspect --file <path>
bintra triage --file <path> [--dmp <crash.dmp>] [--ghidra <export.json|.jsonl|.db>] [--function <name>] [--skip-deobf] [--skip-sensory] [--skip-hybrid-scan] [--format json|md] [--output <path>]   # alias: triage-binary
bintra pe-forensics --file <path> [--pdb <path.pdb>] [--limit 500]
bintra diff-binaries --baseline <a.exe> --target <b.exe> [--mode pe|ghidra_export]
bintra slack-audit --file <path> [--format json|md]   # aliases: overlay-inspect, inspect-slack
bintra py-bytecode --file <path.pyc|.py> [--compare-with <other>] [--limit 50] [--threshold 15]   # alias: py-dissect
bintra deobfuscate [--hex <hex> | --file <path> --offset <off> --length 4096]
bintra dump --file <path> --offset <off> [--length 64]
bintra match --func1 <hex1> --func2 <hex2>   # alias: match-functions
bintra patch-binary --source <src> --offset <off> --patch-hex <hex> [--output <dst>] [--force]   # alias: patch; --patch alias supported; auto-derives workspace output if --output omitted
bintra scan-hybrid --file <path>
bintra sense [--file <path>] [--hex "55 48 89 e5 90 5d c3"]

# Windows system, registry, hardware, network, dependencies & digital signatures
bintra win-audit [--binary <path>] [--format json|md]
bintra resolve-deps --binary <path> [--app-dir <dir>] [--format json|md]
bintra wer-inspect [--binary <name>] [--format json|md]
bintra diagnose --binary <path> [--crash-json <crash.json>] [--ghidra-json <pcode.json>] [--format json|md]
bintra evidence-graph --target <path> [--format json|mermaid]
bintra fuse-evidence [--binary <path>] [--dmp <crash.dmp>] [--ghidra-json <export>] [--function <name>]
bintra win-cmd [list | <command_id>] [--format json|md]
bintra sig-verify <path> [--no-catalog] [--verify-revocation] [--format json|md]
bintra sig-audit <dir> [--pattern *.sys] [--recursive] [--limit 100] [--format json|md]
bintra reg-audit [--domain <DOMAIN>] [--binary <path>] [--format json|md]
bintra reg-read --key <subkey> [--hive HKLM|HKCU|HKCR|HKU|HKCC] [--view dual|64|32|native] --format json   # alias: registry-read
bintra reg-search --query <query> [--hive HKLM] [--root-key <subkey>] [--max-depth 3] [--limit 50] --format json
bintra reg-export --key <subkey> [--hive HKLM] [--output <path.reg>] [--recursive] [--max-depth 1] [--view 64|32]
bintra reg-import <path.reg> [--diff] [--view 64|32] --format json
bintra hw-audit [--problems-only] [--class-filter <class>] [--storage] [--format json|md]
bintra port-audit [--port <COM1>] [--type all|serial|parallel] [--no-modem-status] [--format json|md]
bintra hw-tree [--bus <USB|PCI|ACPI>] [--problems-only] [--format tree|json|mermaid] [--max-devices 300]
bintra hw-net [--virtual] [--format json|md]
bintra hw-dissect [keyword] [--format json|md]
bintra net-conns [--pid <pid>] [--format json|md]
bintra driver-audit [--format json|md]
bintra service-audit [--format json|md]
bintra dev-match [--query <q>] [--class-filter <class>] [--problems-only]
bintra dev-classes --format json
bintra dev-list [--class-filter <class>] [--problems-only] [--limit 50] --format json
bintra dev-search <query> [--limit 50] --format json
bintra dev-info <device> --format json

# Runtime processes, profiling, memory, crashes, ETW & CPython live introspection
bintra file-locks --file <path>
bintra proc-modules --module <name>
bintra sys-perf --format json
bintra proc-list [--limit 50] [--sort memory|commit|threads|handles|pid|name] [--query <q>] [--resolve-users] --format json
bintra proc-search --query <name_or_pid> [--limit 25] --format json
bintra proc-info --pid <pid> --format json
bintra proc-profile --pid <pid> [--samples 10] [--interval 0.2] [--format json|md]   # aliases: process-profile, leak-audit
bintra process-mitigations --pid <pid>
bintra vad-inspect --pid <pid> [--address 0x...] [--regions] [--format json|md]
bintra mem-scan --pid <pid> --type float --mode exact --value 100.0 --session-file .\workspace\scan.json [--format json|md]
bintra pointer-scan --pid <pid> --target 0x... [--max-depth 2] [--max-offset 4096] [--max-results 20] [--format json|md]
bintra dissect-struct --pid <pid> --address 0x... [--size 64] [--name ObjectLayout] [--format json|c|md]
bintra py-mem-inspect --pid <pid> --address 0x... [--type pyobject|pydict|pyascii|pylong]
bintra dmp-inspect [--file <crash.dmp> | --scan] [--format json|md]
bintra crash-rca --dmp <crash.dmp> [--binary <path>] [--format json|md]
bintra etw-audit [--session <name>] [--providers] [--query <q>] [--provider-info <guid>] [--active-kernel] [--limit 50] [--format json|md]
bintra etw-capture [--session-name Bintra_Diagnostic_Trace] [--pid <pid>] [--duration 2.0] [--format json|md]

# Ghidra High P-Code & Live Bridge
bintra match-pcode --func1 <f1.json> --func2 <f2.json>
bintra deobfuscate-pcode [--file <pcode.json> | --pcode '<json>']
bintra ghidra-plan --address <addr> --name <name> [--return-type void] [--comment <text>]
bintra ghidra-analyze --input <export.json|.jsonl|.db> [--output <plan.json>] [--to-sqlite <db>] [--query <q>] [--opcode <op>] [--xref <sym>] [--function <name>] [--sensitive-only] [--profile] [--limit 50]
bintra ghidra-headless --binary <path> [--ghidra-path <dir>] [--project-dir <dir>] [--project-name <name>] [--post-script BintraGhidraBridge.java] [--apply] [--timeout 300] [--max-cpu <n>] [--keep-project]
bintra ghidra-bridge [--start|--daemon|--status|--stop] [--port 41718] [--no-temp-marker]
bintra ghidra-callgraph --input <export> [--function <name>] [--max-depth 4]
bintra ghidra-dataflow --input <export> --function <name> [--var <v>]
bintra ghidra-similar --input <export> [--function <name> | --pcode-file <ops.json>] [--threshold 0.75] [--limit 20] [--min-pcode-ops 1] [--format json|md]

# Weight-Space Security & Maintenance
bintra wsp-audit --model <model.safetensors> [--tensor <name>]
bintra patch-weights --source <in> --output <out> --tensor <name> [--operation column_direction_subtract] [--num-columns 64]
bintra subspace --model <in> --tensor <name> [--mode svd_modes|sparse_extremes|coordinate_slice] [--top-k 8]
bintra decompile --model <in> --tensor <name> [--layer 0] [--head 0] [--num-heads 16] [--circuit-type attention_head|mlp_projection|layer_norm_drift]   # alias: decompile-circuit
bintra diff-weights --baseline <orig> --patched <new> --tensor <name>
bintra probe-trace --model <in> --prompt "<text>" [--max-tokens 32]
bintra verify-behavior --baseline <orig> --patched <new> [--tolerance 0.005]
# (Archived experimental command out of core v1.1 scope per SCOPE.md: bintra synthesize-weights --archived-lineage ...)
bintra update [--check | --yes] [--branch main] [--ref <tag_or_sha>]   # alias: self-update
```

> [!IMPORTANT]
> **CLI Output Format Default Caveat:** `reg-read`, `reg-search`, `reg-import`, `proc-list`, `proc-search`, `proc-info`, `sys-perf`, `dev-classes`, `dev-list`, `dev-search`, and `dev-info` default to `--format md` (human-readable Markdown), while `hw-tree` defaults to `--format tree`. Always pass `--format json` explicitly when parsing stdout programmatically.

---

## 5. Deep Forensics, Triage, Profiling & Capability Discovery (51 MCP Tools)

- **Self-Discovery:** Start with `bintra_list_capabilities` (`bintra capabilities`) to map all 51 tools by host compatibility (`cross_platform`, `windows_native`, `ghidra_required`); `bintra_list_capabilities` publishes a structured MCP `outputSchema`.
- **Unified Triage (`bintra_triage_binary` / `bintra triage`):** Orchestrates PE inspection, deep `.pdata`/RTTI/PDB forensics, Authenticode verification, obfuscation detection, 10-Sense perception, embedded-AI scan, and trailing slack/overlay forensics, with optional Crash RCA and Ghidra fusion plus `--format md` deterministic reporting.
- **Longitudinal Leak Profiling & Slack Auditing:** `bintra_profile_process` (`proc-profile`, bounded `samples_count` `[2, 120]` default `10` and `interval_seconds` `[0.01, 10.0]` default `0.2`) samples Private Bytes, Win32 handles, GDI/USER object counts, threads, and working set to classify sustained vs plateau growth; `bintra_inspect_slack_space` (`slack-audit`) inspects PE overlays and RTF/XML/JSON trailing EOF padding.
- **PE Deep Forensics (`bintra_pe_deep_forensics`):** Recovers x64 `.pdata` `RUNTIME_FUNCTION` boundaries, MSVC RTTI classes/`vftables`, and offline local PDB/RSDS matches.
- **Semantic Binary Diffing (`bintra_binary_diff`):** Compares PE binaries or Ghidra exports using WL-CFG subtree hashing + 64-D P-Code cosine + API/String anchor Jaccard.
- **Ghidra Deep Analysis (`bintra_ghidra_call_graph`, `bintra_ghidra_data_flow`, `bintra_ghidra_similar_functions`):** Extracts caller/callee chains, sensitive API reachability, intra-procedural SSA def-use slices, and Decompiler C AST summaries across `.json`, `.jsonl`, and indexed `.db` SQLite stores. `bintra_ghidra_similar_functions` ranks routines against an in-export or external reference using 64-D P-Code cosine similarity.
- **Unified Causal Fusion (`bintra_fuse_evidence`):** Fuses PE forensics, Crash RCA, and Ghidra Call-Graph/Data-Flow with binary SHA-256 provenance quarantine into `EvidenceGraph`.

---

## 6. MCP Server Resources, Prompts & Exit Contracts

- **4 Read-Only MCP Resources:**
  - `bintra://capabilities`
  - `bintra://security/policy`
  - `bintra://telemetry/session`
  - `bintra://workflows/playbooks`
- **5 Built-In MCP Prompts:**
  - `triage_pe_binary`
  - `root_cause_crash`
  - `audit_windows_host`
  - `diff_binary_versions`
  - `audit_neural_weights`
- **`tools/list` Cursor Pagination:** Supports MCP `2025-06-18` `cursor` / `nextCursor` paging; omitting `cursor` returns the full tool list in one response.
- **CLI Exit-Code Contract:** Commands return non-zero (`1`) on execution errors, guard blocks, `AUDIT_INIT_FAILED`, or failed payloads; `bintra ghidra-headless` propagates tool timeout/error exit codes; `bintra update --check` returns exit code `2` when newer upstream commits exist.
