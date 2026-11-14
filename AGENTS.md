# AGENTS.md -- AI Coding Agent Operating Guide

> **Target Audience:** Autonomous AI Coding Agents (Claude Code, OpenAI Codex, Antigravity, Cursor, Devin, GitHub Copilot CLI).  
> **Mission:** Continuous Semantic Reverse Engineering & Security Analysis for compiled Windows software (`.exe`, `.dll`, PE32/PE32+) and embedded AI runtimes.

---

## 1. Quick Start: The 3 Operational Modalities

Autonomous agents can interact with `bintra` via three direct modalities:

### Modality 1: Model Context Protocol (MCP) -- Recommended for Direct Tool Calls
Launch the native zero-dependency MCP server via stdio:
```json
{
  "mcpServers": {
    "bintra": {
      "command": "bintra-mcp",
      "args": []
    }
  }
}
```
Exposes **42 type-safe tools**:
- **Core Binary & Decompilation (13 Tools):** `bintra_inspect_binary`, `bintra_dump_bytes`, `bintra_deobfuscate_binary`, `bintra_match_functions`, `bintra_patch_binary`, `bintra_scan_hybrid`, `bintra_sensory_audit`, `bintra_match_pcode`, `bintra_deobfuscate_pcode`, `bintra_ghidra_analyze`, `bintra_ghidra_headless`, `bintra_wsp_audit`, `bintra_patch_weights`.
- **Windows System Intelligence & Forensics (14 Tools):** `bintra_windows_env_audit`, `bintra_resolve_dependencies`, `bintra_inspect_crash_reports`, `bintra_correlate_failure_evidence`, `bintra_win_catalog_cmd`, `bintra_registry_audit`, `bintra_hardware_audit`, `bintra_driver_audit`, `bintra_service_audit`, `bintra_dmp_inspect`, `bintra_etw_audit`, `bintra_evidence_graph`, `bintra_device_driver_intelligence`, `bintra_process_resource_audit`.
- **Runtime Telemetry, Crash RCA & Live Ghidra Bridge (7 Tools):** `bintra_vad_inspect`, `bintra_memory_scan`, `bintra_pointer_scan`, `bintra_struct_dissect`, `bintra_crash_rca`, `bintra_etw_capture`, `bintra_ghidra_live_bridge`.

### Modality 2: Unified CLI (`bintra`) -- Recommended for Terminal / Bash / PowerShell
```powershell
bintra <command> [options]
# Or: python -m cli <command> [options]
```
All commands produce machine-readable JSON on `stdout` and exit with code `0` on success.

### Modality 3: Pure Python API -- Recommended for In-Process Scripts
```python
import sys
from binary_neural_engine import BinaryFormatInspector, ContinuousDeobfuscator, SurgicalBinaryPatcher, SensoryCortex
from ghidra_pcode_vectorizer import GhidraAnnotationPlanner, PcodeDeobfuscator
from windows_intelligence import (
    WindowsOSProfiler, WindowsDependencyResolver, WindowsDeviceInspector,
    WindowsSecurityInspector, WindowsCrashAnalyzer, DiagnosticEvidenceCorrelator,
    CommandCatalog, CommandExecutor, PowerShellExecutor,
    RegistryCatalog, WindowsRegistryReader, WindowsRegistryAnalyzer,
    NativeDeviceInspector, KernelDriverInspector, ServiceManagerInspector, ProcessMitigationInspector,
    MiniDumpParser, EventLogCollector, EtwController,
    EvidenceGraph, EvidenceNode, EvidenceEdge, CausalitySynthesizer
)
from windows_intelligence.process_intelligence import FileUsageInspector, ModuleInventory, ProcessInventory
from windows_intelligence.device_intelligence import DriverMatcher, DriverPackageInventory
from windows_intelligence.runtime_telemetry import (
    VirtualMemoryInspector, ProcessMemoryScanner, PointerScanner, StructureDissector,
    CrashRootCauseAnalyzer, EtwLiveCaptureSession, EtwTimelineCorrelator
)
from ghidra_live_bridge import GhidraLiveBridgeServer, GhidraLiveBridgeClient
from security import ExecutionGuard, Capability
```

---

## 2. Agent Skills Architecture (`skills/`)

Bintra provides **7 specialized sub-skills** (plus the [`bintra`](skills/bintra/SKILL.md) master router = 8 total skills):

1. **[`bintra-binary-dissection`](skills/bintra-binary-dissection/SKILL.md):**  
   Anatomy inspection, ASLR/DEP/CFG mitigations, REX-aware opaque predicates, CFF dispatcher loops, cross-architecture matching (x86-64 vs ARM64), 10 Metaphorical Senses.
2. **[`bintra-safe-binary-patching`](skills/bintra-safe-binary-patching/SKILL.md):**  
   Safe byte modification, stack frame balance proprioception ($\Delta RSP/RBP$ guard), automated PE checksum recalculation, strict workspace isolation.
3. **[`bintra-windows-troubleshooter`](skills/bintra-windows-troubleshooter/SKILL.md):**  
   Crash diagnostics (0xc0000005, NULL dereference), MiniDump (.dmp) inspection, Restart Manager file locks, loaded DLL tracking, driver problem codes (`CM_PROB_*`).
4. **[`bintra-neural-weight-security`](skills/bintra-neural-weight-security/SKILL.md):**  
   Safetensors weight auditing without execution, backdoor/trojan outlier neurons ($>4.5\sigma$), spectral effective rank, selective column direction subtraction without training.
5. **[`bintra-live-runtime-analysis`](skills/bintra-live-runtime-analysis/SKILL.md):**  
   Passive VAD layout (`VirtualQueryEx`), read-only `PROCESS_VM_READ` First/Next scans (`session_id`, zero-fill-free reads), depth 1-3 pointer path discovery, 4-byte-granularity struct dissection, Crash RCA.
6. **[`bintra-etw-telemetry`](skills/bintra-etw-telemetry/SKILL.md):**  
   Native `OpenTraceW`/`ProcessTrace` ETW consumption (elevated), `WEVTAPI` Event Log + Toolhelp32 `IMAGE_LOAD` fallback, explicit source provenance, strict PID filtering, temporal crash correlation.
7. **[`bintra-ghidra-integration`](skills/bintra-ghidra-integration/SKILL.md):**  
   64-D High P-Code IR matching, headless automation, authenticated localhost JSON-RPC queue+poll bridge (`cap.tempdir.marker.write`, explicit `rva`/`va` resolution).

---

## 3. Critical Rules for AI Agents on Windows (Safety Kernel)

1. **Target Immutability & Workspace Confinement:**  
   Never modify source binaries in-place. Passing `file_path == output_path` or writing inside the target's original directory is strictly blocked with `TargetMutationError`. Always write outputs to an isolated `./workspace/` directory.
2. **Avoid Inline JSON Quoting in PowerShell:**  
   Windows PowerShell strips unescaped double quotes from inline arguments like `'[{"opcode": "INT_ADD"}]'`.  
   *Best Practice:* Always write complex JSON payloads to a temporary file (`temp_pcode.json`) and pass `--file temp_pcode.json`.
3. **Deterministic Machine Output:**  
   Parse `stdout` directly with `json.loads(output)`. Stderr contains telemetry logs or scope warnings that should not interfere with JSON parsing.
4. **Stack Balance Nociceptive Reflex:**  
   `patch-binary` checks stack frame balance. If a patch injects stack-altering instructions over neutral code, it aborts to prevent silent memory corruption.

---

## 4. Command Reference & Payload Matrix

| Command | Purpose | Input Flags | Expected Output JSON Keys |
|:---|:---|:---|:---|
| `inspect` | PE32/PE32+ deep inspection (headers, imports, exports) | `--file <path>` | `format`, `windows_security_mitigations`, `imports`, `exports`, `sections` |
| `dump` | Extract raw bytes & hex preview at offset/RVA | `--file <path> --offset <N> [--length <L>]` | `file`, `offset`, `length`, `hex`, `ascii_preview` |
| `deobfuscate` | Prune opaque predicates & CFF | `--file <path> [--offset <N>]` or `--hex "<bytes>"` | `opaque_predicates_detected`, `predicates`, `control_flow_flattening`, `complexity_reduction_percentage` |
| `match` | Cross-architecture matching | `--func1 "<hex>" --func2 "<hex>"` | `cosine_similarity`, `is_semantic_match`, `confidence` |
| `patch-binary` | Surgical byte patch with RSP balance | `--file <path> --output <dst> --offset <N> --patch-hex "<hex>"` | `is_safe`, `file_offset`, `patch_length`, `pe_checksum_recalculated` |
| `scan-hybrid` | Scan embedded AI runtimes | `--file <path>` | `embedded_logic_assets_count`, `findings`, `overall_shannon_entropy` |
| `sense` | Holistic 10-sense perception | `--file <path>` or `--hex "<bytes>"` | `active_senses_count`, `overall_sensory_efficiency`, `senses` |
| `match-pcode` | Architecture-invariant P-code matching | `--func1 <file.json> --func2 <file.json>` | `pcode_cosine_similarity`, `is_semantic_match`, `confidence` |
| `deobfuscate-pcode`| Simplify P-code dead branches | `--file <pcode.json>` | `is_obfuscated`, `opaque_predicates_count`, `prunable_operations` |
| `ghidra-analyze`| Batch-analyze exported Ghidra P-Code | `--input <export.json> --output <plan.json>` | `analyzed_functions`, `rename_actions`, `comment_actions`, `summary` |
| `ghidra-headless`| Run Ghidra headless deobfuscation | `--binary <path> [--apply]` | Executes `BintraGhidraBridge.java` via `analyzeHeadless.bat` |
| `wsp-audit` | Audit embedded weights | `--model <model.safetensors>` | `primary_tensor`, `effective_rank_analysis`, `surgical_amenability`, `zero_eval_security_audit` |
| `patch-weights` | Column direction subtraction | `--source <in> --output <out> --tensor <t>` | `output_path`, `output_sha256`, `patched_tensor_names`, `metrics` |
| `win-audit` | Profile host OS, graphics, security | `[--binary <path>] [--format json\|md]` | `os`, `devices`, `security` |
| `resolve-deps` | Safe DLL search order & exports audit | `--binary <path> [--format json\|md]` | `verdict`, `loader_mode`, `resolved_dlls`, `missing_dlls` |
| `wer-inspect` | Scan WER archives & Event Log 1000 | `[--binary <name>] [--format json\|md]` | `wer_reports`, `event_log_errors`, `minidumps` |
| `diagnose` | Correlate OS, crash & PE into Dossier | `--binary <path> [--crash-json <f.json>] [--ghidra-json <f.json>]` | `verdict`, `severity`, `epistemic_classification`, `root_cause_summary`, `binary_mapping` |
| `win-cmd` | Execute read-only command from catalog | `[command_id] [--format json\|md]` | `status`, `command_id`, `duration_ms` / `error` |
| `reg-audit` | Dual-view 11-domain registry audit | `[--domain <name>] [--format json\|md]` | `status`, `domains` / `domain`, `keys_inspected`, `discrepancies` |
| `hw-audit` | Inspect PnP hardware & CM_PROB_* codes | `[--problems-only] [--format json\|md]` | `status`, `is_hardware_healthy`, `display_adapters`, `problem_devices` |
| `driver-audit` | Kernel drivers & image base introspection | `[--format json\|md]` | `total_drivers_loaded`, `graphics_drivers`, `audio_drivers`, `drivers_sample` |
| `service-audit` | Interrogate SCM service states | `[--format json\|md]` | `total_services_enumerated`, `running_services_count`, `stopped_services_count` |
| `dmp-inspect` | Multi-stream MiniDump & AV analysis | `[--file <f>] [--scan] [--format json\|md]` | `status`, `system_info`, `exception_info` *(or `total_dumps_discovered`, `crash_reports`)* |
| `etw-audit` | Audit ETW sessions & providers | `[--session <s>] [--format json\|md]` | `standard_sessions_probed`, `active_sessions`, `providers` |
| `file-locks` | Detect processes holding file locks | `--file <path>` | `status`, `is_locked`, `usage_classifications`, `locking_processes` |
| `proc-modules` | Find processes hosting loaded DLL | `--module <name>` | `status`, `query`, `hosting_processes_count`, `hosting_processes` |
| `dev-match` | Match PnP devices with Driver Store | `[--query <name>] [--problems-only]` | `status`, `devices_audited`, `driver_packages_cataloged`, `device_reports` |
| `vad-inspect` | Passive virtual memory (VAD) inspection | `--pid <pid> [--address 0x...] [--regions]` | `status`, `is_simulated`, `architecture`, `summary`, `module_count` |
| `mem-scan` | Read-only value scan (`PROCESS_VM_READ`) | `--pid <pid> --type <t> --mode <m> [--value <v>] [--session-file <f>]` | `session_id`, `data_type`, `scan_type`, `total_candidates`, `candidates_sample` |
| `pointer-scan` | Backward pointer path resolver (depth 1-3) | `--pid <pid> --target 0x... [--max-depth 1\|2\|3]` | `pid`, `target_address`, `max_depth_searched`, `heuristic`, `paths_count`, `paths` |
| `dissect-struct`| 4-byte-granularity struct field inference | `--pid <pid> --address 0x... [--size 64]` | `status`, `heuristic`, `fields_count`, `fields`, `c_struct_definition` |
| `crash-rca` | MiniDump + disassembly root-cause blame | `--dmp <file.dmp> [--binary <exe>]` | `exception_code`, `access_type`, `root_cause_classification`, `confidence`, `culprit_register` |
| `etw-capture` | Hybrid ETW / Event Log timeline capture | `--session-name <s> [--pid <pid>] [--duration 2.0]` | `session_info`, `events_count`, `event_sources`, `temporal_verdict` |
| `ghidra-bridge` | Authenticated localhost Ghidra JSON-RPC | `--start\|--daemon\|--status\|--stop\|--annotate-* [--no-temp-marker]` | `is_running`, `port`, `ghidra_client_connected`, `queued_commands` |

> **Audit Integrity & Failure Disclosures:** Mutation commands (`patch`, `patch-binary`, `patch-weights`, confirmed `update --yes`) fail closed (`AUDIT_INIT_FAILED`) if the hash-chained audit log cannot be recovered or written. Read-only commands surface persistent log degradation via `"audit_degraded": true` and `audit_degraded_reason`.

---

## 5. Driving Common Vibe-Coding Workflows

### Scenario 1: User says "Why is this desktop application crashing on startup?"
1. Inspect the MiniDump file (or run full disassembly-backed Crash RCA):
   ```powershell
   bintra dmp-inspect --file "C:\path\to\crash.dmp"
   bintra crash-rca --dmp "C:\path\to\crash.dmp" --binary "C:\path\to\target.exe"
   ```
2. Check for missing DLL dependencies:
   ```powershell
   bintra resolve-deps --binary "C:\path\to\target.exe"
   ```
3. Synthesize the complete causality dossier (passing a JSON crash record to `--crash-json`, never a raw binary `.dmp` path):
   ```powershell
   bintra diagnose --binary "C:\path\to\target.exe" --crash-json ".\workspace\crash_record.json"
   ```

### Scenario 2: User says "This file is locked and I can't replace it."
1. Interrogate the Windows Restart Manager:
   ```powershell
   bintra file-locks --file "C:\path\to\locked.dll"
   ```
2. Inform the user which application (PID, Name, Service) holds the lock without forcefully killing system processes.

### Scenario 3: User says "Patch this instruction to bypass a check."
1. Create a segregated output directory:
   ```powershell
   mkdir workspace -Force
   ```
2. Surgically apply the patch to the workspace destination:
   ```powershell
   bintra patch-binary --file "C:\path\to\target.exe" --output ".\workspace\target_patched.exe" --offset 0x2400 --patch-hex "90 90"
   ```
3. Verify that `is_safe: true`, `pe_checksum_recalculated: true`, and `original_sha256 != patched_sha256`.

---

## 6. Deep Reverse Engineering & AI Discoverability Additions (v1.1 Upgrade)

All 6 new tools below are **strictly read-only** (`cap.file.read`) and work **cross-platform** on static PE binaries and Ghidra JSON exports:

| MCP Tool | CLI Command | Purpose |
|:---|:---|:---|
| `bintra_list_capabilities` | `bintra capabilities` | Self-describing JSON manifest of all 42 tools, environment compatibility (`cross_platform` / `windows_native` / `ghidra_required`), and workflows. |
| `bintra_pe_deep_forensics` | `bintra pe-forensics` | x64 `.pdata` `RUNTIME_FUNCTION` boundary recovery, MSVC RTTI (`TypeDescriptor`, `CompleteObjectLocator`, `vftable`), and offline local PDB/RSDS verification. |
| `bintra_binary_diff` | `bintra diff-binaries` | Semantic diffing across two PE binaries or two Ghidra exports (WL-CFG subtree hash + 64-D P-Code cosine + API/String anchor Jaccard). |
| `bintra_ghidra_call_graph` | `bintra ghidra-callgraph` | Caller/callee topology, indirect calls, XREFs, and sensitive Win32 API reachability paths. |
| `bintra_ghidra_data_flow` | `bintra ghidra-dataflow` | Intra-procedural High P-Code SSA def-use backward/forward slice + Decompiler C AST/local variable correlation. |
| `bintra_fuse_evidence` | `bintra fuse-evidence` | Multi-signal causal fusion of PE Deep Forensics + MiniDump Crash RCA + Ghidra Call-Graph/Data-Flow into `EvidenceGraph`. |

### AI Agent Decision Tree
1. **First turn on an unfamiliar host:** Call `bintra_list_capabilities` (or `bintra capabilities`) to inspect which tools are `cross_platform` vs `windows_native` vs `ghidra_required`.
2. **Stripped x64 PE without PDB:** Run `bintra_inspect_binary` -> `bintra_pe_deep_forensics` (recovers `.pdata` function boundaries & MSVC RTTI classes/vtables).
3. **Deep Ghidra export or live bridge:** Run `bintra_ghidra_analyze` -> `bintra_ghidra_call_graph` -> `bintra_ghidra_data_flow` -> `bintra_fuse_evidence`.
4. **Comparing two builds/versions:** Run `bintra_binary_diff` (`mode: "pe"` or `mode: "ghidra_export"`).
