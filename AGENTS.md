# AGENTS.md -- AI Coding Agent Operating Guide

> **Target Audience:** Autonomous AI Coding Agents (Claude Code, OpenAI Codex, Antigravity, Cursor, Devin, GitHub Copilot CLI).  
> **Mission:** Continuous Semantic Reverse Engineering & Security Analysis for compiled Windows software (`.exe`, `.dll`, PE32/PE32+) and embedded AI runtimes.

---

## 1. Quick Start: The 3 Operational Modalities

Autonomous agents can interact with `rea-neural` via three direct modalities:

### Modality 1: Model Context Protocol (MCP) -- Recommended for Direct Tool Calls
Launch the native zero-dependency MCP server via stdio:
```json
{
  "mcpServers": {
    "rea-neural": {
      "command": "rea-mcp",
      "args": []
    }
  }
}
```
Exposes **34 type-safe tools**:
- **Core Binary & Decompilation (13 Tools):** `rea_inspect_binary`, `rea_dump_bytes`, `rea_deobfuscate_binary`, `rea_match_functions`, `rea_patch_binary`, `rea_scan_hybrid`, `rea_sensory_audit`, `rea_match_pcode`, `rea_deobfuscate_pcode`, `rea_ghidra_analyze`, `rea_ghidra_headless`, `rea_wsp_audit`, `rea_patch_weights`.
- **Windows System Intelligence & Forensics (14 Tools):** `rea_windows_env_audit`, `rea_resolve_dependencies`, `rea_inspect_crash_reports`, `rea_correlate_failure_evidence`, `rea_win_catalog_cmd`, `rea_registry_audit`, `rea_hardware_audit`, `rea_driver_audit`, `rea_service_audit`, `rea_dmp_inspect`, `rea_etw_audit`, `rea_evidence_graph`, `rea_device_driver_intelligence`, `rea_process_resource_audit`.
- **Runtime Telemetry, Crash RCA & Live Ghidra Bridge (7 Tools):** `rea_vad_inspect`, `rea_memory_scan`, `rea_pointer_scan`, `rea_struct_dissect`, `rea_crash_rca`, `rea_etw_capture`, `rea_ghidra_live_bridge`.

### Modality 2: Unified CLI (`rea-neural`) -- Recommended for Terminal / Bash / PowerShell
```powershell
rea-neural <command> [options]
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
from security import ExecutionGuard, Capability
```

---

## 2. Agent Skills Architecture (`skills/`)

REA-Neural provides 4 specialized skills designed for AI Agents during "vibe coding":

1. **[`rea-binary-dissection`](skills/rea-binary-dissection/SKILL.md):**  
   Anatomy inspection, ASLR/DEP/CFG mitigations, REX-aware opaque predicates, CFF dispatcher loops, cross-architecture matching (x86-64 vs ARM64), 10 Metaphorical Senses.
2. **[`rea-safe-binary-patching`](skills/rea-safe-binary-patching/SKILL.md):**  
   Safe byte modification, stack frame balance proprioception ($\Delta RSP/RBP$ guard), automated PE checksum recalculation, strict workspace isolation.
3. **[`rea-windows-troubleshooter`](skills/rea-windows-troubleshooter/SKILL.md):**  
   Crash diagnostics (0xc0000005, NULL dereference, DEP violation), MiniDump (.dmp) inspection, Restart Manager file locks, loaded DLL tracking, driver problem codes (`CM_PROB_*`).
4. **[`rea-neural-weight-security`](skills/rea-neural-weight-security/SKILL.md):**  
   Safetensors weight auditing without execution, backdoor/trojan outlier neurons ($>4.5\sigma$), spectral effective rank, selective column direction subtraction without training.

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
| `inspect` | PE32/PE32+ deep inspection (headers, imports, exports) | `--file <path>` | `format`, `mitigations`, `imports`, `exports`, `sections` |
| `dump` | Extract raw bytes & hex preview at offset/RVA | `--file <path> --offset <N> [--length <L>]` | `file`, `offset`, `length`, `hex`, `ascii_preview` |
| `deobfuscate` | Prune opaque predicates & CFF | `--file <path> [--offset <N>]` or `--hex "<bytes>"` | `opaque_predicates`, `control_flow_flattening`, `pruned_hex` |
| `match` | Cross-architecture matching | `--func1 "<hex>" --func2 "<hex>"` | `cosine_similarity`, `is_semantic_match`, `confidence` |
| `patch-binary` | Surgical byte patch with RSP balance | `--file <path> --output <dst> --offset <N> --patch-hex "<hex>"` | `is_safe`, `target_offset`, `patch_length`, `pe_checksum_recalculated` |
| `scan-hybrid` | Scan embedded AI runtimes | `--file <path>` | `embedded_logic_assets_count`, `embedded_assets`, `shannon_entropy` |
| `sense` | Holistic 10-sense perception | `--file <path>` or `--hex "<bytes>"` | `active_senses_count`, `overall_sensory_efficiency`, `senses` |
| `match-pcode` | Architecture-invariant P-code matching | `--func1 <file.json> --func2 <file.json>` | `pcode_cosine_similarity`, `is_semantic_match`, `confidence` |
| `deobfuscate-pcode`| Simplify P-code dead branches | `--file <pcode.json>` | `is_obfuscated`, `opaque_predicates_count`, `prunable_operations` |
| `ghidra-analyze`| Batch-analyze exported Ghidra P-Code | `--input <export.json> --output <plan.json>` | `analyzed_functions`, `rename_actions`, `comment_actions` |
| `ghidra-headless`| Run Ghidra headless deobfuscation | `--binary <path> [--apply]` | Executes `ReaNeuralGhidraBridge.java` via `analyzeHeadless.bat` |
| `wsp-audit` | Audit embedded weights | `--model <model.safetensors>` | `task_domain_inference`, `receptive_field_profile`, `amenability` |
| `patch-weights` | Column direction subtraction | `--source <in> --output <out> --tensor <t>` | `operation`, `sparsity_ratio`, `frobenius_norm_delta` |
| `win-audit` | Profile host OS, graphics, security | `[--binary <path>] [--format json|md]` | `os`, `devices`, `security` |
| `resolve-deps` | Safe DLL search order & exports audit | `--binary <path> [--format json|md]` | `verdict`, `loader_mode`, `resolved_dlls`, `missing_dlls` |
| `wer-inspect` | Scan WER archives & Event Log 1000 | `[--binary <name>] [--format json|md]` | `wer_reports`, `event_log_errors`, `counts` |
| `diagnose` | Correlate OS, crash & PE into Dossier | `--binary <path> [--crash <f>] [--ghidra <f>]` | `verdict`, `root_cause_summary`, `binary_mapping` |
| `win-cmd` | Execute read-only command from catalog | `[command_id] [--format json|md]` | `status`, `schema`, `duration_ms`, `data` |
| `reg-audit` | Dual-view 11-domain registry audit | `[--domain <name>] [--format json|md]` | `domains`, `keys`, `discrepancies`, `critical_policies` |
| `hw-audit` | Inspect PnP hardware & CM_PROB_* codes | `[--problems-only] [--format json|md]` | `status`, `is_hardware_healthy`, `display_adapters`, `problem_devices` |
| `driver-audit` | Kernel drivers & image base introspection | `[--format json|md]` | `total_drivers_loaded`, `graphics_drivers`, `audio_drivers` |
| `service-audit` | Interrogate SCM service states | `[--format json|md]` | `total_services_enumerated`, `running_services_count` |
| `dmp-inspect` | Multi-stream MiniDump & AV analysis | `[--file <f>] [--scan] [--format json|md]` | `status`, `system_info`, `exception_info`, `access_violation_details` |
| `etw-audit` | Audit ETW sessions & providers | `[--session <s>] [--format json|md]` | `standard_sessions_probed`, `active_sessions`, `providers` |
| `file-locks` | Detect processes holding file locks | `--file <path>` | `status`, `is_locked`, `usage_classifications`, `locking_processes` |
| `proc-modules` | Find processes hosting loaded DLL | `--module <name>` | `status`, `query_module`, `hosting_processes_count`, `hosting_processes` |
| `dev-match` | Match PnP devices with Driver Store | `[--query <name>] [--problems-only]` | `status`, `devices_audited`, `device_reports` |

---

## 5. Driving Common Vibe-Coding Workflows

### Scenario 1: User says "Why is this game/app crashing on startup?"
1. Inspect the MiniDump file:
   ```powershell
   rea-neural dmp-inspect --file "C:\path\to\crash.dmp"
   ```
2. Check for missing DLL dependencies:
   ```powershell
   rea-neural resolve-deps --binary "C:\path\to\game.exe"
   ```
3. Synthesize the complete causality dossier:
   ```powershell
   rea-neural diagnose --binary "C:\path\to\game.exe" --crash "C:\path\to\crash.dmp"
   ```

### Scenario 2: User says "This file is locked and I can't replace it."
1. Interrogate the Windows Restart Manager:
   ```powershell
   rea-neural file-locks --file "C:\path\to\locked.dll"
   ```
2. Inform the user which application (PID, Name, Service) holds the lock without forcefully killing system processes.

### Scenario 3: User says "Patch this instruction to bypass a check."
1. Create a segregated output directory:
   ```powershell
   mkdir workspace -Force
   ```
2. Surgically apply the patch to the workspace destination:
   ```powershell
   rea-neural patch-binary --file "C:\path\to\game.exe" --output ".\workspace\game_patched.exe" --offset 0x2400 --patch-hex "90 90"
   ```
3. Verify that `is_safe: true` and `pe_checksum_recalculated: true`.
