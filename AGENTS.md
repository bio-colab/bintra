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
      "command": "python",
      "args": ["<path-to-repo>/src/mcp_server.py"]
    }
  }
}
```
Exposes 22 type-safe tools: core binary analysis (`rea_inspect_binary`, `rea_dump_bytes`, `rea_deobfuscate_binary`, `rea_match_functions`, `rea_patch_binary`, `rea_scan_hybrid`, `rea_sensory_audit`), Ghidra P-Code integration (`rea_match_pcode`, `rea_deobfuscate_pcode`, `rea_ghidra_analyze`, `rea_ghidra_headless`), Windows intelligence & diagnostics (`rea_windows_env_audit`, `rea_resolve_dependencies`, `rea_inspect_crash_reports`, `rea_correlate_failure_evidence`, `rea_win_catalog_cmd`, `rea_registry_audit`), Native hardware and system introspection (`rea_hardware_audit`, `rea_driver_audit`, `rea_service_audit`), and embedded weights security (`rea_wsp_audit`, `rea_patch_weights`).

### Modality 2: Unified CLI (`src/cli.py`) -- Recommended for Terminal / Bash / PowerShell
```powershell
python src/cli.py <command> [options]
```
All commands produce machine-readable JSON on `stdout` and exit with code `0` on success.

### Modality 3: Pure Python API -- Recommended for In-Process Scripts
```python
import sys
sys.path.insert(0, r"D:\rea-neural\src")
from binary_neural_engine import BinaryFormatInspector, ContinuousDeobfuscator, SurgicalBinaryPatcher, SensoryCortex
from ghidra_pcode_vectorizer import GhidraAnnotationPlanner, PcodeDeobfuscator
from windows_intelligence import (
    WindowsOSProfiler, WindowsDependencyResolver, WindowsDeviceInspector,
    WindowsSecurityInspector, WindowsCrashAnalyzer, DiagnosticEvidenceCorrelator,
    CommandCatalog, CommandExecutor, PowerShellExecutor,
    RegistryCatalog, WindowsRegistryReader, WindowsRegistryAnalyzer,
    NativeDeviceInspector, KernelDriverInspector, ServiceManagerInspector, ProcessMitigationInspector
)
```

---

## 2. Critical Rules for AI Agents on Windows

1. **Avoid Inline JSON Quoting in PowerShell:**  
   Windows PowerShell strips unescaped double quotes from inline arguments like `'[{"opcode": "INT_ADD"}]'`.  
   *Best Practice:* Always write complex JSON payloads to a temporary file (`temp_pcode.json`) and pass `--file temp_pcode.json` or `--input temp_pcode.json`.
2. **Deterministic Machine Output:**  
   Parse `stdout` directly with `json.loads(output)`. Stderr contains telemetry logs or scope warnings that should not interfere with JSON parsing.
3. **Atomic Writes & Rollbacks:**  
   `patch-binary` uses atomic writes via temporary files and `os.replace`. If a patch fails the nociceptive stack frame balance check, it returns a safe rejection diagnostic without corrupting the target binary.
4. **Scope Discipline:**  
   Auditing embedded weights to secure or understand a Windows binary is legitimate reverse engineering. Building, merging, or training standalone models from scratch is out of scope (see `SCOPE.md`).

---

## 3. Command Reference & Payload Matrix

| Command | Purpose | Input Flags | Expected Output JSON Keys |
|:---|:---|:---|:---|
| `inspect` | PE32/PE32+ deep inspection (headers, imports, exports) | `--file <path>` | `format`, `mitigations`, `imports`, `exports`, `sections` |
| `dump` | Extract raw bytes & hex preview at offset/RVA | `--file <path> --offset <N> [--length <L>]` | `file`, `offset`, `length`, `hex`, `ascii_preview` |
| `deobfuscate` | Prune opaque predicates & CFF | `--file <path> [--offset <N>]` or `--hex "<bytes>"` | `opaque_predicates`, `control_flow_flattening`, `pruned_hex` |
| `match` | Cross-architecture matching | `--func1 "<hex>" --func2 "<hex>"` | `cosine_similarity`, `is_semantic_match`, `confidence` |
| `patch-binary` | Surgical byte patch with RSP balance | `--file <path> --offset <N> --patch "<hex>"` | `success`, `target_offset`, `patch_length`, `pe_checksum_updated` |
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

---

## 4. Driving the Ghidra Symbiosis Loop as an Autonomous Agent

When asked to reverse engineer an obfuscated Windows executable using Ghidra:

1. **One-Command Headless Deobfuscation:**  
   Run:
   ```powershell
   python src/cli.py ghidra-headless --binary "path/to/target.exe" --apply
   ```
2. **What happens automatically:**  
   - Ghidra headless imports the binary and decompiles all functions via `DecompInterface`.
   - `ReaNeuralGhidraBridge.java` extracts High P-Code, Varnodes, and CFG topologies.
   - Invokes `cli.py ghidra-analyze` to detect algebraic opaque predicates and compute 64-D spectral embeddings.
   - With `--apply`, the script automatically commits function renames (`REA_Deob_...`) and detailed plate comments into Ghidra's Program Database in a safe transaction.
3. **Inspect the Output Plan:**  
   The agent can read the generated `mutation_plan.json` to immediately report discovered keys, bypassed license checks, or deobfuscated dispatchers to the user.


---

## 5. Windows System Intelligence & Failure Diagnostic Workflow

When an executable crashes, fails to launch, or encounters runtime access violations on Windows:

1. **Host Environment & Privilege Audit:**
   ```powershell
   python src/cli.py win-audit --binary "path/to/target.exe" --format md
   ```
   Checks real kernel version (via `ntdll.RtlGetVersion`), WOW64 emulation, AppCompatFlags registry shims, token integrity level, and directory write ACLs.

2. **Loader Dependency & Missing Exports Verification:**
   ```powershell
   python src/cli.py resolve-deps --binary "path/to/target.exe" --format md
   ```
   Simulates Safe DLL search order, resolves MinWin API-Set virtual contracts (e.g., `api-ms-win-core-*` -> `kernelbase.dll`), detects 32-bit vs 64-bit architecture mismatches, and parses up to 4096 exports from disk DLLs to identify unexported APIs (`0xC0000139`).

3. **Crash Telemetry & Event Log Inspection:**
   ```powershell
   python src/cli.py wer-inspect --binary "target.exe"
   ```
   Parses `Report.wer` archives and Application Event Log (Event ID 1000/1001) without requiring WinDbg or heavy symbols.

4. **Authoritative Failure Evidence Dossier Synthesis:**
   ```powershell
   python src/cli.py diagnose --binary "path/to/target.exe" --format md
   ```
   Cross-references runtime crash offset (`FaultOffset`), PE section layout, RVAs, and Ghidra decompilation into an actionable engineering dossier with root cause diagnosis and mitigation guidance.


5. **Live Hardware & PnP Subsystem Health Check:**
   ```powershell
   python src/cli.py hw-audit --format md
   ```
   Interrogates live PnP devices via `SetupAPI` and `CfgMgr32`, flagging device problem codes (`CM_PROB_FAILED_START`, `CM_PROB_FAILED_ADD`, Code 10, Code 43).

6. **Kernel Driver & Graphics Base Introspection:**
   ```powershell
   python src/cli.py driver-audit --format md
   ```
   Enumerates loaded kernel drivers via `PSAPI`, resolving 64-bit kernel virtual base addresses and highlighting graphics and audio drivers.

7. **Service Control Manager (SCM) Audit:**
   ```powershell
   python src/cli.py service-audit --format md
   ```
   Audits active and stopped Windows services via `Advapi32`.