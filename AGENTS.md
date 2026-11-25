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
Exposes **51 type-safe tools** (with MCP `annotations`), **4 MCP resources** (`resources/list`, `resources/read`), and **5 MCP workflow prompts** (`prompts/list`, `prompts/get`):
- **Core Binary, Decompilation & Neural Weights (13 Tools):** `bintra_inspect_binary`, `bintra_dump_bytes`, `bintra_deobfuscate_binary`, `bintra_match_functions`, `bintra_patch_binary`, `bintra_scan_hybrid`, `bintra_sensory_audit`, `bintra_match_pcode`, `bintra_deobfuscate_pcode`, `bintra_ghidra_analyze`, `bintra_ghidra_headless`, `bintra_wsp_audit`, `bintra_patch_weights`.
- **Windows System Intelligence, Forensics & Profiling (21 Tools):** `bintra_windows_env_audit`, `bintra_resolve_dependencies`, `bintra_inspect_crash_reports`, `bintra_correlate_failure_evidence`, `bintra_win_catalog_cmd`, `bintra_registry_audit`, `bintra_hardware_audit`, `bintra_port_audit`, `bintra_hardware_topology`, `bintra_network_audit`, `bintra_network_hardware_dissect`, `bintra_network_connections`, `bintra_driver_audit`, `bintra_service_audit`, `bintra_dmp_inspect`, `bintra_etw_audit`, `bintra_evidence_graph`, `bintra_device_driver_intelligence`, `bintra_process_resource_audit`, `bintra_profile_process`, `bintra_inspect_slack_space`.
- **Runtime Telemetry, Crash RCA & Live Ghidra Bridge (7 Tools):** `bintra_vad_inspect`, `bintra_memory_scan`, `bintra_pointer_scan`, `bintra_struct_dissect`, `bintra_crash_rca`, `bintra_etw_capture`, `bintra_ghidra_live_bridge`.
- **Deep Forensics, Difference & Triaged Evidence Fusion (10 Tools):** `bintra_python_bytecode`, `bintra_cpython_memory_forensics`, `bintra_pe_deep_forensics`, `bintra_binary_diff`, `bintra_ghidra_call_graph`, `bintra_ghidra_data_flow`, `bintra_ghidra_similar_functions`, `bintra_fuse_evidence`, `bintra_triage_binary`, `bintra_list_capabilities`.

### Modality 2: Unified CLI (`bintra`) -- Recommended for Terminal / Bash / PowerShell
```powershell
bintra <command> [options]
# Or: python -m cli <command> [options]
```
Commands produce machine-readable JSON on `stdout` and exit with code `0` on success.

> **Exception — human-oriented defaults:** the Task Manager / Device Manager / Registry Editor style commands default to Markdown (or a text tree). Always pass `--format json` when parsing their output:
> `proc-list`, `proc-search`, `proc-info`, `sys-perf`, `dev-classes`, `dev-list`, `dev-search`, `dev-info`, `reg-read` / `registry-read`, `reg-search`, `reg-import` (default `md`) and `hw-tree` (default `tree`).

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
   Unified `triage`, PE32/PE32+/ELF anatomy & ASLR/DEP/CFG mitigations, `.pdata`/RTTI/PDB deep forensics, semantic binary diffing, slack/overlay inspection (`slack-audit`), Python `.pyc` bytecode forensics (`py-bytecode`), REX-aware opaque predicates, CFF dispatcher loops, cross-arch matching (x86-64 vs ARM64), 10 Metaphorical Senses.
2. **[`bintra-safe-binary-patching`](skills/bintra-safe-binary-patching/SKILL.md):**  
   Safe byte modification, stack frame balance proprioception ($\Delta RSP/RBP$ guard), automated PE checksum recalculation, strict workspace isolation, fail-closed `AuditLogger` persistence.
3. **[`bintra-windows-troubleshooter`](skills/bintra-windows-troubleshooter/SKILL.md):**  
   Crash diagnostics (0xc0000005, `access_violation_details`), MiniDump (.dmp) & WER inspection, Restart Manager file locks, DLL/API-Set/SxS dependency resolution, COM/LPT ports, PnP topology & hardware-to-ring0 dissection, dual-view registry, Authenticode/Catalog verification (`sig-verify`/`sig-audit`), causal evidence fusion (`fuse-evidence`).
4. **[`bintra-neural-weight-security`](skills/bintra-neural-weight-security/SKILL.md):**  
   Safetensors weight auditing without execution, dual-axis row/column trojan outliers ($>4.5\sigma$), spectral effective rank, selective column direction subtraction without training, `audit_neural_weights` prompt.
5. **[`bintra-live-runtime-analysis`](skills/bintra-live-runtime-analysis/SKILL.md):**  
   Passive VAD layout (`VirtualQueryEx`), read-only `PROCESS_VM_READ` First/Next scans (`session_id`, zero-fill-free reads), depth 1-3 pointer path discovery, 4-byte-granularity struct dissection, longitudinal `proc-profile` leak diagnosis, CPython memory forensics (`py-mem-inspect`), Crash RCA.
6. **[`bintra-etw-telemetry`](skills/bintra-etw-telemetry/SKILL.md):**  
   Native `OpenTraceW`/`ProcessTrace` ETW consumption (elevated), `WEVTAPI` Event Log + Toolhelp32 `IMAGE_LOAD` fallback, explicit source provenance, strict PID filtering, temporal crash correlation.
7. **[`bintra-ghidra-integration`](skills/bintra-ghidra-integration/SKILL.md):**  
   64-D High P-Code IR matching, headless automation, authenticated localhost JSON-RPC queue+poll bridge (`cap.tempdir.marker.write`, explicit `rva`/`va` resolution).

---

## 3. Critical Rules for AI Agents on Windows (Safety Kernel)

1. **Target Immutability & Workspace Confinement:**  
   Never modify source binaries in-place. Passing `file_path == output_path` or writing inside the target's original directory (or any sub-folder of it) is strictly blocked with `TargetMutationError`. Always write outputs to an isolated `./workspace/` directory.
   On the **CLI**, an explicit write destination (`--output`, `--session-file`, `--to-sqlite`) designates its parent folder as the workspace when `--workspace` is not given, so `--output .\workspace\x.exe` works out of the box; filesystem roots, the user-home root, Windows system folders and target folders are still refused. The **MCP** server never infers a workspace from an output path.
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
| `ghidra-plan` | Generate Ghidra database mutation plan | `--address <addr> --name <name> [--return-type void] [--comment <txt>]` | Target address, recovered symbol, signature & comment plan |
| `ghidra-analyze`| Batch-analyze/query Ghidra P-Code export | `--input <export.json\|.jsonl\|.db> [--output <plan.json>] [--to-sqlite <db>] [--query <q>] [--opcode <op>] [--xref <sym>] [--function <fn>] [--sensitive-only] [--profile] [--limit 50]` | `analyzed_functions`, `rename_actions`, `comment_actions`, `summary` |
| `ghidra-headless`| Run Ghidra headless deobfuscation | `--binary <path> [--ghidra-path <dir>] [--project-dir <dir>] [--post-script BintraGhidraBridge.java] [--apply] [--timeout 300] [--max-cpu <n>] [--keep-project]` | `exit_code`, `is_timeout`, `script_error_detected`, `analyzed_functions_count` |
| `wsp-audit` | Audit embedded weights | `--model <model.safetensors> [--tensor <name>]` | `primary_tensor`, `effective_rank_analysis`, `surgical_amenability`, `zero_eval_security_audit` |
| `patch-weights` | Column direction subtraction | `--source <in> --output <out> --tensor <t> [--operation column_direction_subtract] [--num-columns 64]` | `output_path`, `output_sha256`, `patched_tensor_names`, `metrics` |
| `subspace` | SVD / sparse weight subspace extraction | `--model <m> --tensor <t> [--mode svd_modes\|sparse_extremes\|coordinate_slice] [--top-k 8]` | Extracted singular modes / subspace coordinates |
| `decompile` | Decompile attention/MLP/LN weight circuit | `--model <m> --tensor <t> [--layer 0] [--head 0] [--num-heads 16] [--circuit-type <c>]` *(alias: `decompile-circuit`)* | Reconstructed pseudocode circuit representation |
| `diff-weights` | Compare baseline vs patched tensors | `--baseline <orig> --patched <new> --tensor <t>` | Frobenius relative shift & safety bound report |
| `probe-trace` | Seeded spectral SVD operator trace | `--model <m> --prompt "<text>" [--max-tokens 32]` | Layer-wise operator trace telemetry |
| `verify-behavior`| Verify weight equilibrium & Lipschitz bound | `--baseline <orig> --patched <new> [--tolerance 0.005]` | `is_equilibrium_preserved`, `max_frobenius_relative_shift` |
| `win-audit` | Profile host OS, graphics, security | `[--binary <path>] [--format json\|md]` | `os`, `devices`, `security` |
| `resolve-deps` | Safe DLL search order & exports audit | `--binary <path> [--app-dir <dir>] [--format json\|md]` | `verdict`, `loader_mode`, `resolved_dlls`, `missing_dlls` |
| `wer-inspect` | Scan WER archives & Event Log 1000 | `[--binary <name>] [--format json\|md]` | `wer_reports`, `event_log_errors`, `minidumps` |
| `diagnose` | Correlate OS, crash & PE into Dossier | `--binary <path> [--crash-json <f.json>] [--ghidra-json <f.json>] [--format json\|md]` | `verdict`, `severity`, `epistemic_classification`, `root_cause_summary`, `binary_mapping` |
| `evidence-graph`| Directed causality EvidenceGraph | `--target <path> [--format json\|mermaid]` | Formal `evidence_graph` / Mermaid diagram |
| `fuse-evidence` | Fuse PE, Crash RCA & Ghidra with quarantine | `[--binary <exe>] [--dmp <dmp>] [--ghidra-json <exp>] [--function <fn>]` | Provenance-verified fused `evidence_graph` |
| `win-cmd` | Execute read-only command from catalog | `[list \| <command_id>] [--format json\|md]` | `status`, `command_id`, `duration_ms` / `error` |
| `process-mitigations` | Inspect target PID security mitigations | `--pid <pid>` | ASLR, DEP, CFG, and exploit mitigation flags |
| `reg-audit` | Dual-view 11-domain registry audit | `[--domain <name>] [--binary <path>] [--format json\|md]` | `status`, `domains` / `domain`, `keys_inspected`, `discrepancies` |
| `reg-read` | Read registry key across 64/32/dual views | `--key <subkey> [--hive HKLM\|...] [--view dual\|64\|32\|native] [--format md\|json]` *(alias: `registry-read`)* | Registry values, subkeys & view comparison *(default `md`)* |
| `reg-search` | Deep search across registry keys & values | `--query <q> [--hive HKLM] [--root-key <k>] [--max-depth 3] [--limit 50] [--format md\|json]` | Matching keys, value names & data *(default `md`)* |
| `reg-export` | Export registry key to `.reg` format 5.00 | `--key <subkey> [--hive HKLM] [--output <file.reg>] [--recursive] [--max-depth 1] [--view 64\|32]` | Version 5.00 `.reg` export content / path |
| `reg-import` | Parse `.reg` file & audit live registry drift | `<file.reg> [--diff] [--view 64\|32] [--format md\|json]` | Parsed entries & live registry drift report *(default `md`)* |
| `hw-audit` | Inspect PnP hardware & CM_PROB_* codes | `[--problems-only] [--class-filter <c>] [--storage] [--format json\|md]` | `status`, `is_hardware_healthy`, `display_adapters`, `problem_devices` |
| `port-audit` | Audit COM/LPT ports & USB serial bridges | `[--port COM1] [--type all\|serial\|parallel] [--no-modem-status] [--format json\|md]` | `status`, `host_os`, `serial_ports_count`, `serial_ports`, `parallel_ports_count`, `parallel_ports` |
| `hw-tree` | Authoritative PnP bus hierarchy tree | `[--bus USB\|PCI\|ACPI] [--problems-only] [--format tree\|json\|mermaid] [--max-devices 300]` | `status`, `format`, `total_nodes`, `root_nodes_count`, `roots`, `rendered` *(default `tree`)* |
| `hw-net` | Audit live network adapters & NDIS links | `[--virtual] [--format json\|md]` | `status`, `total_adapters`, `adapters`, `epistemic_classification` |
| `hw-dissect` | Multi-layer hardware-to-ring0 dossier | `[keyword] [--format json\|md]` | DevNode-to-driver-to-KASLR dissection report |
| `net-conns` | Live TCP/UDP table with owning PIDs | `[--pid <pid>] [--format json\|md]` | `status`, `filter_pid`, `total_connections`, `ipv4_count`, `ipv6_count`, `connections` |
| `driver-audit` | Kernel drivers & image base introspection | `[--format json\|md]` | `total_drivers_loaded`, `graphics_drivers`, `audio_drivers`, `drivers_sample` |
| `service-audit` | Interrogate SCM service states | `[--format json\|md]` | `total_services_enumerated`, `running_services_count`, `stopped_services_count` |
| `sig-verify` | Authenticode & `.cat` catalog trust check | `<file> [--no-catalog] [--verify-revocation] [--format json\|md]` | `signature_present`, `is_signed`, `catalog_verified`, `found_in_catalog`, `catalog_hash_algorithm` |
| `sig-audit` | Bulk directory signature trust triage | `<dir> [--pattern *.sys] [--recursive] [--limit 100] [--format json\|md]` | Directory summary & WHQL/OEM signature classifications |
| `dmp-inspect` | Multi-stream MiniDump & AV analysis | `[--file <f>] [--scan] [--format json\|md]` | `status`, `system_info`, `exception_info` (`access_violation_details`) |
| `etw-audit` | Audit ETW sessions & TDH providers | `[--session <s>] [--providers] [--query <q>] [--provider-info <guid>] [--active-kernel] [--limit 50] [--format json\|md]` | `standard_sessions_probed`, `active_sessions`, `providers` |
| `file-locks` | Detect processes holding file locks | `--file <path>` | `status`, `is_locked`, `usage_classifications`, `locking_processes` |
| `proc-modules` | Find processes hosting loaded DLL | `--module <name>` | `status`, `query`, `hosting_processes_count`, `hosting_processes` |
| `sys-perf` | Task Manager Performance tab metrics | `[--format md\|json]` | `status`, `cpu_utilization_percent`, `memory`, `uptime`, `topology` *(default `md`)* |
| `proc-list` | Live Task Manager process table | `[--limit N] [--sort s] [--query q] [--resolve-users] [--format md\|json]` | `status`, `total_processes`, `matched_processes`, `processes` *(default `md`)* |
| `proc-search` | Search processes by keyword / PID | `--query <q> [--limit N] [--format md\|json]` | `status`, `total_processes`, `matched_processes`, `processes` *(default `md`)* |
| `proc-info` | Deep Task Manager telemetry for PID | `--pid <pid> [--format md\|json]` | `status`, `memory`, `cpu_and_timing`, `io_counters`, `security`, `mitigations` *(default `md`)* |
| `dev-classes` | Device Manager setup class hierarchy | `[--format md\|json]` | Class groups & problem tallies *(default `md`)* |
| `dev-list` | Enriched active PnP device table | `[--class-filter <c>] [--problems-only] [--limit 50] [--format md\|json]` | Active devices with driver metadata *(default `md`)* |
| `dev-search` | Search PnP devices, vendors & HW IDs | `<query> [--limit 50] [--format md\|json]` | Matched devices *(default `md`)* |
| `dev-info` | Full Device Manager properties dossier | `<device> [--format md\|json]` | General, Driver, Hardware IDs & topology *(default `md`)* |
| `dev-match` | Match PnP devices with Driver Store | `[--query <name>] [--class-filter <c>] [--problems-only]` | `status`, `devices_audited`, `driver_packages_cataloged`, `device_reports` |
| `vad-inspect` | Passive virtual memory (VAD) inspection | `--pid <pid> [--address 0x...] [--regions] [--format json\|md]` | `status`, `is_simulated`, `architecture`, `summary`, `module_count` |
| `mem-scan` | Read-only value scan (`PROCESS_VM_READ`) | `--pid <pid> --type <t> --mode <m> [--value <v>] [--session-file <f>] [--format json\|md]` | `session_id`, `data_type`, `scan_type`, `total_candidates`, `candidates_sample` |
| `pointer-scan` | Backward pointer path resolver (depth 1-3) | `--pid <pid> --target 0x... [--max-depth 1\|2\|3] [--max-offset 4096] [--format json\|md]` | `pid`, `target_address`, `max_depth_searched`, `heuristic`, `paths_count`, `paths` |
| `dissect-struct`| 4-byte-granularity struct field inference | `--pid <pid> --address 0x... [--size 64] [--name ObjectLayout] [--format json\|c\|md]` | `status`, `heuristic`, `fields_count`, `fields`, `c_struct_definition` |
| `crash-rca` | MiniDump + disassembly root-cause blame | `--dmp <file.dmp> [--binary <exe>] [--format json\|md]` | `exception_code`, `access_type`, `root_cause_classification`, `confidence`, `culprit_register`, `disassembly_window.code_source`, `image_identity` |
| `etw-capture` | Hybrid ETW / Event Log timeline capture | `--session-name <s> [--pid <pid>] [--duration 2.0] [--format json\|md]` | `session_info`, `events_count`, `event_sources`, `temporal_verdict` |
| `proc-profile` | Longitudinal process profiler & leak diagnoser | `--pid <pid> [--samples 10] [--interval 0.2] [--format json\|md]` *(aliases: `process-profile`, `leak-audit`)* | `status`, `target_pid`, `total_samples`, `behavior_classification`, `metrics_summary` (`delta_*`, `slope_*`, `gdi_handles`, `user_handles`), `samples` |
| `slack-audit` | Binary slack space & overlay forensic auditor | `--file <path> [--format json\|md]` *(aliases: `overlay-inspect`, `inspect-slack`)* | `status`, `format`, `file_size`, `has_trailing_slack`, `slack_bytes_count`, `slack_entropy`, `slack_type` |
| `triage` | Unified binary triage dossier | `--file <path> [--dmp <dmp>] [--ghidra <exp>] [--format json\|md] [--output <path>] [--skip-deobf] [--skip-sensory] [--skip-hybrid-scan]` | `status`, `file_name`, `target_sha256`, `stage_statuses`, `failed_stages`, `partial_stages`, `summary`, `evidence_graph` |
| `pe-forensics` | Offline `.pdata`, MSVC RTTI & local PDB audit | `--file <path> [--pdb <path.pdb>] [--limit 500]` | `status`, `file`, `sha256`, `architecture`, `pdata_functions`, `msvc_rtti`, `pdb_correlation`, `slack_and_overlay` |
| `diff-binaries` | Semantic diff of PEs or Ghidra exports | `--baseline <a.bin> --target <b.bin> [--mode pe\|ghidra_export]` | WL-CFG + P-Code cosine + API/String anchor similarity diff |
| `py-bytecode` | `.pyc`/`.py`/PyInstaller bytecode disassembly | `--file <path> [--compare-with <p2>] [--limit 50] [--threshold 15]` *(alias: `py-dissect`)* | `status`, `file`, `sha256`, `code_objects_analyzed`, `total_basic_blocks`, `functions` |
| `py-mem-inspect`| Live CPython object inspection (`PROCESS_VM_READ`) | `--pid <pid> --address 0x... [--type pyobject\|pydict\|pyascii\|pylong]` | Live decoded CPython object telemetry |
| `ghidra-callgraph`| Offline Ghidra caller/callee & API reachability | `--input <export.json\|.jsonl\|.db> [--function <name>] [--max-depth 4]` | Call graph edges, `CALLIND` sites, XREFs & sensitive API paths |
| `ghidra-dataflow`| Intra-procedural High P-Code SSA slice | `--input <export.json\|.jsonl\|.db> --function <name> [--var <v>]` | Backward/forward SSA slices & Decompiler C correlation |
| `ghidra-similar` | P-Code behavioral similar-function search | `--input <export> [--function <name>\|--pcode-file <f.json>] [--threshold 0.75] [--limit 20] [--min-pcode-ops 1] [--format json\|md]` | `status`, `indexed_functions`, `matches` |
| `ghidra-bridge` | Authenticated localhost Ghidra JSON-RPC | `--start\|--daemon\|--status\|--stop\|--annotate-* [--no-temp-marker]` | `is_running`, `port`, `ghidra_client_connected`, `queued_commands` |
| `capabilities` | Host-aware MCP/CLI capability manifest | `[--platform all\|cross_platform\|windows_native\|ghidra_required]` | `status`, `host_os`, `total_tools`, `tools`, `recommended_workflows` |
| `mcp` | Launch JSON-RPC 2.0 stdio MCP server | `bintra mcp` *(alias: `mcp-server` / `bintra-mcp`)* | Stdio MCP JSON-RPC 2.0 server loop |
| `update` | Check or apply fast-forward git updates | `[--check \| --yes] [--branch main] [--ref <tag_or_sha>]` *(alias: `self-update`)* | Update check (`rc=2` if updates exist) / pull status |

*(Archived experimental lineage outside core v1.1 scope per `SCOPE.md`: `bintra synthesize-weights --archived-lineage ...`.)*

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

All 8 read-only Deep Reverse Engineering & Discoverability tools below (`cap.file.read`) operate **cross-platform** on static PE binaries and Ghidra exports (alongside `bintra_python_bytecode` and `bintra_cpython_memory_forensics` in Tier 4):

| MCP Tool | CLI Command | Purpose |
|:---|:---|:---|
| `bintra_triage_binary` | `bintra triage --file <bin>` | End-to-end read-only binary triage combining PE inspection, `.pdata`/RTTI/PDB deep forensics, Authenticode/Catalog signature intelligence, obfuscation triage, optional Crash RCA, optional Ghidra fusion, and `EvidenceGraph` synthesis. |
| `bintra_list_capabilities` | `bintra capabilities` | Self-describing JSON manifest of all 51 tools, environment compatibility (`cross_platform` / `windows_native` / `ghidra_required`), and workflows. |
| `bintra_pe_deep_forensics` | `bintra pe-forensics` | x64 `.pdata` `RUNTIME_FUNCTION` boundary recovery, MSVC RTTI (`TypeDescriptor`, `CompleteObjectLocator`, `vftable`), and offline local PDB/RSDS verification. |
| `bintra_binary_diff` | `bintra diff-binaries` | Semantic diffing across two PE binaries or two Ghidra exports (WL-CFG subtree hash + 64-D P-Code cosine + API/String anchor Jaccard). |
| `bintra_ghidra_call_graph` | `bintra ghidra-callgraph` | Caller/callee topology, indirect calls, XREFs, and sensitive Win32 API reachability paths. |
| `bintra_ghidra_similar_functions` | `bintra ghidra-similar` | Behavioral nearest-routine search: ranks all functions in a Ghidra export against a reference routine (in-export function or external P-code stream) via 64-D High P-Code cosine similarity. Locates clones, inlined variants, and ported logic. |
| `bintra_ghidra_data_flow` | `bintra ghidra-dataflow` | Intra-procedural High P-Code SSA def-use backward/forward slice + Decompiler C AST/local variable correlation. |
| `bintra_fuse_evidence` | `bintra fuse-evidence` | Multi-signal causal fusion of PE Deep Forensics + MiniDump Crash RCA + Ghidra Call-Graph/Data-Flow into `EvidenceGraph`. Ghidra exports are provenance-verified (SHA-256 / filename) against the target binary and quarantined on mismatch, identical to the triage orchestrator. |

### AI Agent Decision Tree
1. **First turn on an unfamiliar host:** Call `bintra_list_capabilities` (or `bintra capabilities`) to inspect which tools are `cross_platform` vs `windows_native` vs `ghidra_required`.
2. **Stripped x64 PE without PDB:** Run `bintra_inspect_binary` -> `bintra_pe_deep_forensics` (recovers `.pdata` function boundaries & MSVC RTTI classes/vtables).
3. **Deep Ghidra export or live bridge:** Run `bintra_ghidra_analyze` -> `bintra_ghidra_call_graph` -> `bintra_ghidra_data_flow` -> `bintra_fuse_evidence`.
4. **Comparing two builds/versions:** Run `bintra_binary_diff` (`mode: "pe"` or `mode: "ghidra_export"`).
