---
name: bintra-live-runtime-analysis
description: Perform strictly read-only runtime memory inspection (VAD layout, PROCESS_VM_READ value scanning, multi-level pointer path discovery, 4-byte-granularity structure dissection, and MiniDump+VAD crash root-cause analysis) using Bintra Tier-3 tools.
metadata:
  framework: bintra
  version: "1.0.0"
  tier: runtime-telemetry
---

# Bintra: Live Runtime Memory & Crash RCA Skill

Use this skill whenever an agent or engineer needs to inspect the virtual memory layout, read-only value state, pointer chains, heap object structure, or post-mortem crash register/VAD causality of a target process.

> [!IMPORTANT]
> **Strictly Read-Only Telemetry Guarantee:** Every memory tool in this skill uses passive `PROCESS_QUERY_LIMITED_INFORMATION` / `VirtualQueryEx` / `PROCESS_VM_READ` (`ReadProcessMemory`) only. Bintra contains **no** `WriteProcessMemory`, **no** `VirtualProtectEx`, and **no** code/DLL injection.

---

## 1. Platform & Honesty Contracts

- **Windows NT Hosts:** Live win32 APIs execute against permitted processes (`is_simulated: false`). Cross-process access requires matching integrity/permissions; protected/kernel processes fail closed gracefully.
- **Non-Windows Hosts (Linux / macOS CI):** Engine entry points return structured `status: "simulated"`, `is_simulated: true` (or `status: "not_applicable"`) envelopes cleanly without raising platform attribute errors.
- **No Zero-Fill Fabrication:** `VirtualMemoryInspector.read_process_memory_checked` stops at the first unreadable chunk and reports `partial_read`, `valid_bytes_read`, and `first_failed_address` instead of padding failed chunks with fabricated zeros.
- **Bounded Session State:** `ProcessMemoryScanner` tracks up to 64 active sessions (`1800s` TTL, 16-hex `session_id`) with Win32 `GetProcessTimes` PID-reuse verification.

---

## 2. Tool Matrix: MCP vs CLI

| Capability | MCP Tool | Unified CLI (`bintra`) | Core Output Keys |
|:---|:---|:---|:---|
| **VAD Space Map** | `bintra_vad_inspect` | `vad-inspect --pid <pid> [--address 0x...] [--regions]` | `status`, `is_simulated`, `architecture`, `summary`, `module_count` |
| **Read-Only Value Scan** | `bintra_memory_scan` | `mem-scan --pid <pid> --type <t> --mode <m> --value <v>` | `session_id`, `data_type`, `scan_type`, `total_candidates`, `candidates_sample` |
| **Pointer Chain Resolution** | `bintra_pointer_scan` | `pointer-scan --pid <pid> --target 0x... --max-depth 2` | `pid`, `target_address`, `max_depth_searched`, `alignment`, `heuristic`, `paths_count`, `paths` |
| **Structure Dissection** | `bintra_struct_dissect` | `dissect-struct --pid <pid> --address 0x... --size 64` | `status`, `heuristic`, `fields_count`, `fields`, `c_struct_definition`, `is_partial` |
| **Crash RCA (DMP+ASM)** | `bintra_crash_rca` | `crash-rca --dmp <file.dmp> [--binary <exe>]` | `exception_code`, `access_type`, `root_cause_classification`, `confidence`, `culprit_register` |
| **Failure Evidence Graph** | `bintra_evidence_graph` | `diagnose --binary <exe> [--crash-json <f>]` | `verdict`, `severity`, `epistemic_classification`, `evidence_graph`, `mermaid_diagram` |

---

## 3. Iterative First Scan -> Next Scan Workflow

### Modality A: MCP Stateful / Stateless Scanning
Supported `value_type` values: `int8`, `uint8`, `int16`, `uint16`, `int32`, `uint32`, `int64`, `uint64`, `float`, `double`, `bytes`, `string`.  
Supported `scan_mode` values: `EXACT_VALUE`, `BETWEEN`, `UNKNOWN_INITIAL`, `INCREASED_VALUE`, `DECREASED_VALUE`, `CHANGED_VALUE`, `UNCHANGED_VALUE`.

**First Scan:**
```json
{
  "name": "bintra_memory_scan",
  "arguments": {
    "pid": 1234,
    "value_type": "float",
    "value": "100.0",
    "scan_mode": "EXACT_VALUE",
    "alignment": 4,
    "writable_only": true,
    "max_results": 200
  }
}
```

**Next Scan (pass `session_id` returned above, or explicit `candidate_addresses`):**
```json
{
  "name": "bintra_memory_scan",
  "arguments": {
    "pid": 1234,
    "session_id": "<16-hex-session-id>",
    "scan_mode": "CHANGED_VALUE",
    "value_type": "float"
  }
}
```
> **Note:** `bytes` and `string` next-scans support `EXACT_VALUE`, `CHANGED_VALUE`, and `UNCHANGED_VALUE` modes cleanly without numeric coercion; ordinal modes (`INCREASED_VALUE`, `DECREASED_VALUE`, `BETWEEN`) are restricted to scalar numeric types.

### Modality B: CLI Iterative Scan (Workspace-Confined Session File)
```powershell
mkdir workspace -Force
bintra mem-scan --pid 1234 --type int32 --mode exact --value 42 --session-file .\workspace\scan_state.json
bintra mem-scan --pid 1234 --type int32 --mode changed --session-file .\workspace\scan_state.json
```
*(Safety Kernel enforces that `--session-file` stays inside the authorized workspace directory.)*

---

## 4. Pointer Path Resolution & Structure Dissection Caveats

1. **Pointer Scanning (`bintra_pointer_scan` / `pointer-scan`):**
   - Resolves chains up to `max_depth = 3` (`static -> heap2 -> heap1 -> target`) with configurable `alignment` (default `4`).
   - Every returned path is verified by immediate read-only pointer dereference (`"verified": true`, `"heuristic": true`), yet subsequent ASLR/heap reallocation can invalidate paths over time.
2. **Structure Dissection (`bintra_struct_dissect` / `dissect-struct`):**
   - Evaluates objects at 4-byte granularity with 64-bit pointer / `.rdata` vftable lookahead and emits per-field `size_bytes`, `confidence`, and `alternatives`.
   - Always inspect `"heuristic": true`, `"is_partial"`, `"bytes_read"` vs `"bytes_requested"`, and `"alternatives"` before treating inferred scalar types (`int32_t`, `float`, `uint64_t`) as final C types without PDB/DWARF symbols.
3. **Crash Root Cause Analysis (`bintra_crash_rca` / `crash-rca`):**
   - Cross-checks parsed MiniDump exception `operation` / `access_type`, Capstone instruction decoding, and register blame heuristics against memory spatial boundaries. Inspect `confidence` and `memory_spatial_classification` to separate high-confidence NULL dereferences (`< 0x10000`) from dynamic heap/stack faults.

## Offline MiniDump Memory & VAD Streams
- `MiniDumpParser` parses Streams 5, 9, and 16 plus module `CvRecord` (RSDS/NB10 PDB) and `VS_FIXEDFILEINFO`, enabling `read_memory_from_dump()` offline.
- `bintra process-mitigations --pid <pid>` and `bintra registry-read --hive HKLM --key <subkey>` expose mitigation and registry inspection on the CLI.
