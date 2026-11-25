---
name: bintra-binary-dissection
description: Inspect, deobfuscate, disassemble, semantically match, and perceptually audit Windows PE32/PE32+ executables (.exe, .dll) or raw machine code hex streams using Bintra. Use when analyzing binary anatomy, ASLR/DEP/CFG mitigations, section entropy, eliminating algebraic opaque predicates and CFF dispatcher loops, matching assembly routines across x86-64 and ARM64, or evaluating the 10 Metaphorical Senses.
metadata:
  framework: bintra
  version: "1.1.0"
  tier: binary-analysis
---

# Bintra: Binary Dissection & Deobfuscation Skill

Use this skill whenever an autonomous agent or user needs to analyze, deobfuscate, disassemble, or semantically compare compiled Windows executables (`.exe`, `.dll`) or raw machine code byte sequences without guessing or writing ad-hoc disassembly scripts.

---

## 1. When to Activate This Skill

Activate this skill when the user asks any of the following in natural language:
- *"Analyze this executable / DLL (`app.exe`, `payload.dll`)."*
- *"What compiler mitigations (ASLR, DEP, CFG) are enabled in this binary?"*
- *"Deobfuscate this machine code or function."*
- *"Check if this code contains opaque predicates or control flow flattening (CFF)."*
- *"Compare these two functions across compilers or architectures (x86-64 vs ARM64) to see if they do the same thing."*
- *"Scan this binary for embedded AI assets (ONNX, DirectML, GGUF)."*
- *"Run a sensory health audit / 10 Senses evaluation on this code."*

---

## 2. Operational Decision Tree

```mermaid
flowchart TD
    Start[User Query] --> InputType{Input Type?}
    
    InputType -->|PE File (.exe / .dll)| FileWorkflow
    InputType -->|Machine Code Hex| HexWorkflow
    InputType -->|Function Comparison| MatchWorkflow
    
    subgraph FileWorkflow[PE Binary Workflow]
        F1[Inspect PE Headers & Mitigations] --> F2[Run 10-Sense Holistic Audit]
        F2 --> F3[Scan for Embedded AI Runtimes]
    end
    
    subgraph HexWorkflow[Deobfuscation Workflow]
        H1[Detect REX-Aware Opaque Predicates] --> H2[Prune CFF Dispatcher Loops]
        H2 --> H3[Extract Clean Canonical Stream]
    end
    
    subgraph MatchWorkflow[Semantic Matching Workflow]
        M1{Has Ghidra P-Code?}
        M1 -->|Yes| M2[High P-Code IR Embedding Matching]
        M1 -->|No / Raw Assembly| M3[Continuous Behavioral Vector Matching]
    end
```

---

## 3. Tool Invocations: MCP vs CLI

### Modality A: Agent MCP Tools (Preferred when connected to AI harness)

| Target Task | Tool Name | Parameters | Purpose |
|:---|:---|:---|:---|
| **Unified Binary Triage** | `bintra_triage_binary` | `file_path`: string, `dmp_path` / `ghidra_export_path` / `function_name` / `include_deobfuscation` / `include_sensory` / `include_hybrid_scan` / `max_exports` / `forensics_limit` (opt) | Multi-stage triage combining PE anatomy, deep forensics, signatures, obfuscation, 10 Senses, AI scan, slack space, and optional crash/Ghidra fusion. |
| **PE Anatomy & Mitigations** | `bintra_inspect_binary` | `file_path`: string, `max_exports`: int (opt) | Extracts PE32/PE32+/ELF architecture, ASLR, DEP, CFG, sections, Shannon entropy, Rich/TLS/Load Config/Authenticode/CLR metadata. |
| **PE Deep Forensics** | `bintra_pe_deep_forensics` | `file_path`: string, `pdb_path` / `limit` (opt) | Offline recovery of x64 `.pdata` `RUNTIME_FUNCTION` + `UNWIND_INFO`, MSVC RTTI vftables, and local PDB/RSDS verification. |
| **Semantic Binary Diffing** | `bintra_binary_diff` | `baseline_path`: string, `target_path`: string, `mode`: `"pe"` \| `"ghidra_export"` | Diffs two PE binaries or Ghidra exports via WL-CFG subtree hashing, 64-D P-Code cosine, and API/String anchor Jaccard. |
| **Slack & Overlay Audit** | `bintra_inspect_slack_space` | `file_path`: string | Detects PE overlays, truncated headers, MFC NUL padding, and trailing unmapped slack across `.exe`/`.dll`/`.rtf`/`.xml`/`.json`. |
| **Opaque Predicates & CFF** | `bintra_deobfuscate_binary` | `code_hex`: string, `file_path` / `offset` / `length` (opt) | Identifies dead conditional jumps, algebraic zeroing, and recovers canonical control flow. |
| **Raw Bytes at Offset** | `bintra_dump_bytes` | `file_path`: string, `offset`: int\|hex-str, `length`: int (opt, default 64) | Extracts hex preview and ASCII rendering without manual seeking. |
| **Cross-Arch Matching** | `bintra_match_functions` | `func1_hex`: string, `func2_hex`: string | 16-D opcode/transition histogram matching across x86-64 and ARM64 (heuristic threshold $\ge 0.90$ with scale guard $\ge 0.60$). |
| **P-Code Semantic Match** | `bintra_match_pcode` | `func1_pcode`: array, `func2_pcode`: array | 64-D Ghidra High P-Code IR cosine matching (`MATCH_THRESHOLD = 0.90`; empirical accuracy is tracked via repeatable evaluation benchmarks rather than fixed source claims). |
| **P-Code Deobfuscation** | `bintra_deobfuscate_pcode` | `pcode_ops`: array | Prunes algebraic opaque predicates and dispatcher noise directly from Ghidra High P-Code SSA streams. |
| **Python Bytecode Forensics** | `bintra_python_bytecode` | `file_path`: string, `compare_with` / `limit` / `complexity_threshold` (opt) | Disassembles `.pyc`/`.py`/PyInstaller payloads, flags complexity hotspots, and compares versions. |
| **Embedded AI Asset Scan** | `bintra_scan_hybrid` | `file_path`: string | Scans PE `.rsrc`/`.rodata` for embedded DirectML, ONNX, GGUF, or Safetensors. |
| **10 Senses Cybernetic Audit**| `bintra_sensory_audit` | `file_path`: string (or `code_hex`: string) | Holistic 10-Sense evaluation returning unified telemetry. |
| **Host Capability Discovery** | `bintra_list_capabilities` | `platform_filter`: `"all"` \| `"cross_platform"` \| `"windows_native"` \| `"ghidra_required"` | Returns structured capability manifest (`outputSchema`) across all 51 Bintra MCP tools. |

### Modality B: Unified CLI (`bintra`)

```powershell
# 1. End-to-End Unified Triage (JSON or deterministic Markdown report)
bintra triage --file "C:\path\to\target.exe" [--dmp .\crash.dmp] [--ghidra .\export.json] [--format md --output .\workspace\triage.md]

# 2. Deep PE Inspection & Raw Hex Dump
bintra inspect --file "C:\path\to\target.exe"
bintra dump --file "C:\path\to\target.exe" --offset 0x400 --length 64

# 3. Deep Static PE Forensics, Semantic Diffing & Slack/Overlay Audit
bintra pe-forensics --file "C:\path\to\target.exe" [--pdb .\target.pdb] [--limit 500]
bintra diff-binaries --baseline "C:\path\v1.exe" --target "C:\path\v2.exe" --mode pe
bintra slack-audit --file "C:\path\to\target.exe" --format json

# 4. Machine Code & P-Code Deobfuscation / Matching
bintra deobfuscate --hex "55 48 89 e5 31 c0 74 05 e8 11 22 33 44 90 c3"
bintra deobfuscate-pcode --file .\pcode_ops.json
bintra match `
  --func1 "55 48 89 e5 89 7d fc 8b 45 fc 83 c0 01 5d c3" `
  --func2 "55 48 89 e5 8d 47 01 5d c3"

# 5. Python Bytecode, Embedded AI Scan & 10-Sense Evaluation
bintra py-bytecode --file .\payload.pyc [--compare-with .\old.pyc] [--limit 50] [--threshold 15]
bintra scan-hybrid --file "C:\path\to\target.exe"
bintra sense --file "C:\path\to\target.exe" --hex "55 48 89 e5 5d c3"
```
*(CLI commands exit non-zero (`1`) when payload inspection reports errors or blocks via the Safety Kernel.)*

---

## 4. How to Interpret Results for the User

When relaying findings to the user, translate technical telemetry into clear, actionable human insights:

1. **Shannon Byte Entropy:**
   - `< 6.5 bits/byte`: Normal uncompressed compiled native code.
   - `6.5 - 7.2 bits/byte`: Dense compressed data, embedded models, or light obfuscation.
   - `> 7.5 bits/byte`: Packed binary (UPX, Themida), encrypted payload, or cryptographic assets.
2. **Opaque Predicates vs False Positives:**
   - Bintra's deobfuscator is REX-aware. A pattern like `xor r8, r8; jz` is flagged as zeroing, whereas `xor r8, rax; jz` is recognized as legitimate computation and NOT flagged.
3. **Sensory Cortex Efficiency:**
   - Note to Agent: `overall_sensory_efficiency` (e.g. 0.958) is a **static capability readiness indicator** of the 10 senses, NOT a measured machine learning accuracy. Always read the detailed `telemetry` dictionary under each sense for real measured values!

## Extended PE/COFF Directories
- `BinaryFormatInspector.inspect()` surfaces `rich_header`, `tls`, `load_config`, `security_authenticode`, `clr_metadata`, and `sections_truncated`.
- `SemanticFunctionMatcher.match_batch()` provides vectorized $N \times M$ cosine similarity across x86-64 and ARM64.

---

## Deep Static PE Forensics & Binary Diffing (v1.1)
- `bintra_pe_deep_forensics` (`bintra pe-forensics --file <target.exe>`): Strictly read-only recovery of x64 `.pdata` `RUNTIME_FUNCTION` + `UNWIND_INFO` boundaries, MSVC RTTI (`TypeDescriptor`, `CompleteObjectLocator`, `vftable`), and offline local PDB/RSDS verification (zero network).
- `bintra_binary_diff` (`bintra diff-binaries --baseline <a.exe> --target <b.exe>`): Compares PE binaries or Ghidra JSON exports using 2-round Weisfeiler-Lehman CFG subtree hashing + 64-D P-Code cosine + API/String anchor Jaccard.
