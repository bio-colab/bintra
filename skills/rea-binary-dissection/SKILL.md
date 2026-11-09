---
name: rea-binary-dissection
description: Inspect, deobfuscate, disassemble, semantically match, and perceptually audit Windows PE32/PE32+ executables (.exe, .dll) or raw machine code hex streams using REA-Neural. Use when analyzing binary anatomy, ASLR/DEP/CFG mitigations, section entropy, eliminating algebraic opaque predicates and CFF dispatcher loops, matching assembly routines across x86-64 and ARM64, or evaluating the 10 Metaphorical Senses.
metadata:
  framework: rea-neural
  version: "7.4.0"
  tier: binary-analysis
---

# REA-Neural: Binary Dissection & Deobfuscation Skill

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
| **PE Anatomy & Mitigations** | `rea_inspect_binary` | `file_path`: string | Extracts PE32/PE32+ architecture, ASLR, DEP, CFG, sections, Shannon entropy. |
| **Opaque Predicates & CFF** | `rea_deobfuscate_binary` | `code_hex`: string, `file_path` (opt), `offset` (opt) | Identifies dead conditional jumps, algebraic zeroing, and recovers canonical control flow. |
| **Raw Bytes at Offset** | `rea_dump_bytes` | `file_path`: string, `offset`: int, `length`: int | Extracts hex preview and ASCII rendering without manual seeking. |
| **Cross-Arch Matching** | `rea_match_functions` | `func1_hex`: string, `func2_hex`: string | Vector cosine similarity matching across x86-64 and ARM64 ($>90\%$). |
| **P-Code Semantic Match** | `rea_match_pcode` | `func1_pcode`: array, `func2_pcode`: array | Architecture- and compiler-invariant High P-Code IR matching ($>95\%$). |
| **Embedded AI Asset Scan** | `rea_scan_hybrid` | `file_path`: string | Scans PE `.rsrc`/`.rodata` for embedded DirectML, ONNX, GGUF, or Safetensors. |
| **10 Senses Cybernetic Audit**| `rea_sensory_audit` | `file_path`: string (or `code_hex`: string) | Holistic 10-Sense evaluation returning unified telemetry. |

### Modality B: Unified CLI (`rea-neural`)

```powershell
# 1. Deep PE Inspection
rea-neural inspect --file "C:\path\to\target.exe"

# 2. Machine Code Deobfuscation
rea-neural deobfuscate --hex "55 48 89 e5 31 c0 74 05 e8 11 22 33 44 90 c3"

# 3. Cross-Architecture Function Semantic Matching
rea-neural match `
  --func1 "55 48 89 e5 89 7d fc 8b 45 fc 83 c0 01 5d c3" `
  --func2 "55 48 89 e5 8d 47 01 5d c3"

# 4. Embedded AI Container Scan
rea-neural scan-hybrid --file "C:\path\to\game.exe"

# 5. Holistic 10-Sense Evaluation
rea-neural sense --file "C:\path\to\target.exe" --hex "55 48 89 e5 5d c3"
```

---

## 4. How to Interpret Results for the User

When relaying findings to the user, translate technical telemetry into clear, actionable human insights:

1. **Shannon Byte Entropy:**
   - `< 6.5 bits/byte`: Normal uncompressed compiled native code.
   - `6.5 - 7.2 bits/byte`: Dense compressed data, embedded models, or light obfuscation.
   - `> 7.5 bits/byte`: Packed binary (UPX, Themida), encrypted payload, or cryptographic assets.
2. **Opaque Predicates vs False Positives:**
   - REA-Neural's deobfuscator is REX-aware. A pattern like `xor r8, r8; jz` is flagged as zeroing, whereas `xor r8, rax; jz` is recognized as legitimate computation and NOT flagged.
3. **Sensory Cortex Efficiency:**
   - Note to Agent: `overall_sensory_efficiency` (e.g. 0.958) is a **static capability readiness indicator** of the 10 senses, NOT a measured machine learning accuracy. Always read the detailed `telemetry` dictionary under each sense for real measured values!
