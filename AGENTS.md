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
Exposes 13 type-safe tools (`rea_inspect_binary`, `rea_deobfuscate_binary`, `rea_match_functions`, `rea_patch_binary`, `rea_dump_bytes`, `rea_scan_hybrid`, `rea_sensory_audit`, `rea_match_pcode`, `rea_deobfuscate_pcode`, `rea_ghidra_analyze`, `rea_ghidra_headless`, `rea_wsp_audit`, `rea_patch_weights`).

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
