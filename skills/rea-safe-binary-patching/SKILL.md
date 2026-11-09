---
name: rea-safe-binary-patching
description: Surgically patch compiled Windows executables (.exe, .dll) and machine code with stack frame balance proprioception (RSP/RBP guard), automated PE checksum recalculation, and strict workspace isolation. Use when modifying binary instructions, NOPing out calls, bypassing checks, or applying hotfixes without corrupting the target or violating Windows security policies.
metadata:
  framework: rea-neural
  version: "7.4.0"
  tier: binary-mutation
---

# REA-Neural: Safe Surgical Binary Patching Skill

Use this skill whenever an AI coding agent or user needs to modify bytes, NOP out instructions, bypass conditional jumps, or inject hotfixes into a Windows executable (`.exe`, `.dll`) on disk.

---

## 1. Absolute Guardrails for AI Agents (MUST FOLLOW)

The REA-Neural **Safety Kernel & Execution Guard** strictly enforces complete mediation and fail-closed security. Any violation will instantly abort the operation:

> [!CAUTION]
> **RULE 1: TARGET IMMUTABILITY (NO IN-PLACE PATCHING)**  
> Never attempt to modify or overwrite the source binary in-place. Passing `file_path == output_path` will immediately trigger `TargetMutationError(TARGET_WRITE_FORBIDDEN)`.

> [!WARNING]
> **RULE 2: STRICT WORKSPACE CONFINEMENT**  
> Output binaries MUST be written to an isolated, dedicated workspace directory (e.g. `./workspace/target_patched.exe` or `C:\path\to\workspace\patched.exe`). Writing inside the target's original directory triggers `TARGET_DIRECTORY_WRITE_FORBIDDEN`.

> [!IMPORTANT]
> **RULE 3: NOCICEPTIVE STACK BALANCE REFLEX**  
> REA-Neural tracks stack frame alignment ($\Delta RSP / RBP$). If your patch injects stack-altering instructions (like `sub rsp, 0x28` or unaligned `push`/`pop`) over neutral code, the engine's **Nociceptive Reflex** will block execution with `RuntimeError: Stack frame balance violated` to protect the host OS from silent corruption.

---

## 2. Operational Decision Tree

```mermaid
flowchart TD
    Start[User requests patch/hotfix] --> Step1[1. Locate RVA & File Offset]
    Step1 --> Step2[2. Verify Target Section is Executable e.g. .text]
    Step2 --> Step3[3. Compute Clean Patch Hex e.g. 90 90 for NOP]
    Step3 --> Step4[4. Create Dedicated Workspace Directory]
    Step4 --> Step5[5. Invoke SurgicalBinaryPatcher / rea_patch_binary]
    Step5 --> Step6{Nociceptive Reflex Verdict?}
    Step6 -->|Stack Frame Safe| Success[6. Automatic PE Checksum Recalculated & Written]
    Step6 -->|Stack Imbalance Detected| Rollback[Blocked by Guard! Inspect delta_rsp or assert force]
```

---

## 3. Tool Invocations: MCP vs CLI

### Modality A: Agent MCP Tool

Use the `rea_patch_binary` tool:

```json
{
  "name": "rea_patch_binary",
  "arguments": {
    "file_path": "C:\\path\\to\\original\\game.exe",
    "output_path": "C:\\path\\to\\workspace\\game_patched.exe",
    "offset": 4160,
    "patch_hex": "90 90 90 90 90",
    "force": false
  }
}
```

**Key Parameters:**
- `file_path` (string, required): Absolute path to the immutable source executable.
- `output_path` (string, required): Output destination path in an authorized workspace. Must NOT be inside the source directory.
- `offset` (integer, required): 0-based file byte offset where the patch begins.
- `patch_hex` (string, required): Hex string of bytes to write (e.g. `"90 90"` for two NOP instructions, `"EB 05"` for short relative JMP).
- `force` (boolean, optional): If `true`, overrides the nociceptive stack frame warning.

### Modality B: Unified CLI (`rea-neural`)

```powershell
# 1. Create a segregated workspace folder
mkdir workspace -Force

# 2. Surgically patch an instruction (e.g., NOP out a conditional jump at offset 0x1A40)
rea-neural patch-binary `
  --file "C:\path\to\target.exe" `
  --output ".\workspace\target_patched.exe" `
  --offset 0x1A40 `
  --patch-hex "90 90"

# 3. Verify the patched binary integrity
rea-neural inspect --file ".\workspace\target_patched.exe"
```

---

## 4. Common Assembly Patch Patterns

When vibe-coding patches for the user, use these canonical, stack-safe patterns:

| Desired Behavior | Original Machine Code | Safe Replacement Patch | Explanation |
|:---|:---|:---|:---|
| **Disable Check / Function (NOP)** | `74 08` (`jz +8`) or `E8 ...` (`call`) | `90 90` (or matching NOP count) | Neutralizes the instruction; preserves surrounding code. |
| **Always Jump (Force Branch)** | `74 12` (`jz +18`) | `EB 12` (`jmp +18`) | Changes conditional jump to an unconditional short jump. |
| **Never Jump (Skip Branch)** | `75 0A` (`jnz +10`) | `90 90` | Replaces the 2-byte branch with two NOPs. |
| **Return Early (Void / Success)** | `55 48 89 E5 ...` | `31 C0 C3` (`xor eax, eax; ret`) | Returns 0 (`SUCCESS`) immediately without modifying caller stack frame. |

---

## 5. Post-Patch Verification Checklist

After the patch completes, confirm to the user:
1. `is_stack_safe`: True (stack balance maintained).
2. `pe_checksum_recalculated`: True (Windows loader will accept the modified PE header without triggering corruption warnings).
3. `original_file_intact`: True (baseline SHA-256 baseline untouched on disk).
4. `output_location`: Absolute path inside the designated workspace.
