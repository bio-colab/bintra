---
name: Bug Report
about: Create an actionable bug report to help us improve Bintra
title: "[BUG] "
labels: ["bug", "triage"]
assignees: ''
---

**Summary of the Issue**
A clear and concise description of what the unexpected behavior is.

**Environment & System Specifications**
- **OS Version:** Windows 10 / Windows 11 / Windows Server (Build: `winver`)
- **Python Version:** 3.10 / 3.11 / 3.12 (`python --version`)
- **Execution Architecture:** x86-64 / WOW64 (32-bit) / ARM64
- **Bintra Commit or Tag:** (e.g. `v1.0.0` or git hash)

**Target Binary / Input Data**
- Binary Format: PE32 / PE32+ / DLL / Safetensors / Machine Hex
- Target Compiler (if known): MSVC / Clang-cl / MinGW / Rustc
- Obfuscation Type (if applicable): CFF / Opaque Predicates / Virtualized

**Steps to Reproduce**
1. Command executed:
   ```powershell
   python src/cli.py <command> <arguments>
   ```
2. Input payload or synthetic test snippet:
   ```
   [paste hex sequence or synthetic reproduction snippet here]
   ```
3. Error observed / traceback:
   ```
   [paste JSON error output or stack trace here]
   ```

**Expected Behavior**
A clear description of what you expected to happen according to Bintra's deterministic or semantic invariants.

**Additional Context / Anonymity Notice**
*Reminder: Please do NOT include proprietary game titles, closed-source commercial product names, or private binary paths in this issue.*
