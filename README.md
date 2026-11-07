# REA-Neural
### Autonomous Continuous Semantic Reverse Engineering & Binary Analysis Framework

[![Windows Native CI](https://github.com/bio-colab/rea-neural/actions/workflows/windows-ci.yml/badge.svg)](https://github.com/bio-colab/rea-neural/actions/workflows/windows-ci.yml)
[![Platform](https://img.shields.io/badge/Platform-Windows_10_%2F_11_%2F_Server-blue.svg?logo=windows)](https://www.microsoft.com/windows)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue.svg?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)
[![Continuous Semantics](https://img.shields.io/badge/Methodology-Continuous_Semantics-purple.svg)](#)

`REA-Neural` is an agent-native, next-generation reverse engineering framework tailored for **Windows compiled software executables and libraries** (`.exe`, `.dll`, PE32, PE32+). 

Forked from **REA (Reverse Engineer Anything)** and augmented with continuous representation theory from recent MIT CSAIL research (*"Sparks of Weight-Space Programming"*, Takehi, Teoh, Zhang, Khattab, 2026), `REA-Neural` overcomes the core vulnerabilities of traditional symbolic reverse engineering engines (Ghidra, Hopper, IDA Pro) when analyzing obfuscated native code on Windows.

---

## Key Breakthroughs for Windows Binaries

### 1. Continuous Semantic Deobfuscation
Complex code protection techniques—such as Control Flow Flattening, Opaque Predicates, and instruction virtualization—artificially multiply basic blocks and obfuscate control graphs. `REA-Neural` models state transitions as continuous vector trajectories, allowing it to:
- Instantly identify algebraic opaque predicates (e.g. dead conditional jumps following register zeroing).
- Prune dummy dispatcher loops and recover canonical linear control flow graphs.

### 2. Cross-Architecture & Cross-Compiler Semantic Matching
Traditional function matching algorithms rely on exact opcode hashes or structural CFG graphs, which fail when binaries are recompiled across architectures (x86-64 vs. ARM64) or optimization levels (`-O0` vs. `-O3`). `REA-Neural` computes continuous behavioral vector embeddings of assembly routines, achieving $>90\%$ cosine similarity matching on stripped binaries.

### 3. Goal-Driven Surgical Binary Patching
Manual byte patching is notoriously error-prone, frequently resulting in stack imbalance (`RSP`/`RBP` misalignment) or PE checksum violations. `REA-Neural` computes minimal perturbation vectors ($\Delta \text{State} \le \epsilon$), automatically recalculates PE integrity checksums, and guarantees stack frame stability.

### 4. Hybrid Native-Neural Application Dissection
Modern Windows applications (games, anti-cheat, endpoint security clients, media suites) embed neural inference logic (ONNX, TFLite, GGUF, DirectML) directly into PE sections (`.rsrc`, `.rodata`). `REA-Neural` scans native binaries to expose these embedded logic cores and decompile the boundary between native Win32 API calls and embedded decision matrices.

---

## Repository Structure

```
D:/rea-neural/
├── .github/
│   ├── workflows/
│   │   └── windows-ci.yml         # Automated Windows-only CI/CD pipeline
│   └── ISSUE_TEMPLATE/            # Bug report and feature request templates
├── LICENSE                        # Apache 2.0 License
├── CONTRIBUTING.md                # Development and contribution guide
├── SECURITY.md                    # Vulnerability reporting protocol
├── pyproject.toml                 # Standard packaging metadata
├── requirements.txt               # Lightweight runtime dependencies
├── README.md                      # Comprehensive guide
├── src/
│   ├── cli.py                     # Unified CLI entry point
│   ├── binary_neural_engine.py    # PE binary analysis, deobfuscator & patcher
│   ├── rea_neural_engine.py       # Weight-space SVD & circuit decompiler
│   └── sensory_cortex.py          # 10 Metaphorical Senses evaluation cortex
├── skills/
│   └── reverse-engineer-anything/ # Agent-native skill specification
│       ├── SKILL.md               # Main skill contract
│       └── references/            # In-depth technical reference manuals
├── schemas/                       # Agent MCP tool definitions
├── tests/                         # Automated unit & Windows PE regression test suite
└── docs/                          # Architecture & mathematical foundation
```

---

## Quickstart on Windows

### 1. Installation
```powershell
# Clone the repository
git clone https://github.com/bio-colab/rea-neural.git
cd rea-neural

# Install dependencies
pip install -r requirements.txt
```

### 2. CLI Usage Examples
```powershell
# Inspect a native Windows PE executable header and section mapping
python src/cli.py inspect --file "C:\Windows\System32\notepad.exe"

# Deobfuscate machine code bytes and isolate dead opaque predicates
python src/cli.py deobfuscate --hex "55 48 89 e5 31 c0 74 05 e8 11 22 33 44 90 c3"

# Match functions across compilers or architectures semantically
python src/cli.py match `
  --func1 "55 48 89 e5 89 7d fc 8b 45 fc 83 c0 01 5d c3" `
  --func2 "55 48 89 e5 8d 47 01 5d c3"

# Surgically patch an executable file on disk with stack preservation
python src/cli.py patch `
  --source target.exe `
  --output target_patched.exe `
  --offset 0x1A40 `
  --patch-hex "90 90"

# Scan a native Windows binary for embedded neural logic (ONNX, DirectML, GGUF)
python src/cli.py scan-hybrid --file application.exe

# Holistic multi-modal binary inspection & 10 Metaphorical Senses evaluation
python src/cli.py sense --file application.exe --hex "55 48 89 e5 5d c3"

# Run the automated Windows test suite
python tests/test_suite.py
```

---

## Citation, References & Verification
- **Upstream Foundation:** Based on **REA (Reverse Engineer Anything)** by morluto.
- **Academic Research Reference:** Inspired by *"Sparks of Weight-Space Programming: LLMs can natively read & write neural network weights"*, by Rikiya Takehi, Jayden Teoh, Alex Zhang, and Omar Khattab (MIT CSAIL, November 2026).
  - [alphaXiv Preprint Discussion](https://www.alphaxiv.org/abs/2611.weight-space-programming)
  - [Official MIT CSAIL Replication Logs & Prompts Repository](https://github.com/RikiyaT/lm_understand-logs)
  - [Alan Turing Institute Weights Editing Replications](https://github.com/alan-turing-institute/weights_editing)
- **Scope & Methodological Verification:** While WSP research explores direct LLM reasoning over neural network parameters in small models, `REA-Neural` extends this conceptual foundation into continuous state-transition analysis, deterministic deobfuscation, and surgical PE patching for compiled native software.
- Maintained by [bio-colab](https://github.com/bio-colab).
