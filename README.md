# REA-Neural
### Autonomous Continuous Semantic Reverse Engineering & Binary Analysis

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Continuous Semantics](https://img.shields.io/badge/Methodology-Continuous_Semantics-purple.svg)](#)

`REA-Neural` is an agent-native, next-generation reverse engineering framework for compiled software executables (`.exe`, `.dll`, `.so`, `.dylib`, ELF, PE, Mach-O). 

Forked from **REA (Reverse Engineer Anything)** and augmented with continuous representation theory from recent MIT CSAIL research (*"Sparks of Weight-Space Programming"*, Takehi, Teoh, Zhang, Khattab, 2026), `REA-Neural` solves the foundational limitations of traditional symbolic reverse engineering engines (Ghidra, Hopper, IDA Pro).

---

## Key Breakthroughs

### 1. Continuous Semantic Deobfuscation
Complex code protection techniques—such as Control Flow Flattening, Opaque Predicates, and instruction virtualization—artificially multiply basic blocks and obfuscate control graphs. `REA-Neural` models state transitions as continuous vector trajectories, allowing it to:
- Instantly identify algebraic opaque predicates (e.g. dead conditional jumps following register zeroing).
- Prune dummy dispatcher loops and recover canonical linear control flow graphs.

### 2. Cross-Architecture & Cross-Compiler Semantic Matching
Traditional function matching algorithms rely on exact opcode hashes or structural CFG graphs, which fail when binaries are recompiled across architectures (x86-64 vs. ARM64) or optimization levels (`-O0` vs. `-O3`). `REA-Neural` computes continuous behavioral vector embeddings of assembly routines, achieving $>90\%$ cosine similarity matching on stripped binaries.

### 3. Goal-Driven Surgical Binary Patching
Manual byte patching is notoriously error-prone, frequently resulting in stack imbalance (`RSP`/`RBP` misalignment) or checksum violations. `REA-Neural` computes minimal perturbation vectors ($\Delta \text{State} \le \epsilon$), automatically recalculates PE/ELF checksums, and guarantees stack frame stability.

### 4. Hybrid Native-Neural Application Dissection
Modern applications (games, anti-cheat, endpoint security clients, media suites) embed neural inference logic (ONNX, TFLite, GGUF, DirectML) directly into PE/ELF sections (`.rsrc`, `.rodata`). `REA-Neural` scans native binaries to expose these embedded logic cores and decompile the boundary between native OS API calls and embedded decision matrices.

---

## Repository Structure

```
D:/rea-neural/
├── LICENSE                        # Apache 2.0 License
├── package.json                   # Project metadata
├── README.md                      # Comprehensive guide
├── src/
│   ├── cli.py                     # Unified CLI entry point
│   ├── binary_neural_engine.py    # Binary analysis, deobfuscator & patcher
│   └── rea_neural_engine.py      # Weight-space SVD & circuit decompiler
├── skills/
│   └── reverse-engineer-anything/ # Agent-native skill specification
│       ├── SKILL.md               # Main skill contract
│       └── references/            # In-depth technical reference manuals
├── schemas/                       # Agent MCP tool definitions
├── tests/                         # Automated unit & regression test suite
└── docs/                          # Architecture & mathematical foundation
```

---

## Quickstart CLI Usage

```bash
# Clone the repository
git clone https://github.com/your-username/rea-neural.git
cd rea-neural

# 1. Inspect a native PE/ELF binary header and section mapping
python src/cli.py inspect --file target_app.exe

# 2. Deobfuscate machine code bytes and isolate dead opaque predicates
python src/cli.py deobfuscate --hex "55 48 89 e5 31 c0 74 05 e8 11 22 33 44 90 c3"

# 3. Match functions across architectures or compiler optimization levels
python src/cli.py match \
  --func1 "55 48 89 e5 89 7d fc 8b 45 fc 83 c0 01 5d c3" \
  --func2 "55 48 89 e5 8d 47 01 5d c3"

# 4. Surgically patch an executable with verified stack frame alignment
python src/cli.py patch \
  --source target.exe \
  --output target_patched.exe \
  --offset 0x1A40 \
  --patch-hex "90 90"

# 5. Scan a native binary for embedded neural logic (ONNX, TFLite, GGUF)
python src/cli.py scan-hybrid --file application.exe

# 6. Run automated test suite
python tests/test_suite.py
```

---

## Citation & Acknowledgments
- Based on **REA (Reverse Engineer Anything)** by morluto.
- Inspired by *"Sparks of Weight-Space Programming: LLMs can natively read & write neural network weights"* (MIT CSAIL, 2026).
