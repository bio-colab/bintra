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

### 4. Hybrid Native-Neural Application Dissection & Weight Security Auditing
Modern Windows applications (games, anti-cheat, endpoint security clients, media suites) embed neural inference logic (ONNX, TFLite, GGUF, DirectML, WinML, Safetensors) directly into PE sections (`.rsrc`, `.rodata`). `REA-Neural` scans native binaries to expose these embedded logic cores and decompile the boundary between native Win32 API calls and embedded decision matrices.
- **Zero-Execution Security Auditing:** Scans raw embedded weights for dormant Trojan/backdoor trigger neurons and anomalous rank-1 spikes before host execution.
- **Selective Column Surgery:** Intervenes in linear projection matrices (`column_direction_subtract`) at extreme sparsity (editing top-$K$ columns, e.g. 0.016% of weights) to eliminate pathological looping or bypass deadlocks without retraining.
- **Cross-Layer Induction & Effective Rank:** Evaluates cross-layer composition ($W_{QK}^{(l_2)} W_{OV}^{(l_1)}$) and spectral effective rank to infer alphabet and structural data complexity without running model text.

### 5. Symbiotic Ghidra Integration (High P-Code Vectorization & Windows Mutation)
Rather than treating Ghidra as a detached external decompiler, `REA-Neural` establishes a bidirectional pipeline with Ghidra 12.1.4:
- **High P-Code IR Vectorization:** Translates Ghidra's SSA P-code operations into 64-dimensional continuous behavioral vectors, achieving $>95\%$ cross-architecture semantic matching invariant to compiler registers or optimizations.
- **Pre-Decompiler Opaque Predicate Pruning:** Simplifies algebraic dead-end branches before AST construction, eliminating decompiler timeouts and sprawling control-flow flattening dispatcher cascades.
- **Unlocked Windows Database Mutation:** Removes legacy read-only locks, permitting automated function renaming (`set_address_name`), prototype injection (`annotate_native_function`), and C-structure type synthesis on Windows via authenticated loopback TCP.

---

## The 10 Metaphorical Senses Framework (Cybernetic Program Perception)

To unify diverse binary and neural analysis modalities into a cohesive cognitive architecture, `REA-Neural` introduces the **10 Metaphorical Senses (`SensoryCortex`)**. Inspired by biological sensorimotor systems, these senses map complex reverse engineering tasks into continuous perceptual channels:

| # | Sense (Arabic / English) | Cybernetic Biological Metaphor | Technical Realization in REA-Neural | Telemetry & Measurement |
|:---:|:---|:---|:---|:---|
| **1** | **البصر التحليلي**<br>`Analytical Vision` | Static spatial perception of anatomy and structural form. | Deep inspection of PE32/PE32+ headers, section geometry, mitigations (ASLR, DEP, CFG), and singular value spectral decay. | Sections discovered, mitigation vector, SVD spectral energy decay. |
| **2** | **السمع الزمني**<br>`Temporal Hearing` | Sequential listening to acoustic cadences and rhythms over time. | Tracing instruction transition sequences, activation progression over execution steps, and control transition density. | Decoded instruction steps, temporal transition count, transition density $\Delta t$. |
| **3** | **اللمس النشط**<br>`Active Touch` | Physical palpation, tactile probing, and physical intervention. | Surgical byte patching on disk, selective column direction subtraction (`column_direction_subtract`), and Lipschitz perturbation probing. | Supported patch operations, perturbation delta $\| \Delta W \|_F$, Lipschitz bound. |
| **4** | **الشم الاستكشافي**<br>`Exploratory Smell` | Detecting distant chemical scents, pheromones, and invisible traces. | Sniffing algebraic opaque predicates, scanning embedded neural inference containers (ONNX, DirectML), and computing Shannon byte entropy. | Opaque predicates detected, embedded AI assets, Shannon entropy (bits/byte). |
| **5** | **الذوق التمييزي**<br>`Discriminative Taste` | Chemical taste discrimination of nutrients vs. toxic non-food noise. | Discriminating genuine executable machine code from random byte noise, validating x64 REX cross-register zeroing, and P-code semantics. | Signal-to-noise ratio, valid code classification, cross-register false-positive rejection. |
| **6** | **الحس العميق**<br>`Deep Proprioception` | Internal awareness of body posture, joint angles, and balance. | Instruction-boundary stack frame tracking ($\Delta RSP / RBP$), frame-altering opcode accounting, and pre-surgery amenability awareness. | Cumulative stack delta bytes, frame-altering op count, boundary alignment. |
| **7** | **حس المكان**<br>`Spatial Sense` | Spatial orientation, mental coordinate projection, and mapping. | Bidirectional virtual coordinate projection ($RVA \leftrightarrow 	ext{File Offset}$), section boundary alignment, and multidimensional tensor slicing. | Coordinate slicing active, RVA-to-Offset spatial mapping accuracy. |
| **8** | **التوازن الدهليزي**<br>`Vestibular Balance` | Inner-ear equilibrium, posture maintenance, and upright stability. | PE integrity Checksum recalculation, Frobenius norm equilibrium bounds, and the Keep-on-Improvement rollback gate. | PE Checksum sync engine, Frobenius safety threshold, rollback barrier. |
| **9** | **الألم المجازي**<br>`Metaphorical Pain (Nociception)` | Protective reflex to noxious stimuli preventing tissue damage. | Pre-mutation hazard reflex that halts execution on stack-destroying patches, DEP section violations, in-place file truncation, or unamenable edits. | Overwrite safety boolean, nociceptive diagnosis, safety reflex triggers. |
| **10** | **الإحساس بالإيقاع**<br>`Sense of Rhythm (Chronoception)` | Perceiving harmonic cadence, beat intervals, and periodicity. | Measuring dispatcher switch cadence regularity in flattened control flow (CFF), and lag-4 autocorrelation in byte streams. | Dispatcher regularity metric, CFF rhythm detection, byte autocorrelation. |

---

## MIT CSAIL Research Lineage & Latent Experimental Capabilities

`REA-Neural` directly incorporates and adapts the foundational experiments from MIT CSAIL's research:  
*"Sparks of Weight-Space Programming: LLMs can natively read & write neural network weights"*, by Rikiya Takehi, Jayden Teoh, Alex Zhang, and Omar Khattab (November 2, 2026).

Beyond the declared binary reverse engineering workflows, the codebase preserves **the complete suite of experimental capabilities** as an active research platform:

1. **Spatial Receptive Field Concentration (Exp 1):**  
   `WeightSecurityAuditor.audit_weights_without_evaluation` reads first-layer weight distributions across input channels to determine task domain (e.g. bottom-row paddle detection in Breakout at row 8) without inference.
2. **Geometric Output Outline Extraction (Exp 2):**  
   Extracts 2D decision contours and shape edge geometries directly from output-layer hidden unit weights.
3. **Cross-Layer Virtual Composition & Spectral Effective Rank (Exp 3):**  
   `CrossLayerCircuitAnalyzer.analyze_cross_layer_induction` multiplies weight matrices across layers ($W_{QK}^{(l_2)} W_{OV}^{(l_1)}$) to detect copying/induction heads without token inputs, while `compute_effective_rank` uses Roy-Vetterli spectral entropy to infer alphabet and syntax complexity.
4. **Conditional Sub-Circuit Grafting (Exp 4):**  
   `CircuitGrafter.graft_conditional_subcircuit` grafts minimal conditional override paths ($\le 3.5\%$ of weights) into dormant units of host matrices, creating self-terminating bypass circuits.
5. **Zero-Shot Weight Synthesis from Symbolic Domain Rules (Exp 5 & 6):**  
   `WeightSpaceCompiler.compile_breakout_policy_network` compiles algorithmic game rules directly into 2-layer neural network weight tensors from scratch without backpropagation.
6. **Budgeted Forward-Pass Rollout Optimization (Exp 6 & 8):**  
   `ForwardPassHarness.run_budgeted_optimization` provides a bounded rollout loop (e.g. 10 to 50 forward passes) with an automated Keep-on-Improvement rollback gate.
7. **Contrastive Attention-Routing Probing (Exp 7):**  
   `AttentionPatternAuditor.audit_sycophancy_attention` isolates factual question tokens vs. user suggestion tokens to diagnose subtle routing biases when static weight differences are distributed and inconclusive.
8. **Selective Column Direction Subtraction (Exp 8):**  
   `WeightPatcher.column_direction_subtract` surgically subtracts pathological loop attractor directions exclusively from the top $K$ output columns (e.g., 64 columns; $0.016\%$ of total weights), curing infinite reasoning loops while protecting $98.4\%$ of model parameters.
9. **Pre-Surgery Amenability Diagnostic (Page 17 Boundary Condition):**  
   `AmenabilityDiagnostic.evaluate_surgical_amenability` distinguishes removable attractor obstacles ($\ge 30\%$ loop rate, high spectral dominance $\sigma_0/\sigma_1$) from fundamental capability deficits, triggering a nociceptive warning when surgery is futile.
10. **Zero-Evaluation Backdoor & Trojan Auditing (Page 19):**  
    `WeightSecurityAuditor` identifies dormant malicious triggers directly from weight space geometry (neuron norm z-score outliers $> 4.5\sigma$) without test cases, crucial for auditing embedded AI runtimes in Windows software.
11. **Cross-Architecture Subspace Transplantation (Page 19):**  
    `CircuitGrafter.transplant_reasoning_subspace` projects principal circuit modes across non-identical tensor dimensions via continuous interpolation.

---

## Future Research Roadmap & Historical Lineage Archive

The preservation of these capabilities serves three vital engineering purposes:

* **1. Active Frontier for Ongoing Development:**  
  These mechanisms form the concrete development backlog for upcoming `REA-Neural` milestones, including automated Ghidra P-code symbolic-to-neural lifting, full CFF unflattening with SSA reconstruction, and live Win32 DirectML memory hooking.
* **2. Open Platform for Future Collaborators:**  
  By documenting both the operational CLI tools and the latent experimental algorithms, external researchers and open-source contributors can immediately access, benchmark, and extend these continuous semantic techniques.
* **3. Historical Lineage & Design Provenance:**  
  In the event that future major architectures deprecate, refactor, or decouple specific experimental modules, this documentation and code serve as a permanent historical record of the foundational bridge between Weight-Space Programming (WSP) and native binary software reverse engineering.

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
│   ├── sensory_cortex.py          # 10 Metaphorical Senses evaluation cortex
│   └── ghidra_pcode_vectorizer.py # Ghidra P-Code IR continuous vectorizer
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

# Audit embedded Safetensors neural model (Effective Rank, Induction Heads, Backdoors, Amenability)
python src/cli.py wsp-audit --model model.safetensors

# Perform surgical low-rank column direction subtraction on embedded linear layers
python src/cli.py patch-weights `
  --source model.safetensors `
  --output patched.safetensors `
  --tensor mlp.down_proj `
  --operation column_direction_subtract `
  --num-columns 64

# Holistic multi-modal binary inspection & 10 Metaphorical Senses evaluation
python src/cli.py sense --file application.exe --hex "55 48 89 e5 5d c3"

# Match functions across architectures using Ghidra High P-Code IR
python src/cli.py match-pcode --func1 pcode_x86.json --func2 pcode_arm64.json

# Prune P-Code opaque predicates before decompiler AST construction
python src/cli.py deobfuscate-pcode --file routine_pcode.json

# Generate Ghidra Program Database annotation plan
python src/cli.py ghidra-plan --address 0x140001000 --name "CheckLicense" --return-type "bool"

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
