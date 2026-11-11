# Weight-Space Programming (WSP) Reference Specification
### Adapted for Windows Native Executable Reverse Engineering & Embedded Neural Inspection

Based on MIT CSAIL research (*"Sparks of Weight-Space Programming: LLMs can natively read & write neural network weights"*, Rikiya Takehi, Jayden Teoh, Alex Zhang, and Omar Khattab, November 2, 2026 — https://rikiyat.github.io/blog/weight-space-programming/).

---

## Important Scope & Architectural Positioning in Bintra

> **Bintra is an autonomous continuous semantic reverse engineering framework designed for Windows compiled software (`.exe`, `.dll`, PE32/PE32+) and modern hybrid binaries embedding AI runtimes (DirectML, WinML, ONNX, Safetensors).**
>
> While the original MIT CSAIL paper explores LLMs directly reading and writing parameters of small toy models, **Bintra adapts these mathematical and algorithmic breakthroughs to solve real binary analysis, deobfuscation, and security auditing problems in native Windows software**:
>
> 1. **Inspecting Embedded Neural Runtimes:** Modern Windows executables (multimedia suites, simulation engines, endpoint agents) embed neural weights in `.rsrc` or `.rodata` sections. Bintra inspects, extracts, and analyzes these models without running unsafe host binaries.
> 2. **Auditing Without Evaluation (Security & Backdoors):** Detecting hidden Trojan triggers, abnormal rank-1 spikes, and unauthorized decision paths in embedded models prior to execution.
> 3. **Zero-Gradient Surgical Intervention:** Performing precision modifications on linear projection tables, heuristic matrices, and embedded weights (e.g. `column_direction_subtract` editing 0.016% of weights) without requiring full retraining datasets or compilation toolchains.
> 4. **Cross-Architecture & Continuous Semantic Representation:** Transferring the continuous representation concepts (SVD decomposition, effective rank, behavioral trajectory modeling) to native machine code instructions (x86-64 / ARM64).

---

## 1. The Three Pillars of Weight-Space Programming in Hybrid Binary Analysis

1. **Reading Neural Weights Directly (Zero-Execution Static Inspection):**
   - **Spatial Input Receptive Fields (Exp 1):** Mapping input channels to discover the functional domain of embedded models (e.g. detecting image sensors, audio streams, or spatial input-channel coordinate layouts).
   - **Geometric Output Contours (Exp 2):** Reading final layer weights to reconstruct geometric decision boundaries and output classification topologies without forward passes.
   - **Cross-Layer Matrix Multiplication & Effective Rank (Exp 3):** Identifying copying/induction structures across layers ($W_{QK}^{(l_2)} W_{OV}^{(l_1)}$), and computing Roy-Vetterli Effective Rank & Participation Ratio to infer data complexity and alphabet entropy.
   - **Attention-Only Contrastive Probing (Exp 7):** Contrastive attention inspection to isolate routing biases and factual token alignment when static weight diffing alone is inconclusive.

2. **Fixing Neural & Linear Weights Surgically (Minimal Perturbation):**
   - **Conditional Sub-Circuit Grafting (Exp 4):** Grafting minimal conditional bypass paths (<= 3.5% weights) into dormant/low-energy units to override specific failure states while leaving default execution intact.
   - **Selective Column Direction Subtraction (Exp 8):** Tracing pathological loop directions to specific linear projection layers and subtracting that direction exclusively from the top $K$ output columns (e.g., 64 columns; 0.016% of total weights), avoiding disruption to non-looping features.
   - **Obstacle Removal vs. Capability Creation (Amenability Diagnostics):** Distinguishing between removable attractor loops (high spectral dominance $\sigma_0 / \sigma_1$, looping states) and intrinsic capability deficits where weight editing cannot synthesize missing information.

3. **Weight Synthesis & Zero-Evaluation Security Auditing (Exp 5, 6 & Security):**
   - **Zero-Shot Weight Compilation (Exp 5 & 6):** Translating symbolic logic and heuristic rules directly into neural layer weights without backpropagation.
   - **Auditing Without Evaluation (Backdoors & Trojans):** Detecting dormant malicious triggers directly from weight geometry (neuron norm z-score outliers > 4.5 $\sigma$) without needing trigger-specific test suites.
   - **Cross-Architecture Subspace Merging:** Transplanting functional principal components across non-identical matrix dimensions via continuous interpolation.
