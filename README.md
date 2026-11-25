<p align="center">
  <img src="assets/banner.jpg" alt="Bintra Continuous Semantic Reverse Engineering" width="100%">
</p>

<p align="center">
  <a href="#quick-start"><img src="assets/icon.png" alt="Bintra Icon" width="110" height="110"></a>
</p>

<h1 align="center">Bintra</h1>

<p align="center">
  <strong>Autonomous Continuous Semantic Reverse Engineering & Binary Analysis Framework</strong><br>
  <em>Bridging Symbolic Decompilation, Continuous Weight-Space Semantics, and Windows System Forensics</em>
</p>

<p align="center">
  <a href="https://github.com/bio-colab/bintra/actions/workflows/windows-ci.yml"><img src="https://github.com/bio-colab/bintra/actions/workflows/windows-ci.yml/badge.svg" alt="Bintra Cross-Platform CI"></a>
  <a href="https://github.com/bio-colab/bintra/releases/tag/v1.1.0"><img src="https://img.shields.io/badge/Release-v1.1.0-purple.svg" alt="Latest Release"></a>
  <a href="https://www.microsoft.com/windows"><img src="https://img.shields.io/badge/Platform-Windows_10_%2F_11_%2F_Server-blue.svg?logo=windows" alt="Platform"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue.svg?logo=python" alt="Python"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-green.svg" alt="License"></a>
  <a href="docs/ROADMAP.md"><img src="https://img.shields.io/badge/Roadmap-2026-blueviolet.svg" alt="Roadmap"></a>
</p>


`Bintra` is an agent-native, next-generation reverse engineering framework tailored for **Windows compiled software executables and libraries** (`.exe`, `.dll`, PE32, PE32+). 

Built as a standalone framework grounded in continuous representation theory from recent MIT CSAIL research (*"Sparks of Weight-Space Programming"*, Takehi, Teoh, Zhang, Khattab, 2026), `Bintra` overcomes the core vulnerabilities of traditional symbolic reverse engineering engines (Ghidra, Hopper, IDA Pro) when analyzing obfuscated native code on Windows.

---

## Key Breakthroughs for Windows Binaries

### 1. Continuous Semantic Deobfuscation
Complex code protection techniques—such as Control Flow Flattening, Opaque Predicates, and instruction virtualization—artificially multiply basic blocks and obfuscate control graphs. `Bintra` models state transitions as continuous vector trajectories, allowing it to:
- Instantly identify algebraic opaque predicates (e.g. dead conditional jumps following register zeroing) with flag-preserving lookahead (`mov`, `nop`, `lea`).
- Prune dummy dispatcher loops using localized window cadence analysis ($\le 1024$ bytes, regularity $\ge 0.35$) and recover canonical linear control flow graphs without false-positive alarms on standard compiler outputs.

### 2. Cross-Architecture & Cross-Compiler Semantic Matching
Traditional function matching algorithms rely on exact opcode hashes or structural CFG graphs, which fail when binaries are recompiled across architectures (x86-64 vs. ARM64) or optimization levels (`-O0` vs. `-O3`). `Bintra` bridges this gap via two complementary mechanisms:
- **16-D Behavioral Feature Vectorizer (`SemanticFunctionMatcher`):** In standalone mode, extracts an engineered 16-dimensional behavioral histogram and state transition profile with scale-congruence guards (`scale_ratio >= 0.60`) and 100% disassembly completeness. Provides fast, zero-dependency cosine matching across structurally similar routines without requiring a heavy deep learning runtime.
- **High P-Code SSA IR Vectorizer (`ghidra_pcode_vectorizer.py`):** When paired with Ghidra decompilation, High P-Code SSA operations are lifted into complete 64-dimensional semantic vectors encoding transition topology, def-use edge density, cyclomatic loop complexity, and memory intensity (cosine match threshold `MATCH_THRESHOLD = 0.90`; empirical accuracy is tracked via repeatable evaluation benchmarks rather than fixed source claims).

### 3. Goal-Driven Surgical Binary Patching
Manual byte patching is notoriously error-prone, frequently resulting in stack imbalance (`RSP`/`RBP` misalignment) or PE checksum violations. `Bintra` computes minimal perturbation vectors ($\Delta \text{State} \le \epsilon$), automatically recalculates PE integrity checksums, and enforces a heuristic nociception guard against stack frame balance violations (`RET`/frame-altering opcode checks).

### 4. Hybrid Native-Neural Application Dissection & Weight Security Auditing
Modern Windows applications (desktop suites, simulation runtimes, endpoint security clients, media tools) embed neural inference logic (ONNX, TFLite, GGUF, DirectML, WinML, Safetensors) directly into PE sections (`.rsrc`, `.rodata`). `Bintra` scans native binaries to expose these embedded logic cores and decompile the boundary between native Win32 API calls and embedded decision matrices.
- **Zero-Execution Security Auditing:** Scans raw embedded weights for dormant Trojan/backdoor trigger neurons and anomalous rank-1 spikes before host execution.
- **Selective Column Surgery:** Intervenes in linear projection matrices (`column_direction_subtract`) at extreme sparsity (editing top-$K$ columns, e.g. 1.56% of weights for 64 of 4096 columns) to eliminate pathological looping or bypass deadlocks without retraining.
- **Cross-Layer Induction & Effective Rank:** Evaluates cross-layer composition ($W_{QK}^{(l_2)} W_{OV}^{(l_1)}$) and spectral effective rank to infer alphabet and structural data complexity without running model text.

### 5. Symbiotic Ghidra Integration (High P-Code Vectorization & Live Queued-Poll Bridge)
Rather than treating Ghidra as a detached external decompiler, `Bintra` directly feeds and complements Ghidra through an authenticated localhost HTTP JSON-RPC 2.0 queued-poll bridge (`ghidra_live_bridge.py` & `BintraLiveBridgeService.py`):
- **Queued-Poll Localhost IPC Bridge:** Multi-threaded `ThreadingMixIn` HTTP server on `127.0.0.1:41718` (with per-session auth token verification and bounded discovery markers under `cap.tempdir.marker.write`, optionally disabled via `--no-temp-marker` / `publish_temp_marker=false`). `BintraLiveBridgeService.py` polls queued mutations on a `1.0s` interval inside Ghidra's background thread for thread-safe Program DB updates.
- **Dynamic Diagnostic Injection:** Streams Phase 1 VAD memory layout notes, Phase 1.5 runtime structure dissections (auto-synthesized C composite structs registered in Ghidra's `DataTypeManager`) and pointer scan paths, Phase 2 Crash RCA root-cause bookmarks and function renames (preserving explicit `rva` vs. `va` image-base relocation), and Phase 3 ETW temporal causality timelines directly into the active Ghidra Program Database.
- **High P-Code IR Vectorization:** Translates Ghidra's SSA P-code operations into 64-dimensional continuous behavioral vectors, matching routines deterministically above `MATCH_THRESHOLD = 0.90` cosine similarity across compiler optimizations and architectures.
- **Pre-Decompiler Opaque Predicate Pruning:** Simplifies algebraic dead-end branches before AST construction, eliminating decompiler timeouts and sprawling control-flow flattening dispatcher cascades.

---

<p align="center">
  <img src="assets/hero.jpg" alt="Bintra Continuous Binary Perception and Deobfuscation Flow" width="95%">
  <br>
  <em>Figure 1: Continuous Program Perception — Machine code basic blocks flow through the cybernetic sensory core into continuous vector trajectories, deobfuscating control flow and enabling cross-architecture equivalence matching.</em>
</p>

## The 10 Metaphorical Senses Framework (Cybernetic Program Perception)

To unify diverse binary and neural analysis modalities into a cohesive cognitive architecture, `Bintra` introduces the **10 Metaphorical Senses (`SensoryCortex`)**. Inspired by biological sensorimotor systems, these senses map complex reverse engineering tasks into continuous perceptual channels:

| # | Sense (Arabic / English) | Cybernetic Biological Metaphor | Technical Realization in Bintra | Telemetry & Measurement |
|:---:|:---|:---|:---|:---|
| **1** | **البصر التحليلي**<br>`Analytical Vision` | Static spatial perception of anatomy and structural form. | Deep inspection of PE32/PE32+ headers, section geometry, mitigations (ASLR, DEP, CFG), and singular value spectral decay. | Sections discovered, mitigation vector, SVD spectral energy decay. |
| **2** | **السمع الزمني**<br>`Temporal Hearing` | Sequential listening to acoustic cadences and rhythms over time. | Tracing instruction transition sequences, activation progression over execution steps, and control transition density. | Decoded instruction steps, temporal transition count, transition density $\Delta t$. |
| **3** | **اللمس النشط**<br>`Active Touch` | Physical palpation, tactile probing, and physical intervention. | Surgical byte patching on disk, selective column direction subtraction (`column_direction_subtract`), and Lipschitz perturbation probing. | Supported patch operations, perturbation delta $\| \Delta W \|_F$, Lipschitz bound. |
| **4** | **الشم الاستكشافي**<br>`Exploratory Smell` | Detecting distant chemical scents, pheromones, and invisible traces. | Sniffing algebraic opaque predicates, scanning embedded neural inference containers (ONNX, DirectML), and computing Shannon byte entropy. | Opaque predicates detected, embedded AI assets, Shannon entropy (bits/byte). |
| **5** | **الذوق التمييزي**<br>`Discriminative Taste` | Chemical taste discrimination of nutrients vs. toxic non-food noise. | Discriminating genuine executable machine code from random byte noise, validating x64 REX cross-register zeroing, and P-code semantics. | Signal-to-noise ratio, valid code classification, cross-register false-positive rejection. |
| **6** | **الحس العميق**<br>`Deep Proprioception` | Internal awareness of body posture, joint angles, and balance. | Instruction-boundary stack frame tracking ($\Delta RSP / RBP$), frame-altering opcode accounting, and pre-surgery amenability awareness. | Cumulative stack delta bytes, frame-altering op count, boundary alignment. |
| **7** | **حس المكان**<br>`Spatial Sense` | Spatial orientation, mental coordinate projection, and mapping. | Bidirectional virtual coordinate projection ($RVA \leftrightarrow \text{File Offset}$), section boundary alignment, and multidimensional tensor slicing. | Coordinate slicing active, RVA-to-Offset spatial mapping accuracy. |
| **8** | **التوازن الدهليزي**<br>`Vestibular Balance` | Inner-ear equilibrium, posture maintenance, and upright stability. | PE integrity Checksum recalculation, Frobenius norm equilibrium bounds, and the Keep-on-Improvement rollback gate. | PE Checksum sync engine, Frobenius safety threshold, rollback barrier. |
| **9** | **الألم المجازي**<br>`Metaphorical Pain (Nociception)` | Protective reflex to noxious stimuli preventing tissue damage. | Pre-mutation hazard reflex that halts execution on stack-destroying patches, DEP section violations, in-place file truncation, or unamenable edits. | Overwrite safety boolean, nociceptive diagnosis, safety reflex triggers. |
| **10** | **الإحساس بالإيقاع**<br>`Sense of Rhythm (Chronoception)` | Perceiving harmonic cadence, beat intervals, and periodicity. | Measuring dispatcher switch cadence regularity in flattened control flow (CFF), and lag-4 autocorrelation in byte streams. | Dispatcher regularity metric, CFF rhythm detection, byte autocorrelation. |

---

## MIT CSAIL Research Lineage & Latent Experimental Capabilities

`Bintra` directly incorporates and adapts the foundational experiments from MIT CSAIL's research:  
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
   `WeightPatcher.column_direction_subtract` surgically subtracts pathological loop attractor directions exclusively from the top $K$ output columns (e.g., 64 of 4096 columns; $1.56\%$ of total weights), curing infinite reasoning loops while protecting $98.4\%$ of model parameters.
9. **Pre-Surgery Amenability Diagnostic (Page 17 Boundary Condition):**  
   `AmenabilityDiagnostic.evaluate_surgical_amenability` distinguishes removable attractor obstacles ($\ge 30\%$ loop rate, high spectral dominance $\sigma_0/\sigma_1$) from fundamental capability deficits, triggering a nociceptive warning when surgery is futile.
10. **Zero-Evaluation Backdoor & Trojan Auditing (Page 19):**  
    `WeightSecurityAuditor` identifies dormant malicious triggers directly from weight space geometry (neuron norm z-score outliers $> 4.5\sigma$) without test cases, crucial for auditing embedded AI runtimes in Windows software.
11. **Cross-Architecture Subspace Transplantation (Page 19):**  
    `CircuitGrafter.transplant_reasoning_subspace` projects principal circuit modes across non-identical tensor dimensions via continuous interpolation.

---

## Future Research Roadmap & Historical Lineage Archive

For detailed strategic priorities, technological evaluations (ETW, Event Log, phnt, WMI, Sysinternals), and phased development milestones, see the comprehensive [Strategic Direction & Roadmap (docs/ROADMAP.md)](docs/ROADMAP.md).

The preservation of these capabilities serves three vital engineering purposes:

* **1. Active Frontier for Ongoing Development:**  
  These mechanisms form the concrete development backlog for upcoming `Bintra` milestones, including live ETW process-targeted tracing, automated Ghidra P-code symbolic-to-neural lifting, and deep NTAPI inspection.
* **2. Open Platform for Future Collaborators:**  
  By documenting both the operational CLI tools and the latent experimental algorithms, external researchers and open-source contributors can immediately access, benchmark, and extend these continuous semantic techniques.
* **3. Historical Lineage & Design Provenance:**  
  In the event that future major architectures deprecate, refactor, or decouple specific experimental modules, this documentation and code serve as a permanent historical record of the foundational bridge between Weight-Space Programming (WSP) and native binary software reverse engineering.

---

## Repository Structure

```
bintra/
├── .github/
│   ├── workflows/
│   │   └── windows-ci.yml         # Bintra Cross-Platform CI pipeline (Windows + Linux)
│   ├── ISSUE_TEMPLATE/            # Bug report and feature request templates
│   └── PULL_REQUEST_TEMPLATE.md   # Pull request checklist
├── AGENTS.md                      # AI coding agent operating guide & MCP/CLI matrix
├── CODE_OF_CONDUCT.md             # Contributor covenant & standards
├── CONTRIBUTING.md                # Development and contribution guide
├── install.bat                    # 1-Click Windows batch installer (Double-clickable)
├── install.ps1                    # Automated PowerShell installer & PATH configurator
├── LICENSE                        # Apache 2.0 License
├── pyproject.toml                 # Standard PEP 517/621 packaging metadata
├── README.md                      # Comprehensive guide
├── requirements.txt               # Lightweight runtime dependencies (numpy, capstone)
├── SAFETY_POLICY.md               # Non-destructive execution & Safety Kernel policy
├── SCOPE.md                       # Active RE scope & archived lineage policy
├── SECURITY.md                    # Vulnerability reporting & audit chain contract
├── assets/                        # Official brand marks, banners, icons & visual identity
├── benchmarks/
│   └── real_world_windows/        # Host-driven 8-level Windows benchmark campaign & RESULTS.md
├── ghidra_scripts/                # BintraGhidraBridge.java, BintraLiveBridgeService.py, bintra_extract_pcode.py
├── schemas/                       # MCP tool schema definitions
├── skills/                        # 8 agent-native skills (bintra router + 7 specialist skills)
├── src/
│   ├── cli.py                     # Unified CLI entry point (`bintra`) with self-update
│   ├── analysis_orchestrator.py   # Unified read-only binary triage & cross-domain evidence orchestrator
│   ├── mcp_server.py              # JSON-RPC 2.0 stdio MCP server (`bintra-mcp`, 51 tools, resources, prompts)
│   ├── binary_neural_engine.py    # PE binary analysis, deobfuscator & patcher
│   ├── bintra_engine.py           # Weight-space SVD & circuit decompiler
│   ├── sensory_cortex.py          # 10 Metaphorical Senses evaluation cortex
│   ├── ghidra_pcode_vectorizer.py # Ghidra P-Code IR continuous vectorizer & similarity index
│   ├── ghidra_export_store.py     # Zero-dependency SQLite & JSONL export store & index
│   ├── ghidra_headless_runner.py  # Shared Ghidra analyzeHeadless execution engine (CLI + MCP)
│   ├── ghidra_live_bridge.py      # Authenticated localhost JSON-RPC 2.0 Ghidra bridge
│   ├── pe_deep_forensics.py       # Offline x64 .pdata, MSVC RTTI vftables & local PDB verifier
│   ├── python_intelligence.py     # Python bytecode & frozen binary forensics
│   ├── python_package_intelligence.py # CPython runtime & package intelligence
│   ├── token_telemetry.py         # Session telemetry tracker
│   ├── security/                  # ExecutionGuard, AuditLogger & Reference Monitor
│   └── windows_intelligence/      # Process, Device, Registry, Network, Slack & Crash Diagnostics
├── tests/                         # 466 automated unit, sensory, runtime telemetry & security tests
└── docs/                          # Architecture, Roadmap & runtime telemetry documentation
    ├── architecture.md            # Master architecture & formal model
    ├── ROADMAP.md                 # Strategic direction, tech evaluation & roadmap
    ├── RUNTIME_TELEMETRY_AND_CRASH_ANALYSIS.md  # Live memory/ETW/crash pipeline reference
    └── releases/
        └── v1.0.0.md              # Frozen v1.0.0 release notes archive
```

---

## Installation & Quickstart on Windows

### Prerequisites
- **Operating System:** Windows 10, Windows 11, or Windows Server (x86-64 / ARM64).
- **Python:** Python 3.10, 3.11, or 3.12 (64-bit recommended). Ensure *"Add Python to PATH"* was selected during Python installation.

---

### Option 1: Automated 1-Click Installation (Recommended)
Clone the repository and run the automated PowerShell installer:
```powershell
git clone https://github.com/bio-colab/bintra.git
cd bintra

# Run the PowerShell installer (automatically configures PATH, installs package, runs smoke test)
powershell -ExecutionPolicy Bypass -File .\install.ps1

# Or double-click install.bat
```

---

### Option 2: Standard Developer Installation (`pip`)
```powershell
# Clone the repository
git clone https://github.com/bio-colab/bintra.git
cd bintra

# Install in editable mode
pip install -e .
```

---

### Option 3: Direct Installation via Git (Zero-Clone)
Install Bintra directly into your active Python environment without manually downloading the repository:
```bash
pip install git+https://github.com/bio-colab/bintra.git
```

---

### Option 4: Fast Installation via `uv`
If you use Astral's [`uv`](https://github.com/astral-sh/uv):
```powershell
# Install as a persistent global tool
uv tool install git+https://github.com/bio-colab/bintra.git

# Or in an active project virtual environment
uv pip install -e .
```

---

### 2. Immediate Verification & Smoke Test
Run the unified CLI from any directory or terminal:
```powershell
# Verify CLI presence and version
bintra --help

# Run a quick 10-Sense Sensory Cortex smoke test on a sample hex stream
bintra sense --hex "55 48 89 e5 90 5d c3"
```

---

## Agent-Native MCP (Model Context Protocol) Integration

`Bintra` ships with a **JSON-RPC 2.0 stdio MCP server** (`bintra-mcp`) offering **51 mediated reverse engineering and Windows intelligence tools** (with MCP tool annotations and structured `outputSchema` on self-describing tools), **4 live contextual resources** (`bintra://capabilities`, `bintra://security/policy`, `bintra://telemetry/session`, `bintra://workflows/playbooks`), and **5 workflow prompts** (`triage_pe_binary`, `root_cause_crash`, `audit_windows_host`, `diff_binary_versions`, `audit_neural_weights`) to AI agents (Claude Desktop, Cursor, Antigravity, Windsurf). `tools/list` supports MCP 2025-06-18 cursor pagination for token-budgeted agents.

### 1. Claude Desktop Configuration
Add the `bintra` server to your `%APPDATA%\Claude\claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "bintra": {
      "command": "bintra-mcp",
      "args": []
    }
  }
}
```
*(If `bintra-mcp` is not yet in your system PATH, replace `"bintra-mcp"` with the absolute path to your Python Scripts executable, e.g. `"C:\\Users\\<YourUser>\\AppData\\Local\\Programs\\Python\\Python312\\Scripts\\bintra-mcp.exe"` or `["python", "-m", "mcp_server"]`)*.

### 2. Cursor / VS Code MCP Configuration
In your Cursor or VS Code `.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "bintra": {
      "command": "bintra-mcp",
      "args": []
    }
  }
}
```

### 3. Verification of MCP Server
Test the stdio JSON-RPC handshake directly:
```powershell
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | bintra-mcp
```
Output:
```json
{"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05", "supportedProtocolVersions": ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"], "serverInfo": {"name": "bintra", "version": "1.1.0"}}}
```

---

## CLI Usage Reference

### Binary / Windows Executable Commands
```powershell
# Inspect PE executable headers, ASLR/DEP/CFG mitigations, and sections
bintra inspect --file "C:\Windows\System32\notepad.exe"

# Deobfuscate machine code bytes and isolate dead opaque predicates
bintra deobfuscate --hex "55 48 89 e5 31 c0 74 05 e8 11 22 33 44 90 c3"

# Match functions across compilers or architectures semantically
bintra match `
  --func1 "55 48 89 e5 89 7d fc 8b 45 fc 83 c0 01 5d c3" `
  --func2 "55 48 89 e5 8d 47 01 5d c3"

# Surgically patch an executable file on disk with stack preservation & PE checksum sync
# Note: Output file must be outside the target source directory (Complete Mediation guarantee)
bintra patch-binary `
  --file target.exe `
  --output workspace/target_patched.exe `
  --offset 0x1A40 `
  --patch-hex "90 90"

# Scan a native Windows binary for embedded neural logic (DirectML, ONNX, GGUF)
bintra scan-hybrid --file application.exe

# Holistic multi-modal binary inspection & 10 Metaphorical Senses evaluation
bintra sense --file application.exe --hex "55 48 89 e5 5d c3"

# End-to-end unified triage, deep .pdata/RTTI/PDB forensics, semantic binary diff, slack/overlay & Python bytecode
bintra triage --file "C:\Windows\System32\notepad.exe" --format md --output .\workspace\triage.md
bintra pe-forensics --file application.exe
bintra diff-binaries --baseline v1.exe --target v2.exe --mode pe
bintra slack-audit --file installer.exe
bintra py-bytecode --file app_frozen.pyc
bintra capabilities --platform all
```

### Ghidra P-Code, Headless, Topology & Causal Fusion Commands
```powershell
# High P-Code cross-architecture matching, opaque predicate pruning & plan generation
bintra match-pcode --func1 fn_x64.json --func2 fn_arm64.json
bintra deobfuscate-pcode --file pcode_ops.json
bintra ghidra-plan --address 0x140001000 --name RecoveredHandler

# Batch analyze/query (.json, .jsonl, .db), headless automation & localhost live bridge
bintra ghidra-analyze --input export.json --output plan.json --to-sqlite .\workspace\prog.db
bintra ghidra-headless --binary target.exe --timeout 300 --apply
bintra ghidra-bridge --start --port 41718 --no-temp-marker

# Call graphs, SSA def-use slicing, behavioral similarity & provenance-verified fusion
bintra ghidra-callgraph --input .\workspace\prog.db --function target_fn --max-depth 4
bintra ghidra-dataflow --input .\workspace\prog.db --function target_fn
bintra ghidra-similar --input .\workspace\prog.db --function target_fn --threshold 0.75
bintra fuse-evidence --binary target.exe --dmp crash.dmp --ghidra-json export.json
```

### Windows System, Hardware, Network, Registry & Signature Commands
*(Note: `proc-*`, `sys-perf`, `dev-classes`/`list`/`search`/`info`, `reg-read`/`search`/`import` default to `--format md`, and `hw-tree` defaults to `--format tree`; pass `--format json` when parsing stdout.)*
```powershell
# Profile host Windows OS build, WOW64 emulation, and AppCompatFlags layers
bintra win-audit --file target.exe

# Audit DLL search order, API-Sets, Side-by-Side (SxS) assemblies & required exports
bintra resolve-deps --file target.exe [--app-dir "C:\Program Files\App"]

# Detect file locks (Restart Manager), DLL holders & inspect crashes / evidence graph
bintra file-locks --file target.dll
bintra proc-modules --module kernel32.dll
bintra wer-inspect --binary target.exe
bintra dmp-inspect --file .\crash.dmp
bintra crash-rca --dmp .\crash.dmp --binary target.exe
bintra diagnose --binary target.exe --crash-json .\workspace\crash_record.json
bintra evidence-graph --target target.exe --format mermaid

# Authenticode & Security Catalog (.cat) verification and directory trust audit
bintra sig-verify C:\Windows\System32\notepad.exe
bintra sig-audit C:\Windows\System32\drivers --pattern *.sys --limit 100

# Task Manager telemetry & longitudinal resource profiling (Private Bytes, Handles, GDI/USER)
bintra sys-perf --format json
bintra proc-list --limit 20 --sort memory --format json
bintra proc-search --query "notepad" --format json
bintra proc-info --pid 10324 --format json
bintra proc-profile --pid 10324 --samples 10 --interval 0.2
bintra process-mitigations --pid 10324

# Live VAD, read-only memory scanning, pointer chains, struct dissection, CPython heap & ETW
bintra vad-inspect --pid 10324
bintra mem-scan --pid 10324 --type int32 --mode exact --value 42 --session-file .\workspace\scan.json
bintra pointer-scan --pid 10324 --target 0x7FF700102000 --max-depth 2
bintra dissect-struct --pid 10324 --address 0x7FF700102000 --size 64 --format c
bintra py-mem-inspect --pid 10324 --address 0x7FF700102000 --type pyobject
bintra etw-audit --providers --limit 50
bintra etw-capture --session-name Bintra_Diagnostic_Trace --pid 10324 --duration 2.0

# Device Manager, COM/LPT ports, PnP topology, network & driver store correlation
bintra hw-audit --problems-only
bintra port-audit
bintra hw-tree --format tree
bintra hw-net
bintra hw-dissect wifi
bintra net-conns --pid 10324
bintra driver-audit
bintra service-audit
bintra dev-classes --format json
bintra dev-list --class-filter Display --format json
bintra dev-search --query "Realtek" --format json
bintra dev-info --device "Intel(R) UHD Graphics 620" --format json
bintra dev-match --query "PCI" --problems-only

# Dual-view Windows Registry Editor intelligence
bintra reg-audit --domain SECURITY_POLICIES
bintra reg-read --key "SOFTWARE\Microsoft\Windows NT\CurrentVersion" --hive HKLM --format json
bintra reg-search --query "Windows 10" --hive HKLM --root-key "SOFTWARE\Microsoft\Windows NT" --format json
bintra reg-export --key "SOFTWARE\Microsoft\Windows NT\CurrentVersion" --output .\workspace\version.reg
bintra reg-import .\workspace\version.reg --diff --format json
```

### Weight-Space & Safetensors Neural Commands
```powershell
# Audit embedded Safetensors neural model (Effective Rank, Induction Heads, Amenability, Dual-Axis Backdoors)
bintra wsp-audit --model model.safetensors

# Surgical low-rank column direction subtraction on embedded linear layers
bintra patch-weights `
  --source model.safetensors `
  --output workspace/patched.safetensors `
  --tensor mlp.down_proj `
  --operation column_direction_subtract `
  --num-columns 64

# Subspace extraction, pseudocode decompilation, weight diffing & equilibrium verification
bintra subspace --model model.safetensors --tensor mlp.down_proj --mode svd_modes
bintra decompile --model model.safetensors --tensor mlp.down_proj --circuit-type mlp_projection
bintra diff-weights --baseline model.safetensors --patched workspace/patched.safetensors --tensor mlp.down_proj
bintra probe-trace --model model.safetensors --prompt "status check"
bintra verify-behavior --baseline model.safetensors --patched workspace/patched.safetensors
# (Archived experimental command decoupled per SCOPE.md: bintra synthesize-weights --archived-lineage ...)
```

### Self-Update & Continuous Deployment
```powershell
# Check whether an upstream update is available from GitHub (returns exit code 2 if behind)
bintra update --check

# Pull verified commits with explicit confirmation (--yes), sync dependencies, or pin --ref <tag-or-sha>
bintra update --yes
```

### Running the Test Suite
```powershell
# Run the complete test suite (466 tests across 36 suites, sustaining 440+ unit, sensory, runtime telemetry & security tests)
python -m unittest discover -s tests -p "test_*.py"
```

---

## Windows Troubleshooting & FAQ

### 1. Error: `'bintra' is not recognized as an internal or external command`
**Cause:** The Python `Scripts` directory is not in your user environment `PATH`.  
**Solution:**
1. Run `install.ps1`, which automatically detects your Python `Scripts` directory and appends it to your User `PATH`.
2. Or manually add `%LOCALAPPDATA%\Programs\Python\Python3xx\Scripts` (or `%APPDATA%\Python\Python3xx\Scripts`) to your User Environment Variables, then restart your terminal.
3. Alternatively, invoke Bintra directly via Python from any location:
   ```powershell
   python -m cli --help
   python -m mcp_server
   ```

### 2. Error: `WRITE_OUTSIDE_WORKSPACE` or `TARGET_DIRECTORY_WRITE_FORBIDDEN`
**Cause:** The `ExecutionGuard` reference monitor enforces **Target Immutability**. Modifying the target binary in-place or writing output patches inside the target's original directory is strictly blocked to protect host software from corruption.  
**Solution:** Direct `--output` to an isolated workspace folder (e.g. `--output ./workspace/target_patched.exe`).

---

## Community & Contributing

We warmly welcome contributions from the binary analysis, systems research, and reverse engineering communities!
- **Contributing Guide:** Review [CONTRIBUTING.md](CONTRIBUTING.md) for local environment setup, architecture standards, and PR requirements.
- **Code of Conduct:** Please adhere to our [Code of Conduct](CODE_OF_CONDUCT.md) in all project spaces.
- **Security & Responsible Disclosure:** Review our [Security Policy](SECURITY.md) and fail-closed safety kernel invariants.
- **Visual Identity:** Check out our official brand marks, palettes, and vector assets in [assets/README.md](assets/README.md).
- **Roadmap:** Track ongoing priorities (ETW live telemetry, Event Log native API, NTAPI phnt) in [docs/ROADMAP.md](docs/ROADMAP.md).

## Citation, References & Verification
- **Academic Research Reference:** Inspired by *"Sparks of Weight-Space Programming: LLMs can natively read & write neural network weights"*, by Rikiya Takehi, Jayden Teoh, Alex Zhang, and Omar Khattab (MIT CSAIL, November 2026).
  - [alphaXiv Preprint Discussion](https://www.alphaxiv.org/abs/2611.weight-space-programming)
  - [Official MIT CSAIL Replication Logs & Prompts Repository](https://github.com/RikiyaT/lm_understand-logs)
  - [Weights Editing Replications (Jasper Zhao)](https://github.com/jasperzhao05/weights_editing)
- **Scope & Methodological Verification:** While WSP research explores direct LLM reasoning over neural network parameters in small models, `Bintra` extends this conceptual foundation into continuous state-transition analysis, deterministic deobfuscation, and surgical PE patching for compiled native software.
- Maintained by [bio-colab](https://github.com/bio-colab).

---

## Real-World Validation Matrix

`benchmarks/real_world_windows/` contains a host-driven campaign (8 levels: static PE anatomy, host intelligence, real crash dumps, live processes, mutation & safety, MCP end-to-end, malformed-PE fuzzing, System32-scale triage) that runs against genuine artifacts on a Windows workstation and reports to `workspace/real_world/SUMMARY.md`:

```powershell
python benchmarks\real_world_windows\run_matrix.py
```

See [`TEST_PLAN.md`](benchmarks/real_world_windows/TEST_PLAN.md) for pass criteria and [`RESULTS.md`](benchmarks/real_world_windows/RESULTS.md) for the latest campaign and the defects it uncovered.

## Known Limitations & Heuristic Boundaries

`Bintra` maintains a strict, transparent distinction between deterministic mathematical verification and heuristic statistical pattern matching:

1. **Standalone 16-D Behavioral Vectors vs. Deep Learned Neural Embeddings:**
   - The standalone `vectorize_function` in `binary_neural_engine.py` is an engineered 16-dimensional behavioral histogram and state transition profile (frequency of instruction classes, branch topology, memory operations, and stack frame deltas), **not** a deep learned neural network embedding (such as jTrans or PalmTree). The term "continuous semantic vector" refers to continuous state-transition modeling rather than a trained deep representation.
   - Routines with fewer than 5 instructions or trivial linear sequences (e.g. leaf stubs) share similar instruction class distributions and can produce high cosine similarity despite differing semantics. The engine incorporates branch topology and stack delta guards to mitigate false positives, but comparisons on small snippets remain heuristic.
   - For rigorous, compiler-invariant cross-architecture matching, the Ghidra High P-Code IR vectorizer (`ghidra_pcode_vectorizer.py`) should be used.

2. **Deobfuscator Detection & Capstone Instruction Boundaries:**
   - **Opaque Predicates:** Evaluated via Capstone linear sweep disassembly following valid x86/x64 instruction boundaries. Immediate operand constants containing zeroing bit patterns (e.g. `mov eax, 0x0574C031`) are strictly parsed as operands and never falsely flagged as opaque predicates.
   - **Control Flow Flattening (CFF):** Requires dispatcher comparison and assignment operations to cluster on the *same* state variable storage location ($\ge 3$ comparisons and $\ge 2$ assignments on the identical frame offset or register). Furthermore, regions with Shannon entropy $\ge 7.4$ (such as compressed payloads or cryptographic keys) are rejected to eliminate false positives.

3. **Complete Mediation & Target Immutability:**
   - Target executables and neural weight files are treated as immutable reference artifacts.
   - In-place modification is strictly blocked at both the CLI layer and the low-level library layer (`SurgicalBinaryPatcher.patch_file` and `SafetensorsHandler.write_patched_safetensors`) via `PathIdentity.is_same_file()`. Any attempt to patch a target into itself unconditionally raises `TargetMutationError(TARGET_WRITE_FORBIDDEN)`.
   - All surgical patches and weight interventions must specify an explicit, distinct destination path.

4. **Cross-Platform Host Degradation:**
   - Windows Intelligence subsystems (`WindowsRegistryAnalyzer`, `CommandExecutor`, `WindowsOSProfiler`) fail-closed gracefully on non-Windows host environments (such as Linux CI or sandboxes), returning structured `status: "not_applicable"` diagnostics rather than failing with platform attribute errors.

5. **Runtime Telemetry, Memory Integrity & Audit Persistence Contracts:**
   - **Strict Read-Only Process Introspection:** Live memory scanning (`bintra_memory_scan`, `bintra_pointer_scan`, `bintra_struct_dissect`) uses `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` only and requires an explicit workspace-scoped `--session-file` / `session_id` without altering target process memory.
   - **Hybrid Native ETW + Non-Elevated Fallbacks:** `EtwCaptureEngine` attempts real-time native `OpenTraceW` / `ProcessTrace` trace consumption (requiring Administrator or Performance Log Users privileges) and falls back cleanly on standard non-elevated Windows sessions to Toolhelp32 module snapshots (`CreateToolhelp32Snapshot`) and `WEVTAPI` Windows Event Log channels, explicitly reporting `event_sources` and `has_native_etw_events`.
   - **Audit Persistence & Fail-Closed CLI:** Mutating CLI actions (`patch`, `patch-binary`, `patch-weights`, and `update --yes`/`--confirm`) require strict fail-closed `AuditLogger` initialization (`AUDIT_INIT_FAILED`), while read-only CLI inspections signal degraded logging transparently via `"audit_degraded": true` and `"audit_degraded_reason"`.

### Read-Only Reverse Engineering & Hardware Intelligence Capabilities
- **Extended PE/COFF Inspection (`inspect` / `bintra_inspect_binary`):** Pure-Python parsing of **Rich Header** build entries, **TLS Callbacks**, **Load Config** (GuardCF, SafeSEH, Security Cookie), **Authenticode (`WIN_CERTIFICATE`)**, **CLR/.NET** headers, and vectorized PE checksums.
- **Offline MiniDump & Crash RCA (`dmp-inspect` / `crash-rca`):** Parses `MemoryListStream` (5), `Memory64ListStream` (9), `MemoryInfoListStream` (16), `VS_FIXEDFILEINFO`, and `CvRecord` (CodeView RSDS/NB10 PDB GUIDs) with $O(\log N)$ `read_memory_from_dump()` lookup.
- **Hardware & Device Intelligence (`hw-audit` / `dev-match` / `bintra_device_driver_intelligence`):** `CM_PROB_*` problem code descriptions, `PCI`/`USB`/`HDAUDIO`/`HID`/`ACPI`/`BLUETOOTH`/`STORAGE` bus decoding, `hw-audit --problems-only --class-filter`, and cross-platform offline `.inf` Driver Rank matching (`DriverPackageInventory.parse_offline_inf`, `DriverMatcher.match_offline_device_to_infs`).
- **Additional Read-Only CLI Tools:** `evidence-graph` (JSON/Mermaid causality dossier), `registry-read` (safe hive/key inspection), and `process-mitigations` (DEP/ASLR/CFG inspection).

## Frozen Python & Hybrid Binary Reverse Engineering (`.pyd`, PyInstaller, Nuitka, Cython)

Bintra provides dedicated read-only forensic capabilities for **compiled and frozen Python executables** on Windows:
- **`.pyd` C-Extensions & Cython / Nuitka Binaries**: Inspects PE32/PE32+ headers, `PyInit_*` / `__pyx_*` / `__nuitka_*` exports, `.pdata` functions, and MSVC RTTI alongside `python3*.dll` dependencies.
- **PyInstaller Executables**: Detects `MEI` CArchive cookies and `PYZ` bytecode archives via `scan-hybrid`.
- **CPython Bytecode & Live Memory Forensics**: Disassembles `.py`/`.pyc` bytecode into Basic Blocks for `WeisfeilerLehmanCfgHasher` (`py-bytecode`) and inspects live `PyObject` / `PyDictObject` heap structures (`py-mem-inspect`).

## High-Performance SQLite & JSONL Export Storage for Ghidra

To handle multi-megabyte Ghidra exports (10MB–50MB+ on large binaries like game engines and OBS Studio) without memory exhaustion:
- **Zero-Dependency SQLite Store (`src/ghidra_export_store.py`)**: Built-in `sqlite3` + `JSON1` engine providing $O(\log N)$ indexed B-Tree function retrieval and SQL-accelerated call-graph queries (72x faster, 99.9% RAM reduction).
- **Transparent Ingestion Cache**: JSON exports exceeding 2MB are automatically indexed to `.bintra_cache.db` on first read.
- **JSON Lines (`.jsonl`) Streaming**: Full line-by-line streaming from Ghidra without loading the entire program AST into memory.
- **CLI Compilation**: Pre-compile any export via `bintra ghidra-analyze --input <export.json> --to-sqlite <export.db>`.
