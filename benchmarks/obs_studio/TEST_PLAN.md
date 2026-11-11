# Bintra OBS Studio 32.1.2 Field Benchmark — Test Plan

**Bintra Version:** 1.0.0  
**Target:** OBS Studio 32.1.2 (x64), `%ProgramFiles%\obs-studio`  
**OS:** Windows (medium integrity, standard user)  
**Authors:** static-auditor, ghidra-auditor, runtime-auditor, guard-and-mcp-auditor  
**Verifier:** verifier (independent)

---

## 1. Test Axes (6)

| # | Axis | Description |
|---|------|-------------|
| A1 | **Static PE Analysis** | Headers, imports/exports, sections, mitigations, embedded library detection |
| A2 | **Ghidra Integration** | Headless analysis, P-code extraction, Live Bridge RPC, deobfuscation |
| A3 | **Runtime / Live Telemetry** | VAD module discovery, memory scanning, pointer paths, struct dissection |
| A4 | **ETW & Event Tracing** | Hybrid ETW / Event Log / Toolhelp32 timelines during OBS lifecycle |
| A5 | **Permission Guard & Audit** | ExecutionGuard / PolicyEngine access control, audit hash chain, boundary probes |
| A6 | **MCP Server & Reporting** | JSON-RPC 2.0 stdio MCP, tool enumeration, schema validation, live calls |

---

## 2. Evaluation Levels (3)

### Level 1 — Blind Analysis
Bintra operates on a **clean PDB-free copy** of OBS PE files. No debug symbols, no source knowledge.  
Measures: PE headers, mitigations, sections, imports/exports, strings/xrefs (if supported), function extraction/CFG, embedded library version detection (Qt6, CEF, FFmpeg, x264), architecture metadata, third-party plugin (`droidcam-obs.dll`) vs core OBS plugins.

### Level 2 — Symbol-Assisted
Shipped `.pdb` files (`obs.pdb`, `libobs-d3d11.pdb`, `droidcam-obs.pdb`, etc.) are loaded via `dbghelp.dll` (`SymInitialize` / `SymLoadModuleEx` / `SymEnumSymbols`).  
Measures: Exact delta of functions/symbols Bintra's Level 1 missed or caught. Quantifies blind analysis coverage gaps.

### Level 3 — Source / Spec Validation + Version Differential
Findings from Levels 1 & 2 compared against:
- OBS Studio 32.1.2 `libobs` plugin architecture (`obs_module_load`, `obs_module_description`, delay-load vs static imports, `libcef.dll` version vs `obs-browser.dll`)
- Core vs third-party plugin boundaries (`droidcam-obs.dll`)
- Version differential between two OBS builds (or auxiliary PE cross-matching if only 32.1.2 is available)

---

## 3. The 12 Proof-of-Concept Tests (OBS-001 … OBS-012)

| PoC ID | Title | Axis | Level(s) | Author |
|--------|-------|------|----------|--------|
| **BINTRA-OBS-001** | PE Analysis & Mitigation Fingerprint | A1 | L1, L2, L3 | static-auditor |
| **BINTRA-OBS-002** | Dependency Mapping & DLL Search Order | A1 | L1, L2, L3 | static-auditor |
| **BINTRA-OBS-003** | Ghidra Integration — Headless & Live Bridge | A2 | L1, L2 | ghidra-auditor |
| **BINTRA-OBS-004** | P-code Extraction & Semantic Deobfuscation | A2 | L1, L2 | ghidra-auditor |
| **BINTRA-OBS-005** | Runtime Module Discovery (VAD) | A3 | L1 | runtime-auditor |
| **BINTRA-OBS-006** | Memory Analysis — Scan, Pointer, Struct | A3 | L1 | runtime-auditor |
| **BINTRA-OBS-007** | ETW / Event Log Monitoring | A4 | L1 | runtime-auditor |
| **BINTRA-OBS-008** | Static-Dynamic Correlation (RVA alignment) | A3 | L1, L2 | runtime-auditor |
| **BINTRA-OBS-009** | Plugin Architecture Enumeration | A1 | L1, L2, L3 | static-auditor |
| **BINTRA-OBS-010** | Permission Guard & Audit Trail | A5 | L1 | guard-and-mcp-auditor |
| **BINTRA-OBS-011** | Version Differential Analysis | A1 | L3 | static-auditor |
| **BINTRA-OBS-012** | MCP Server: Reporting & Tool Schema | A6 | L1 | guard-and-mcp-auditor |

---

## 4. Verdict Schema

Each PoC declares one of:

| Verdict | Meaning |
|---------|---------|
| **PASS** | Feature works as designed; output matches expected schema and contains correct data |
| **PARTIAL** | Feature partially works; some sub-checks pass, some fail or produce degraded data |
| **FAIL** | Feature does not work; output is absent, corrupt, or incorrect |
| **NOT TESTED** | Test could not run due to missing prerequisite (hardware, second OBS version, etc.) |

Failures are classified as:
- **Engine Gap** — Bintra's core logic does not implement the feature
- **Test Limitation** — External constraint (non-admin, missing hardware, single OBS install) prevents verification
- **Integration Issue** — Feature exists but wiring, CLI flags, or environment causes the failure

---

## 5. Critical Constraints

1. **Source Immutability:** NEVER edit `src/`, `ghidra_scripts/`, `tests/`. Record engine gaps honestly.
2. **No Hardcoded Developer Paths:** All scripts/documents use env vars (`%ProgramFiles%`, `Path(__file__)`, etc.). Zero hardcoded user profile or repository paths in saved files.
3. **Target Immutability:** `%ProgramFiles%\obs-studio\bin\64bit\obs.dll` is the **strictly immutable reference**. All tests use temporary copies placed in isolated workspace directories.
4. **Privacy:** Never read, store, or log OBS stream keys, OAuth tokens, or raw config files (`service.json`, `global.ini`).
5. **Workspace Isolation:** All Bintra output goes to `./workspace/` or OS temp; never adjacent to OBS system files.

---

## 6. File Ownership Map

| File | Owner |
|------|-------|
| `benchmarks/obs_studio/TEST_PLAN.md` | guard-and-mcp-auditor |
| `benchmarks/obs_studio/scripts/run_static_pocs.py` | static-auditor |
| `benchmarks/obs_studio/scripts/run_ghidra_pocs.py` | ghidra-auditor |
| `benchmarks/obs_studio/scripts/run_runtime_pocs.py` | runtime-auditor |
| `benchmarks/obs_studio/scripts/run_guard_and_mcp_pocs.py` | guard-and-mcp-auditor |
| `benchmarks/obs_studio/evidence/obs_001.json` … `obs_004.json` | static-auditor / ghidra-auditor |
| `benchmarks/obs_studio/evidence/obs_005.json` … `obs_008.json` | runtime-auditor |
| `benchmarks/obs_studio/evidence/obs_009.json`, `obs_011.json` | static-auditor |
| `benchmarks/obs_studio/evidence/obs_010.json`, `obs_012.json` | guard-and-mcp-auditor |
| `benchmarks/obs_studio/pocs/BINTRA-OBS-*.md` | as per author column above |
| `benchmarks/obs_studio/README.md` | guard-and-mcp-auditor (after verifier sign-off) |
| `benchmarks/obs_studio/SUMMARY_REPORT.md` | guard-and-mcp-auditor (after verifier sign-off) |
