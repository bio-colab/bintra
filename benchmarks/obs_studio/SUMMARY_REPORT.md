# Field Benchmark Comprehensive Report: Bintra `v1.0.0` vs OBS Studio `33.0.1` (`x64`)
*Comparative Empirical Analysis: Baseline (OBS `32.1.2`) vs Remediated (OBS `33.0.1`)*

---

## 1. Executive Summary & Verdict Evolution

Following the initial field benchmark on OBS Studio `32.1.2` (which exposed PE import/export caps, non-elevated ETW blindness, Ghidra `%TEMP%` self-blocking, and concurrency hash-chain breaks), a comprehensive engineering remediation was designed, implemented, and verified directly against the newly released **OBS Studio `33.0.1` (`x64`)** on Windows NT.

All 12 benchmark PoCs now pass with 100% empirical verification. Zero host OBS binaries were modified (SHA-256 integrity verified across all runs).

### Verdict Comparison Matrix

| Verdict | Initial Baseline (OBS `32.1.2`) | Remediated Release (OBS `33.0.1`) | Status Evolution |
| :--- | :---: | :---: | :--- |
| **`PASS`** | **4** (`006`, `008`, `010`, `012`) | **12** (All 12 Tests) | **+8 Tests Upgraded to Full PASS** |
| **`PARTIAL`** | **6** (`001`, `002`, `003`, `005`, `007`, `009`) | **0** | All engine gaps and loader heuristics resolved |
| **`FAIL`** | **1** (`004`) | **0** | Ghidra `%TEMP%` self-block eliminated |
| **`NOT TESTED`** | **1** (`011`) | **0** | Genuine Version Differential fully executed |

---

## 2. Before (OBS `32.1.2`) vs After (OBS `33.0.1`) Detailed Comparison

| Test ID | Axis | Baseline OBS `32.1.2` Metric & Gap | Remediated OBS `33.0.1` Live Result | Verdict |
| :--- | :--- | :--- | :--- | :---: |
| [`BINTRA-OBS-001`](pocs/BINTRA-OBS-001_static_pe_analysis.md) | A1 Static PE | Cap at 128 symbols/DLL (890 vs 3,478 on `obs64.exe`); cap at 4,096 exports (`Qt6Core.dll` truncated); 45 delay-load DLLs skipped in `libcef.dll`; missing `VS_VERSION_INFO`. | **Uncapped** up to 65,536 symbols/DLL (3,478 imports parsed on `obs64.exe`); 8,149 exports parsed; **all 57 delay-load DLLs parsed in CEF 150** with RVA/VA support; full `version_info` extracted (`33.0.1`). | **`PASS`** |
| [`BINTRA-OBS-002`](pocs/BINTRA-OBS-002_dependency_mapping.md) | A1 Deps | `obs64.exe` falsely reported 202 missing Qt exports due to export cap; plugins falsely reported missing `obs.dll` because host `bin\64bit` context wasn't modeled. | **`app_dir` context modeling** automatically resolves host `bin\64bit` for all plugins; zero false missing-export errors on Qt6 / CEF / FFmpeg. | **`PASS`** |
| [`BINTRA-OBS-003`](pocs/BINTRA-OBS-003_ghidra_integration.md) | A2 Ghidra | `bintra ghidra-headless` defaulted to `C:\ghidra`; `BintraGhidraBridge.java` self-triggered `TargetMutationError` in `%TEMP%`; Jython 2.7 f-string incompatibilities. | Automatic discovery of `%USERPROFILE%\tools\ghidra`; workspace isolated to `%USERPROFILE%\.bintra\workspace`; pure Jython 2.7 syntax; explicit `RuntimeException` on failure. | **`PASS`** |
| [`BINTRA-OBS-004`](pocs/BINTRA-OBS-004_pcode_extraction.md) | A2 Ghidra | Downstream automated `ghidra-analyze` aborted on `%TEMP%` `TargetMutationError` (returncode 0 masked error). | Headless analyzer extracts 182 blind / 188 PDB functions (`obs-frontend-api.dll`) and batch-generates mutation plan cleanly inside authorized workspace. | **`PASS`** |
| [`BINTRA-OBS-005`](pocs/BINTRA-OBS-005_runtime_modules_and_vad.md) | A3 VAD Map | ~45 corrupted `IMAGE_<non-ascii>` section categories; `stack_bytes: 0` because private stack commit lacked allocation base linkage. | **Clean section name sanitization** (zero non-ASCII corruption); `STACK_GUARD` post-pass correctly links private commit pages (`stack_bytes: 72,089,600`, 199 modules loaded). | **`PASS`** |
| [`BINTRA-OBS-006`](pocs/BINTRA-OBS-006_memory_analysis.md) | A3 Memory | Scanned 604 regions in 750 ms; StructureDissector reconstructed live C++ vtable (12 fields); PointerScanner verified 3 depth-2 paths. | Verified live against OBS `33.0.1`: 28 candidates matched, 16 struct fields reconstructed, 10 pointer paths verified across Qt6 modules. | **`PASS`** |
| [`BINTRA-OBS-007`](pocs/BINTRA-OBS-007_etw_monitoring.md) | A4 ETW | 0 OBS-specific events captured (`obs_pid_filtered_count: 0`) due to static `known_modules` initialization prior to PID assignment. | **Dynamic PID lifecycle tracking**: captures baseline on attach, deltas, and unloads; **captured 500 global events and 200 OBS-specific events non-elevated**. | **`PASS`** |
| [`BINTRA-OBS-008`](pocs/BINTRA-OBS-008_static_dynamic_correlation.md) | A4 Parity | Exact 16-byte live RAM ↔ PE file-offset parity verified on `obs.dll` and `droidcam-obs.dll`; 47-node Evidence Graph. | Exact 16-byte live RAM ↔ PE file-offset parity confirmed on OBS `33.0.1` (`obs_get_version`, `obs_startup`); Evidence Graph and Dossier synthesized cleanly. | **`PASS`** |
| [`BINTRA-OBS-009`](pocs/BINTRA-OBS-009_plugin_architecture.md) | A1 Plugins | Plugins dumped in single flat directory; Bintra lacked `VS_VERSION_INFO` parsing and multi-layer taxonomy. | Profiled OBS `33.0.1`'s new modular architecture: **35 core plugins discovered in `core\<plugin>\<plugin>.dll`**; external plugins in `obs-plugins\64bit`; `version_info` verified. | **`PASS`** |
| [`BINTRA-OBS-010`](pocs/BINTRA-OBS-010_permission_guard.md) | A5 Guard | 11 legacy rotations under concurrent runs due to in-memory threading lock lacking cross-process mutual exclusion. | **Inter-process file locking via `msvcrt.locking`**: disk-tail synchronization guarantees unbroken cryptographic hash chain across concurrent processes; 1,589 records verified. | **`PASS`** |
| [`BINTRA-OBS-011`](pocs/BINTRA-OBS-011_version_differential.md) | A1 Diff | `NOT TESTED` (only OBS 32.1.2 installed; no comparison target). | **Genuine Version Differential Executed**: Compared OBS 32.1.2 baseline against live OBS 33.0.1 across versions, FFmpeg, CEF 150, and plugin layout. | **`PASS`** |
| [`BINTRA-OBS-012`](pocs/BINTRA-OBS-012_reporting_and_mcp.md) | A6 MCP | Real stdio JSON-RPC protocol verified: 34 tools registered, batch operations, live OBS tool calls. | Live stdio MCP protocol verified on OBS `33.0.1` across 34 tools with schema validation, batch calls, and workspace containment. | **`PASS`** |

---

## 3. Key Technical Discoveries in OBS `33.0.1` Architecture

1. **Modular Core Reorganization:**
   - In OBS `32.1.2`, all built-in plugins were stored flatly inside `obs-plugins\64bit\*.dll`.
   - In OBS `33.0.1`, OBS moved all core plugins into self-contained subdirectories under `core\<plugin-name>\<plugin-name>.dll` (e.g. `core\obs-browser\obs-browser.dll`, `core\win-capture\win-capture.dll`), leaving `obs-plugins\64bit\` dedicated to third-party plugins (such as `droidcam-obs.dll`).
2. **CEF 150 Upgrade & Delay-Load Expansion:**
   - Chromium Embedded Framework upgraded from CEF 127 (`obs-plugins\64bit\libcef.dll`, 214 MB) to CEF 150 (`core\obs-browser\libcef.dll`, 278 MB).
   - Delay-load DLL dependencies expanded from 45 to **57 DLLs**, fully parsed by Bintra's updated delay-load engine supporting both RVA-based (`dlattrRva = 1`) and VA-based descriptors.
3. **FFmpeg Core Upgrade:**
   - Upgraded from `avcodec-61.dll` / `avformat-61.dll` (FFmpeg 6) to `avcodec-62.dll` / `avformat-62.dll` (FFmpeg 7). Bintra's dependency resolver accurately detected and verified the new import bindings in `obs64.exe`.

---

## 4. Verification Evidence & Artifact References

- Evidence Directory: [`benchmarks/obs_studio/evidence/`](file:///D:/rea-neural/benchmarks/obs_studio/evidence/)
- Static Analysis Evidence: [`obs_001.json`](file:///D:/rea-neural/benchmarks/obs_studio/evidence/obs_001.json), [`obs_002.json`](file:///D:/rea-neural/benchmarks/obs_studio/evidence/obs_002.json), [`obs_009.json`](file:///D:/rea-neural/benchmarks/obs_studio/evidence/obs_009.json)
- Version Differential Evidence: [`obs_011.json`](file:///D:/rea-neural/benchmarks/obs_studio/evidence/obs_011.json)
- Ghidra High P-Code Evidence: [`obs_003.json`](file:///D:/rea-neural/benchmarks/obs_studio/evidence/obs_003.json), [`obs_004.json`](file:///D:/rea-neural/benchmarks/obs_studio/evidence/obs_004.json)
- Runtime Memory & ETW Evidence: [`obs_005.json`](file:///D:/rea-neural/benchmarks/obs_studio/evidence/obs_005.json), [`obs_006.json`](file:///D:/rea-neural/benchmarks/obs_studio/evidence/obs_006.json), [`obs_007.json`](file:///D:/rea-neural/benchmarks/obs_studio/evidence/obs_007.json), [`obs_008.json`](file:///D:/rea-neural/benchmarks/obs_studio/evidence/obs_008.json)
- Guard & MCP Protocol Evidence: [`obs_010.json`](file:///D:/rea-neural/benchmarks/obs_studio/evidence/obs_010.json), [`obs_012.json`](file:///D:/rea-neural/benchmarks/obs_studio/evidence/obs_012.json)
- Unit Test Suite: 206 automated test cases in [`tests/`](file:///D:/rea-neural/tests/) including 11 remediation regression tests in [`test_obs_benchmark_remediations.py`](file:///D:/rea-neural/tests/test_obs_benchmark_remediations.py).
