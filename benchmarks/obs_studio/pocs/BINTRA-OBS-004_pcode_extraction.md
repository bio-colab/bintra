# PoC `BINTRA-OBS-004`: High P-Code Extraction & Symbol-Free vs PDB Function Comparison

- **Axis:** A2 — Ghidra Integration
- **Verdict:** `FAIL` (Python/PyGhidra P-code workflow `bintra_extract_pcode.py` fails under `analyzeHeadless.bat`, and Java bridge P-code JSON export could not reach `ghidra-analyze` / `PcodeFunctionMatcher` due to `%TEMP%` self-block & temp cleanup)
- **Primary Classification:** `Integration Issue` (`analyzeHeadless` vs PyGhidra mismatch + `BintraGhidraBridge.java` `%TEMP%` `TargetMutationError` blocking automated downstream `ghidra-analyze`)
- **Raw Evidence:** [`obs_004.json`](../evidence/obs_004.json)

## 1. Reproducible Command
```powershell
python benchmarks/obs_studio/scripts/run_ghidra_pocs.py
```

## 2. Empirical Extraction & Blind vs PDB Comparison

### A. Python Extraction Script (`bintra_extract_pcode.py`)
- Executed via standard Ghidra `12.1.4` `support\analyzeHeadless.bat` on `obs-frontend-api.dll`:
- **Failed with:**
  `ERROR REPORT SCRIPT ERROR: bintra_extract_pcode.py : Ghidra was not started with PyGhidra. Python is not available` (`PyGhidraScriptProvider.getScriptInstance`).
- Bintra's `ghidra-headless` CLI invokes `analyzeHeadless.bat` (JVM/Java/Jython) rather than PyGhidra.

### B. Java Extraction Bridge (`BintraGhidraBridge.java`) — Level 1 Blind vs Level 2 `.pdb`
Observed directly from Ghidra `HeadlessAnalyzer` logs during isolated runs:

| Binary | Size | Blind Mode Functions Extracted (Level 1, No PDB) | PDB Mode Functions Extracted (Level 2, With PDB) | Downstream `ghidra-analyze` Verdict |
| --- | ---: | ---: | ---: | --- |
| `obs-frontend-api.dll` | 40 KB | **`182 / 182`** (vs 96 PE exports) | **`188 / 188`** (+6 PDB functions, +RTTI/internal names) | **Blocked (`TargetMutationError`, exit 1)** |
| `libobs-d3d11.dll` | 196 KB | **`636 / 636`** (vs 171 PE exports) | **`812 / 812`** (+176 functions recovered with PDB!) | **Blocked (`TargetMutationError`, exit 1)** |

## 3. Honest Assessment
- Ghidra headless analyzer + `BintraGhidraBridge.java` **successfully** closes the static function discovery gap on Windows C/C++ DLLs (recovering `636` blind functions in `libobs-d3d11.dll` vs only `171` exports in `obs_001.json`, and `812` with `.pdb`!).
- However, the end-to-end automated pipeline inside Bintra **fails** both via `bintra_extract_pcode.py` (requires PyGhidra launch) and `BintraGhidraBridge.java` (`--output` written in `%TEMP%` alongside `--input` violates Bintra's own `ExecutionGuard` directory rule, causing `ghidra-analyze` to abort with `TargetMutationError` before any `PcodeVectorizer` / `GhidraAnnotationPlanner` mutations can run).
